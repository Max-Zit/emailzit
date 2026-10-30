package web

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/store"
)

// Day-to-day operation: the delivery log for staff and customers, the
// mail queue for staff, the certificate of the mail services and the
// blacklist check of the server's addresses.

// ---- delivery log

type deliveriesData struct {
	List   []store.LogEntry
	Q      string
	Status string
}

func (s *Server) handleDeliveries(w http.ResponseWriter, r *http.Request) {
	d := &deliveriesData{Q: strings.TrimSpace(r.FormValue("q")), Status: r.FormValue("status")}
	var err error
	d.List, err = s.store.DeliveryLog(r.Context(), scopeOf(r), store.LogFilter{Query: d.Q, Status: d.Status, Limit: 300})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "deliveries", &Page{Title: "Delivery log", Nav: "deliveries", Data: d})
}

// ---- mail queue (staff)

type queueData struct {
	List  []mailhelper.QueueItem
	Error bool
}

func (s *Server) helperClient() *mailhelper.Client {
	return &mailhelper.Client{Socket: mailhelper.Socket}
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	d := &queueData{}
	if s.Mail == nil {
		d.Error = true
	} else if err := s.helperClient().CallData(r.Context(), mailhelper.Request{Action: mailhelper.ActionQueue, Op: "list"}, &d.List); err != nil {
		s.log.Error("mail queue", "err", err)
		d.Error = true
	}
	sort.Slice(d.List, func(i, j int) bool { return d.List[i].Arrival > d.List[j].Arrival })
	s.render(w, r, http.StatusOK, "queue", &Page{Title: "Mail queue", Nav: "queue", Data: d})
}

func (s *Server) handleQueueAction(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	op := r.FormValue("op")
	req := mailhelper.Request{Action: mailhelper.ActionQueue, Op: op, IDs: r.Form["id"], By: userFrom(r).Username}
	if s.Mail == nil {
		s.redirectErr(w, r, "/queue", "This installation has no mail helper.")
		return
	}
	if err := s.helperClient().CallData(r.Context(), req, nil); err != nil {
		s.log.Error("mail queue action", "op", op, "err", err)
		s.redirectErr(w, r, "/queue", "The action could not be done.")
		return
	}
	s.audit(r, "queue."+op, "queue", "%d message(s): %s", len(req.IDs), strings.Join(req.IDs, " "))
	s.redirect(w, r, "/queue", "Done.")
}

// ---- certificate of the mail services

type certData struct {
	Subject  string
	Names    []string
	Issuer   string
	NotAfter time.Time
	Days     int
	SelfSign bool
	Missing  bool
}

func readMailCert() certData {
	var d certData
	b, err := os.ReadFile("/etc/emailzit/tls/mail.crt")
	if err != nil {
		d.Missing = true
		return d
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		d.Missing = true
		return d
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		d.Missing = true
		return d
	}
	d.Subject, d.Names, d.Issuer, d.NotAfter = c.Subject.CommonName, c.DNSNames, c.Issuer.CommonName, c.NotAfter
	d.Days = int(time.Until(c.NotAfter).Hours() / 24)
	d.SelfSign = c.Issuer.String() == c.Subject.String()
	return d
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "certificate", &Page{Title: "Certificate", Nav: "settings", Data: readMailCert()})
}

func (s *Server) handleCertificateSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	req := mailhelper.Request{Action: mailhelper.ActionCert, Chain: strings.TrimSpace(r.FormValue("chain")) + "\n", Key: strings.TrimSpace(r.FormValue("key")) + "\n", By: userFrom(r).Username}
	if err := req.Validate(); err != nil {
		p := &Page{Title: "Certificate", Nav: "settings", Data: readMailCert()}
		p.Error = translate(s.lang(r, userFrom(r)), err.Error())
		s.render(w, r, http.StatusBadRequest, "certificate", p)
		return
	}
	if s.Mail == nil {
		s.redirectErr(w, r, "/settings/certificate", "This installation has no mail helper.")
		return
	}
	if err := s.helperClient().CallData(r.Context(), req, nil); err != nil {
		s.log.Error("certificate", "err", err)
		s.redirectErr(w, r, "/settings/certificate", "The certificate could not be installed; the old one stays in use.")
		return
	}
	s.audit(r, "settings.certificate", "settings", "certificate of the mail services replaced")
	s.redirect(w, r, "/settings/certificate", "The certificate is installed; Postfix and Dovecot use it now.")
}

// ---- blacklist check

// Blacklists checked for the server's addresses.
var Blacklists = []string{"zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net", "psbl.surriel.com"}

// ListResult is the state of one address on one list.
type ListResult struct {
	IP     string
	List   string
	Listed bool
	Error  bool
}

// publicAddrs are the server's public IPv4 addresses.
func publicAddrs() []netip.Addr {
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := p.Addr()
		if ip.Is4() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			out = append(out, ip)
		}
	}
	return out
}

func checkBlacklists(ctx context.Context, ips []netip.Addr) []ListResult {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out []ListResult
	for _, ip := range ips {
		b := ip.As4()
		rev := fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
		for _, l := range Blacklists {
			res := ListResult{IP: ip.String(), List: l}
			addrs, err := net.DefaultResolver.LookupHost(ctx, rev+"."+l)
			switch {
			case err == nil && len(addrs) > 0:
				// 127.255.255.x: the list refuses the query (public resolver)
				res.Listed = !strings.HasPrefix(addrs[0], "127.255.255.")
				res.Error = !res.Listed
			case err != nil:
				var dnsErr *net.DNSError
				if !(asDNS(err, &dnsErr) && dnsErr.IsNotFound) {
					res.Error = true
				}
			}
			out = append(out, res)
		}
	}
	return out
}

func asDNS(err error, target **net.DNSError) bool {
	e, ok := err.(*net.DNSError)
	if ok {
		*target = e
	}
	return ok
}

type blacklistData struct {
	IPs     []string
	Results []ListResult
	Checked bool
}

func (s *Server) handleBlacklists(w http.ResponseWriter, r *http.Request) {
	d := &blacklistData{}
	ips := publicAddrs()
	for _, ip := range ips {
		d.IPs = append(d.IPs, ip.String())
	}
	if r.Method == http.MethodPost {
		d.Results, d.Checked = checkBlacklists(r.Context(), ips), true
	}
	s.render(w, r, http.StatusOK, "blacklists", &Page{Title: "Blacklists", Nav: "queue", Data: d})
}
