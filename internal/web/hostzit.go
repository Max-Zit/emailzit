package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/submit"
)

// The links to HostZit (INTEGRATION.md P3, P6, P7 and E7–E13): when both
// products run for the same customers, the DNS records of a mail domain
// are written into HostZit's DNS (only the names EmailZit owns, as one
// desired set per zone), a domain whose zone HostZit hosts for the same
// customer counts as verified, HostZit tells EmailZit the user IDs of the
// hosting accounts, and the sidebar shows a switch to HostZit.
//
// EmailZit keeps a LIST of links, one per HostZit server. Every call says
// by its token which link it belongs to, and a link serves either all
// customers or only the ones assigned to it (E13).

// links are the linked HostZit servers.
func (s *Server) links(ctx context.Context) []*store.HostZitLink {
	l, err := s.store.HostZitLinks(ctx)
	if err != nil {
		s.log.Error("the HostZit links cannot be read", "err", err)
		return nil
	}
	return l
}

// linked reports whether at least one HostZit is linked.
func (s *Server) linked(ctx context.Context) bool { return len(s.links(ctx)) > 0 }

// switchURL is the HostZit the header's product switcher points at: the
// link that serves this customer, or the first link for staff.
func (s *Server) switchURL(ctx context.Context, customerID string) string {
	for _, l := range s.links(ctx) {
		if customerID == "" || s.store.LinkServes(ctx, l, customerID) {
			return l.URL
		}
	}
	return ""
}

// errNoZone: HostZit does not host the zone (the records are set elsewhere).
var errNoZone = errors.New("the zone is not in HostZit's DNS")

// hostzitCall sends one API call to the HostZit of a link. The
// certificate must be trusted the usual way or match the pin of the
// pairing; only an administrator who says so explicitly gets a link
// without any check.
func (s *Server) hostzitCall(ctx context.Context, l *store.HostZitLink, method, path string, body any) (int, []byte, error) {
	if l == nil || l.URL == "" {
		return 0, nil, nil
	}
	tok, err := s.store.OpenSecret("hostzit.token", l.Token)
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(l.URL, "/")+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: linkTLS(l)}}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	s.store.TouchHostZitLink(ctx, l.ID)
	return resp.StatusCode, b, nil
}

// linkTLS is how EmailZit checks the certificate of a HostZit: the usual
// way, or against the public key the pairing code carried (a HostZit with
// a self-signed certificate), or — only when the administrator allows it
// — not at all.
func linkTLS(l *store.HostZitLink) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if l.Pin == "" {
		// #nosec G402 -- only when the administrator allows a self-signed HostZit without a pin
		cfg.InsecureSkipVerify = l.Insecure
		return cfg
	}
	want, err := base64.StdEncoding.DecodeString(l.Pin)
	if err != nil || len(want) != sha256.Size {
		// #nosec G402 -- a broken pin falls back to the administrator's choice
		cfg.InsecureSkipVerify = l.Insecure
		return cfg
	}
	// The pin replaces the chain check (the certificate is usually
	// self-signed), so the name is not checked either: the pin is the
	// stronger statement, and it is checked on resumed sessions too.
	cfg.InsecureSkipVerify = true // #nosec G402 -- VerifyConnection checks the pinned key below
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("HostZit sent no certificate")
		}
		sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(sum[:], want) != 1 {
			return errors.New("the certificate of HostZit does not match the key of the pairing")
		}
		return nil
	}
	return cfg
}

// hzRecord is a record in HostZit's API.
type hzRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
	Content string `json:"content"`
}

// publishDNS writes the mail records of a domain into the DNS of the
// HostZit that hosts the zone for the domain's customer (E10: every link
// is asked, and a link that does not serve the customer is skipped). With
// remove the records EmailZit owns are removed from every such link.
func (s *Server) publishDNS(ctx context.Context, domainID string, remove bool, d *store.Domain) {
	links := s.links(ctx)
	if len(links) == 0 {
		return
	}
	var err error
	if d == nil {
		if d, err = s.store.DomainByID(ctx, store.Staff, domainID); err != nil {
			return
		}
	}
	path := "/api/v1/dns/zones/" + url.PathEscape(d.Name) + "/owned/emailzit"
	if remove {
		for _, l := range links {
			if !s.store.LinkServes(ctx, l, d.CustomerID) {
				continue
			}
			if st, _, err := s.hostzitCall(ctx, l, http.MethodDelete, path, nil); err != nil || (st >= 300 && st != 404) {
				s.log.Warn("removing the mail records from HostZit", "hostzit", l.URL, "domain", d.Name, "status", st, "err", err)
			}
		}
		return
	}
	m := s.MailConfig(ctx)
	k, _ := s.store.DKIM(ctx, d.ID)
	var recs []hzRecord
	all := mailRecords(d, m, k)
	if c, err := s.store.CustomerByID(ctx, d.CustomerID); err == nil {
		all = withOutboundSPF(all, c.OutboundIP)
	}
	for _, r := range all {
		if strings.HasPrefix(r.Name, "_emailzit.") {
			continue // HostZit hosting the zone is the proof
		}
		name := strings.TrimSuffix(strings.TrimSuffix(r.Name, d.Name), ".")
		if name == "" {
			name = "@"
		}
		recs = append(recs, hzRecord{Name: name, Type: r.Type, TTL: 3600, Content: strings.TrimSuffix(r.Value, ".")})
	}
	note, managed, asked := errNoZone.Error(), false, false
	for _, l := range links {
		if l.Token == "" || !s.store.LinkServes(ctx, l, d.CustomerID) {
			continue
		}
		asked = true
		st, body, err := s.hostzitCall(ctx, l, http.MethodPut, path, map[string]any{"customer_id": d.CustomerID, "records": recs})
		switch {
		case err != nil:
			note = "HostZit is not reachable: " + err.Error()
		case st == http.StatusNotFound:
			continue // that HostZit does not host the zone: ask the next one
		case st == http.StatusConflict:
			managed, note = true, "HostZit kept some own records of the customer with the same names: "+apiMessage(body)
		case st >= 300:
			note = fmt.Sprintf("HostZit refused the records (%d): %s", st, apiMessage(body))
			continue
		default:
			managed, note = true, ""
		}
		break
	}
	if !asked {
		note = errNoZone.Error()
	}
	_ = s.store.SetDomainDNS(ctx, d.ID, managed, note)
	if managed && !d.DKIMPublished {
		// HostZit now holds the DKIM record itself, so the domain can be
		// signed without waiting for the hourly check
		if err := s.store.SetDKIMPublished(ctx, d.ID, true); err == nil {
			d.DKIMPublished = true
			s.installDKIM(ctx, d.ID)
		}
	}
	if managed && !d.Verified {
		// the zone is in HostZit for the same customer: that is the proof
		if err := s.store.SetDomainVerified(ctx, store.Staff, d.ID, true); err == nil {
			_ = s.store.Audit(ctx, "-", "local", "domain.verify", "domain:"+d.Name, "verified: the zone is in HostZit's DNS for the same customer")
		}
	}
}

func apiMessage(b []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}

// publishAllDNS writes the records of every domain (host name changed, a
// link saved).
func (s *Server) publishAllDNS(ctx context.Context) {
	if !s.linked(ctx) {
		return
	}
	doms, err := s.store.Domains(ctx, store.Staff, "")
	if err != nil {
		return
	}
	for _, d := range doms {
		s.publishDNS(ctx, d.ID, false, d)
	}
}

// linkView is one link on the HostZit page, with its relay login.
type linkView struct {
	L         *store.HostZitLink
	Customers []*store.Customer // the customers of an assigned link
	Assigned  map[string]bool   // their IDs, for the list of customers
}

type hostzitData struct {
	Links     []linkView
	All       []*store.Customer // every customer, to assign
	Code      string            // a fresh pairing code, shown once
	RelayHost string
	RelayPort int
}

// hostzitPage is what the HostZit page shows (the pairing code is added
// by the handler that made it).
func (s *Server) hostzitPage(ctx context.Context) *hostzitData {
	d := &hostzitData{RelayPort: submit.RelayPort, RelayHost: s.MailConfig(ctx).Hostname}
	for _, l := range s.links(ctx) {
		v := linkView{L: l, Assigned: map[string]bool{}}
		if ids, err := s.store.LinkCustomerIDs(ctx, l.ID); err == nil {
			for _, id := range ids {
				v.Assigned[id] = true
				if c, err := s.store.CustomerByID(ctx, id); err == nil {
					v.Customers = append(v.Customers, c)
				}
			}
		}
		d.Links = append(d.Links, v)
	}
	if list, err := s.store.Customers(ctx, store.CustomerFilter{Limit: 500}); err == nil {
		d.All = list
	}
	return d
}

func (s *Server) handleHostZit(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "hostzit", &Page{Title: "HostZit", Nav: "settings", Data: s.hostzitPage(r.Context())})
}

// handleHostZitSave adds or changes a link by hand (URL and token typed
// in). A link made with a pairing code keeps what the pairing settled.
func (s *Server) handleHostZitSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := &store.HostZitLink{ScopeAll: true}
	if id, _ := strconv.ParseInt(r.FormValue("link"), 10, 64); id > 0 {
		old, err := s.store.HostZitLinkByID(ctx, id)
		if err != nil {
			s.notFound(w, r)
			return
		}
		l = old
	}
	u, err := validLinkURL(strings.TrimSpace(r.FormValue("url")))
	if err != nil {
		s.redirectErr(w, r, "/settings/hostzit", err.Error())
		return
	}
	// another address means the token we gave is of no use there
	if l.ID != 0 && u != l.URL && l.TokenID != "" {
		_ = s.store.DeleteAPIToken(ctx, l.TokenID)
		_ = s.store.DeleteRelayLoginsOfLink(ctx, l.ID)
		l.TokenID, l.Addresses, l.Pin, l.ServerName = "", nil, "", ""
	}
	l.URL, l.Insecure = u, r.FormValue("insecure") == "1"
	if t := strings.TrimSpace(r.FormValue("token")); t != "" {
		if !strings.HasPrefix(t, "hzt_") || len(t) > 200 || strings.ContainsAny(t, " \r\n") {
			s.redirectErr(w, r, "/settings/hostzit", "A HostZit API token starts with hzt_")
			return
		}
		l.Token = s.store.SealSecret("hostzit.token", t)
	}
	if err := s.store.SaveHostZitLink(ctx, l); err != nil {
		s.redirectErr(w, r, "/settings/hostzit", storeErr(err))
		return
	}
	s.ForgetHostedDomains()
	s.audit(r, "settings.hostzit", "settings", "HostZit link %q (self-signed allowed %v)", l.URL, l.Insecure)
	go s.publishAllDNS(context.WithoutCancel(ctx))
	s.redirect(w, r, "/settings/hostzit", "Saved. The DNS records of all domains are being written into HostZit's DNS.")
}

// handleHostZitScope sets whether a link serves all customers or only the
// ones chosen (E13).
func (s *Server) handleHostZitScope(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.FormValue("link"), 10, 64)
	l, err := s.store.HostZitLinkByID(r.Context(), id)
	if err != nil {
		s.notFound(w, r)
		return
	}
	all := r.FormValue("scope") != "assigned"
	var list []string
	if !all {
		_ = r.ParseForm()
		list = r.Form["customer"]
	}
	if err := s.store.SetLinkScope(r.Context(), l.ID, all, list); err != nil {
		s.redirectErr(w, r, "/settings/hostzit", storeErr(err))
		return
	}
	s.ForgetHostedDomains()
	if all {
		s.audit(r, "hostzit.scope", "settings", "%s serves all customers", l.URL)
	} else {
		s.audit(r, "hostzit.scope", "settings", "%s serves %d assigned customers", l.URL, len(list))
	}
	s.redirect(w, r, "/settings/hostzit", "Saved.")
}

// apiWebUIDs stores the user IDs of a customer's hosting accounts (HostZit
// calls it when accounts are created, suspended or removed).
func (s *Server) apiWebUIDs(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoadCustomer(w, r)
	if c == nil {
		return
	}
	var in struct {
		UIDs []int `json:"uids"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.store.SetWebUIDs(r.Context(), c.ID, in.UIDs); err != nil {
		storeAPIError(w, err)
		return
	}
	s.apiAudit(r, "customer.web-uids", "customer:"+c.ID, "hosting user IDs %v", in.UIDs)
	writeJSON(w, http.StatusOK, map[string]any{"customer_id": c.ID, "uids": in.UIDs})
}

// handleWebSend blocks or allows mail from a hosting account (a hacked
// website sending spam is blocked automatically).
func (s *Server) handleWebSend(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	uid, err := strconv.Atoi(r.FormValue("uid"))
	blocked := r.FormValue("blocked") == "1"
	back := "/customers/" + c.ID
	if err != nil || s.store.SetWebSendBlocked(r.Context(), store.Scope{CustomerID: c.ID}, uid, blocked) != nil {
		s.redirectErr(w, r, back, "Unknown hosting account.")
		return
	}
	if blocked {
		s.audit(r, "web.send.block", fmt.Sprintf("webuid:%d", uid), "mail from the hosting account blocked (customer %s)", c.Name)
		s.redirect(w, r, back, "Mail from the hosting account is blocked.")
		return
	}
	s.audit(r, "web.send.unblock", fmt.Sprintf("webuid:%d", uid), "mail from the hosting account allowed again (customer %s)", c.Name)
	s.redirect(w, r, back, "Mail from the hosting account is allowed again.")
}

// ---- "does HostZit host this domain?" (the relay asks for every message)

// HostedLife is how long an answer of HostZit about a domain is used
// before it is asked again.
const HostedLife = 10 * time.Minute

// hostedCache remembers HostZit's answers about domains, per link.
type hostedCache struct {
	mu sync.Mutex
	m  map[string]hostedAnswer
}

type hostedAnswer struct {
	customer string
	ok       bool
	until    time.Time
}

// HostedDomain tells whether the HostZit of a link hosts the domain for
// one of its customers, and which customer that is here (empty when the
// customer is not in EmailZit). temp: HostZit could not be asked, so
// nothing is decided — the caller lets the sender try again later.
//
// The relay asks with the link of the login the message came in on (E8),
// so a HostZit only ever vouches for its own websites. HostZit answers
// GET /api/v1/domains/{domain} with the domain's customer (customer_id,
// or customer.id) and its state; 404 means it does not host the domain.
// The answer is remembered for HostedLife, in both directions.
func (s *Server) HostedDomain(ctx context.Context, linkID int64, domain string) (string, bool, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	l, err := s.store.HostZitLinkByID(ctx, linkID)
	if domain == "" || err != nil || l.Token == "" {
		return "", false, false
	}
	key := strconv.FormatInt(linkID, 10) + "|" + domain
	now := s.now()
	s.hosted.mu.Lock()
	a, found := s.hosted.m[key]
	s.hosted.mu.Unlock()
	if found && now.Before(a.until) {
		return a.customer, a.ok, false
	}
	st, body, err := s.hostzitCall(ctx, l, http.MethodGet, "/api/v1/domains/"+url.PathEscape(domain), nil)
	switch {
	case err != nil || st == 0:
		s.log.Warn("HostZit cannot be asked about a domain", "hostzit", l.URL, "domain", domain, "err", err)
		return "", false, true
	case st == http.StatusNotFound:
		a = hostedAnswer{until: now.Add(HostedLife)}
	case st >= 300:
		s.log.Warn("HostZit refused the question about a domain", "hostzit", l.URL, "domain", domain, "status", st, "message", apiMessage(body))
		return "", false, true
	default:
		var in struct {
			CustomerID string `json:"customer_id"`
			Customer   struct {
				ID string `json:"id"`
			} `json:"customer"`
			Status    string `json:"status"`
			Suspended bool   `json:"suspended"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			s.log.Warn("HostZit's answer about a domain is not understood", "domain", domain, "err", err)
			return "", false, true
		}
		cust := in.CustomerID
		if cust == "" {
			cust = in.Customer.ID
		}
		live := !in.Suspended && (in.Status == "" || in.Status == "active")
		// the customer counts only when it is the same customer here (P1)
		// and when this link may serve it (E13)
		if cust != "" {
			if _, err := s.store.CustomerByID(ctx, cust); err != nil || !s.store.LinkServes(ctx, l, cust) {
				cust = ""
			}
		}
		a = hostedAnswer{customer: cust, ok: live, until: now.Add(HostedLife)}
	}
	s.hosted.mu.Lock()
	if s.hosted.m == nil {
		s.hosted.m = map[string]hostedAnswer{}
	}
	if len(s.hosted.m) > 5000 {
		s.hosted.m = map[string]hostedAnswer{} // a flood of unknown domains
	}
	s.hosted.m[key] = a
	s.hosted.mu.Unlock()
	return a.customer, a.ok, false
}

// RelayCustomer tells the relay whether the customer of a mail domain may
// send over the login of this link: an assigned link only ever carries the
// mail of its own customers (E13).
func (s *Server) RelayCustomer(ctx context.Context, linkID int64, customerID string) bool {
	l, err := s.store.HostZitLinkByID(ctx, linkID)
	if err != nil {
		return false
	}
	return s.store.LinkServes(ctx, l, customerID)
}

// ForgetHostedDomains drops what HostZit said about domains (a link
// changed).
func (s *Server) ForgetHostedDomains() {
	s.hosted.mu.Lock()
	s.hosted.m = nil
	s.hosted.mu.Unlock()
}

// HostZitAddresses are the addresses of every linked HostZit, for the
// allow-list of the relay port.
func (s *Server) HostZitAddresses(ctx context.Context) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range s.links(ctx) {
		for _, a := range l.Addresses {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}
