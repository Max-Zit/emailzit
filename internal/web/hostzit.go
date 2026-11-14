package web

import (
	"bytes"
	"context"
	"crypto/tls"
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

// The link to HostZit (INTEGRATION.md P3, P6, P7): when both products run
// for the same customers, the DNS records of a mail domain are written into
// HostZit's DNS (only the names EmailZit owns, as one desired set per zone),
// a domain whose zone HostZit hosts for the same customer counts as
// verified, HostZit tells EmailZit the user IDs of the hosting accounts,
// and the sidebar shows a switch to HostZit.

const settingHostZit = "hostzit"

// HostZitLink is where HostZit's API is. A link made with a pairing code
// also knows the other server's name and addresses and the token EmailZit
// gave it, so Unlink can take that token back.
type HostZitLink struct {
	URL      string `json:"url"`   // e.g. https://host.example.com:8442
	Token    string `json:"token"` // sealed hzt_… token with the scope dns:mail
	Insecure bool   `json:"insecure"`
	// Paired link (empty for a link typed in by hand):
	ServerName string    `json:"server_name,omitempty"`
	Addresses  []string  `json:"addresses,omitempty"` // addresses of HostZit
	Pin        string    `json:"pin,omitempty"`       // SHA-256 of HostZit's public key
	TokenID    string    `json:"token_id,omitempty"`  // the ezt_ token EmailZit gave HostZit
	LinkedAt   time.Time `json:"linked_at,omitempty"`
}

// Paired reports whether the link was made with a pairing code.
func (l HostZitLink) Paired() bool { return l.TokenID != "" }

func (s *Server) hostzitLink(ctx context.Context) HostZitLink {
	var l HostZitLink
	_ = s.store.GetSetting(ctx, settingHostZit, &l)
	return l
}

// errNoZone: HostZit does not host the zone (the records are set elsewhere).
var errNoZone = errors.New("the zone is not in HostZit's DNS")

// hostzitCall sends one API call to HostZit.
func (s *Server) hostzitCall(ctx context.Context, method, path string, body any) (int, []byte, error) {
	l := s.hostzitLink(ctx)
	if l.URL == "" {
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
	// #nosec G402 -- only when the administrator allows a self-signed HostZit
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: l.Insecure}}
	resp, err := (&http.Client{Timeout: 20 * time.Second, Transport: tr}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, b, nil
}

// hzRecord is a record in HostZit's API.
type hzRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
	Content string `json:"content"`
}

// publishDNS writes the mail records of a domain into HostZit's DNS. With
// remove the records EmailZit owns in the zone are removed (domain gone).
func (s *Server) publishDNS(ctx context.Context, domainID string, remove bool, d *store.Domain) {
	if s.hostzitLink(ctx).URL == "" {
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
		if st, _, err := s.hostzitCall(ctx, http.MethodDelete, path, nil); err != nil || (st >= 300 && st != 404) {
			s.log.Warn("removing the mail records from HostZit", "domain", d.Name, "status", st, "err", err)
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
	st, body, err := s.hostzitCall(ctx, http.MethodPut, path, map[string]any{"customer_id": d.CustomerID, "records": recs})
	note, managed := "", false
	switch {
	case err != nil:
		note = "HostZit is not reachable: " + err.Error()
	case st == http.StatusNotFound:
		note = errNoZone.Error()
	case st == http.StatusConflict:
		managed, note = true, "HostZit kept some own records of the customer with the same names: "+apiMessage(body)
	case st >= 300:
		note = fmt.Sprintf("HostZit refused the records (%d): %s", st, apiMessage(body))
	default:
		managed = true
	}
	_ = s.store.SetDomainDNS(ctx, d.ID, managed, note)
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

// publishAllDNS writes the records of every domain (host name changed,
// link saved).
func (s *Server) publishAllDNS(ctx context.Context) {
	if s.hostzitLink(ctx).URL == "" {
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

type hostzitData struct {
	L        HostZitLink
	HasToken bool
	Code     string // a fresh pairing code, shown once
	// Relay is the login the websites of HostZit send their mail with.
	Relay     *store.RelayLogin
	RelayHost string
	RelayPort int
}

// hostzitPage is what the HostZit page shows (the pairing code is added by
// the handler that made it).
func (s *Server) hostzitPage(ctx context.Context) *hostzitData {
	l := s.hostzitLink(ctx)
	d := &hostzitData{L: l, HasToken: l.Token != "", RelayPort: submit.RelayPort}
	if rl, err := s.store.RelayLoginOf(ctx); err == nil {
		d.Relay, d.RelayHost = rl, s.MailConfig(ctx).Hostname
	}
	return d
}

func (s *Server) handleHostZit(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "hostzit", &Page{Title: "HostZit", Nav: "settings", Data: s.hostzitPage(r.Context())})
}

func (s *Server) handleHostZitSave(w http.ResponseWriter, r *http.Request) {
	old := s.hostzitLink(r.Context())
	l := HostZitLink{URL: strings.TrimRight(strings.TrimSpace(r.FormValue("url")), "/"), Insecure: r.FormValue("insecure") == "1", Token: old.Token}
	if l.URL != "" {
		if _, err := validLinkURL(l.URL); err != nil {
			s.redirectErr(w, r, "/settings/hostzit", err.Error())
			return
		}
	}
	// A paired link keeps what the pairing settled as long as the address
	// stays the same; another address means the token we gave is of no use.
	switch {
	case old.Paired() && l.URL == old.URL:
		l.ServerName, l.Addresses, l.Pin, l.TokenID, l.LinkedAt = old.ServerName, old.Addresses, old.Pin, old.TokenID, old.LinkedAt
	case old.TokenID != "":
		_ = s.store.DeleteAPIToken(r.Context(), old.TokenID)
		s.dropRelay(r.Context()) // that HostZit is gone
	}
	if t := strings.TrimSpace(r.FormValue("token")); t != "" {
		if !strings.HasPrefix(t, "hzt_") || len(t) > 200 || strings.ContainsAny(t, " \r\n") {
			s.redirectErr(w, r, "/settings/hostzit", "A HostZit API token starts with hzt_")
			return
		}
		l.Token = s.store.SealSecret("hostzit.token", t)
	}
	if l.URL == "" {
		l = HostZitLink{}
		s.dropRelay(r.Context())
	}
	if err := s.store.SetSetting(r.Context(), settingHostZit, l); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.ForgetHostedDomains()
	s.audit(r, "settings.hostzit", "settings", "HostZit link %q (self-signed allowed %v)", l.URL, l.Insecure)
	go s.publishAllDNS(context.WithoutCancel(r.Context()))
	s.redirect(w, r, "/settings/hostzit", "Saved. The DNS records of all domains are being written into HostZit's DNS.")
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

// hostedCache remembers HostZit's answers about domains.
type hostedCache struct {
	mu sync.Mutex
	m  map[string]hostedAnswer
}

type hostedAnswer struct {
	customer string
	ok       bool
	until    time.Time
}

// HostedDomain tells whether HostZit hosts the domain for one of its
// customers, and which customer that is here (empty when the customer is
// not in EmailZit). temp: HostZit could not be asked, so nothing is
// decided — the caller lets the sender try again later.
//
// HostZit answers GET /api/v1/domains/{domain} with the domain's customer
// (customer_id, or customer.id) and its state; 404 means it does not host
// the domain. The answer is remembered for HostedLife, in both directions.
func (s *Server) HostedDomain(ctx context.Context, domain string) (string, bool, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || s.hostzitLink(ctx).Token == "" {
		return "", false, false
	}
	now := s.now()
	s.hosted.mu.Lock()
	a, found := s.hosted.m[domain]
	s.hosted.mu.Unlock()
	if found && now.Before(a.until) {
		return a.customer, a.ok, false
	}
	st, body, err := s.hostzitCall(ctx, http.MethodGet, "/api/v1/domains/"+url.PathEscape(domain), nil)
	switch {
	case err != nil || st == 0:
		s.log.Warn("HostZit cannot be asked about a domain", "domain", domain, "err", err)
		return "", false, true
	case st == http.StatusNotFound:
		a = hostedAnswer{until: now.Add(HostedLife)}
	case st >= 300:
		s.log.Warn("HostZit refused the question about a domain", "domain", domain, "status", st, "message", apiMessage(body))
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
		if cust != "" {
			if _, err := s.store.CustomerByID(ctx, cust); err != nil {
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
	s.hosted.m[domain] = a
	s.hosted.mu.Unlock()
	return a.customer, a.ok, false
}

// ForgetHostedDomains drops what HostZit said about domains (the link
// changed).
func (s *Server) ForgetHostedDomains() {
	s.hosted.mu.Lock()
	s.hosted.m = nil
	s.hosted.mu.Unlock()
}

// HostZitAddresses are the addresses of the linked HostZit (empty when the
// link was typed in by hand and nobody said them).
func (s *Server) HostZitAddresses(ctx context.Context) []string {
	return s.hostzitLink(ctx).Addresses
}
