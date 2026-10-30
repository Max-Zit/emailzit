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
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// The link to HostZit (INTEGRATION.md P3, P6, P7): when both products run
// for the same customers, the DNS records of a mail domain are written into
// HostZit's DNS (only the names EmailZit owns, as one desired set per zone),
// a domain whose zone HostZit hosts for the same customer counts as
// verified, HostZit tells EmailZit the user IDs of the hosting accounts,
// and the sidebar shows a switch to HostZit.

const settingHostZit = "hostzit"

// HostZitLink is where HostZit's API is.
type HostZitLink struct {
	URL      string `json:"url"`   // e.g. https://host.example.com:8442
	Token    string `json:"token"` // sealed hzt_… token with the scope dns:mail
	Insecure bool   `json:"insecure"`
}

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
	for _, r := range mailRecords(d, m, k) {
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
}

func (s *Server) handleHostZit(w http.ResponseWriter, r *http.Request) {
	l := s.hostzitLink(r.Context())
	s.render(w, r, http.StatusOK, "hostzit", &Page{Title: "HostZit", Nav: "settings", Data: &hostzitData{L: l, HasToken: l.Token != ""}})
}

func (s *Server) handleHostZitSave(w http.ResponseWriter, r *http.Request) {
	old := s.hostzitLink(r.Context())
	l := HostZitLink{URL: strings.TrimRight(strings.TrimSpace(r.FormValue("url")), "/"), Insecure: r.FormValue("insecure") == "1", Token: old.Token}
	if l.URL != "" {
		u, err := url.Parse(l.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || len(l.URL) > 200 {
			s.redirectErr(w, r, "/settings/hostzit", "The address must look like https://host.example.com:8442")
			return
		}
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
	}
	if err := s.store.SetSetting(r.Context(), settingHostZit, l); err != nil {
		s.serverError(w, r, err)
		return
	}
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
