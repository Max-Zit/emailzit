package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/auth"
	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/submit"
)

// Linking EmailZit and HostZit with ONE pairing code (INTEGRATION.md,
// "Pairing protocol"). The administrator asks EmailZit for a code and
// pastes it into HostZit; the two servers then make each other's tokens
// themselves, with the least rights and with the addresses of the other
// server, so nobody copies a token or an address list by hand.
//
// The code is shown once, lives ten minutes and works once. EmailZit keeps
// only its hash, and the code never reaches a log or the audit entry.

const (
	settingPairing = "hostzit_pairing"
	// PairingLife is how long a pairing code works.
	PairingLife = 10 * time.Minute
	// pairingPrefix marks our codes.
	pairingPrefix = "ezlink_"
	// linkTokenName is the name of the API token EmailZit gives HostZit.
	linkTokenName = "HostZit (paired)" // #nosec G101 -- a name shown on the token page, not a secret
	// relayUser is the local part of the relay login of the link.
	relayUser = "hostzit-relay"
)

// pairing is what EmailZit remembers of an open pairing code.
type pairing struct {
	Hash    string    `json:"hash"` // sha256 of the secret, hex
	Expires time.Time `json:"expires"`
	By      string    `json:"by"`
}

// NewPairingCode makes a code for the administrator to paste into HostZit.
// Only the hash is kept; an older code stops working.
func (s *Server) NewPairingCode(ctx context.Context, by string) (string, time.Time, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw[:])
	until := s.now().Add(PairingLife)
	sum := sha256.Sum256([]byte(secret))
	p := pairing{Hash: base64.RawURLEncoding.EncodeToString(sum[:]), Expires: until, By: by}
	if err := s.store.SetSetting(ctx, settingPairing, p); err != nil {
		return "", time.Time{}, err
	}
	body := map[string]any{"v": 1, "url": s.PublicPanelURL(ctx), "secret": secret}
	if pin := s.certPin(); pin != "" {
		body["pin"] = pin
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", time.Time{}, err
	}
	return pairingPrefix + base64.RawURLEncoding.EncodeToString(b), until, nil
}

// usePairingCode checks the secret HostZit sends and uses the code up. It
// is used up even when the rest of the pairing fails, so a code cannot be
// tried twice.
func (s *Server) usePairingCode(ctx context.Context, secret string) error {
	var p pairing
	if err := s.store.GetSetting(ctx, settingPairing, &p); err != nil || p.Hash == "" {
		return errors.New("no pairing code is open")
	}
	_ = s.store.SetSetting(ctx, settingPairing, pairing{}) // one use, whatever follows
	if s.now().After(p.Expires) {
		return errors.New("the pairing code has expired")
	}
	sum := sha256.Sum256([]byte(secret))
	want, err := base64.RawURLEncoding.DecodeString(p.Hash)
	if err != nil || subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return errors.New("wrong pairing code")
	}
	return nil
}

// pairingLimiter counts the attempts of an address and of the open code,
// at most five a minute each (the protocol asks for it).
type pairingLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *pairingLimiter) allow(now time.Time, keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	ok := true
	for _, k := range keys {
		var keep []time.Time
		for _, t := range l.hits[k] {
			if now.Sub(t) < time.Minute {
				keep = append(keep, t)
			}
		}
		if len(keep) >= 5 {
			ok = false
		}
		l.hits[k] = append(keep, now)
	}
	return ok
}

// handleLinkHostZit is step 1 of the pairing: HostZit sends the code and
// its own data and gets an API token for EmailZit.
func (s *Server) handleLinkHostZit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.pairLimit.allow(s.now(), "ip:"+ip, "code") {
		apiError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts; try again in a minute", "")
		return
	}
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Pairing ")
	if !ok || strings.TrimSpace(secret) == "" {
		apiError(w, http.StatusUnauthorized, "invalid_code", "the pairing code is not valid", "")
		return
	}
	var in struct {
		URL       string   `json:"hostzit_url"`
		Name      string   `json:"server_name"`
		Addresses []string `json:"addresses"`
		Pin       string   `json:"pin"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.usePairingCode(r.Context(), strings.TrimSpace(secret)); err != nil {
		s.log.Warn("pairing refused", "ip", ip, "err", err)
		apiError(w, http.StatusUnauthorized, "invalid_code", "the pairing code is not valid", "")
		return
	}
	u, err := validLinkURL(in.URL)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_url", err.Error(), "hostzit_url")
		return
	}
	addrs, err := validAddresses(in.Addresses)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_address", err.Error(), "addresses")
		return
	}
	// a second pairing replaces the link: the old token of the other side
	// goes first
	old := s.hostzitLink(r.Context())
	if old.TokenID != "" {
		_ = s.store.DeleteAPIToken(r.Context(), old.TokenID)
	}
	tok, rec, err := s.store.CreateAPIToken(r.Context(), linkTokenName,
		[]string{store.ScopeCustomersRead, store.ScopeCustomersWrite, store.ScopeSSO}, addrs, 0, "pairing")
	if err != nil {
		s.apiInternal(w, r, err)
		return
	}
	link := HostZitLink{URL: u, Insecure: old.Insecure, ServerName: strings.TrimSpace(in.Name),
		Addresses: addrs, Pin: strings.TrimSpace(in.Pin), TokenID: rec.ID, LinkedAt: s.now().UTC()}
	if err := s.store.SetSetting(r.Context(), settingHostZit, link); err != nil {
		_ = s.store.DeleteAPIToken(r.Context(), rec.ID)
		s.apiInternal(w, r, err)
		return
	}
	s.ForgetHostedDomains()
	_ = s.store.Audit(r.Context(), "-", ip, "hostzit.paired", "settings", "paired with "+u+" (token for "+strings.Join(addrs, ", ")+")")
	writeJSON(w, http.StatusCreated, map[string]any{
		"api_token":          tok,
		"scopes":             []string{store.ScopeCustomersRead, store.ScopeCustomersWrite, store.ScopeSSO},
		"emailzit_addresses": s.ownAddresses(r.Context()),
		"emailzit_url":       s.PublicPanelURL(r.Context()),
		"emailzit_mail_host": s.MailConfig(r.Context()).Hostname,
		"relay":              s.newRelay(r.Context(), ip),
	})
}

// handleLinkDNSToken is step 2: HostZit hands over its own token for the
// DNS of the mail domains.
func (s *Server) handleLinkDNSToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	t := strings.TrimSpace(in.Token)
	if !strings.HasPrefix(t, "hzt_") || len(t) < 20 {
		apiError(w, http.StatusBadRequest, "invalid_token", "a HostZit API token starts with hzt_", "token")
		return
	}
	l := s.hostzitLink(r.Context())
	if l.URL == "" {
		apiError(w, http.StatusConflict, "not_paired", "pair the servers first", "")
		return
	}
	l.Token = s.store.SealSecret("hostzit.token", t)
	if err := s.store.SetSetting(r.Context(), settingHostZit, l); err != nil {
		s.apiInternal(w, r, err)
		return
	}
	if st, _, err := s.hostzitCall(r.Context(), http.MethodGet, "/api/v1/zit/info", nil); err != nil || st >= 300 {
		l.Token = ""
		_ = s.store.SetSetting(r.Context(), settingHostZit, l)
		apiError(w, http.StatusBadGateway, "token_refused", "HostZit did not accept the token", "token")
		return
	}
	_ = s.store.Audit(r.Context(), "-", clientIP(r), "hostzit.dns_token", "settings", "DNS token of "+l.URL+" stored")
	go s.publishAllDNS(context.WithoutCancel(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleLinkDelete ends the link from HostZit's side: the stored HostZit
// token goes, and so does the token EmailZit gave HostZit.
func (s *Server) handleLinkDelete(w http.ResponseWriter, r *http.Request) {
	l := s.hostzitLink(r.Context())
	if l.URL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if err := s.store.SetSetting(r.Context(), settingHostZit, HostZitLink{}); err != nil {
		s.apiInternal(w, r, err)
		return
	}
	if l.TokenID != "" {
		_ = s.store.DeleteAPIToken(r.Context(), l.TokenID)
	}
	s.dropRelay(r.Context())
	s.ForgetHostedDomains()
	_ = s.store.Audit(r.Context(), "-", clientIP(r), "hostzit.unlinked", "settings", "unlinked by HostZit ("+l.URL+")")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ownAddresses are the addresses of this server HostZit should allow for
// EmailZit's token: the addresses of the mail host name, or the addresses
// of this machine when the name says nothing.
func (s *Server) ownAddresses(ctx context.Context) []string {
	var out []string
	if h := s.MailConfig(ctx).Hostname; h != "" {
		if ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h); err == nil {
			for _, ip := range ips {
				out = append(out, ip.String())
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			out = append(out, n.IP.String())
		}
	}
	return out
}

// validAddresses keeps the addresses and networks of the other server.
func validAddresses(list []string) ([]string, error) {
	var out []string
	for _, a := range list {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, err := netacl.Parse([]string{a}); err != nil {
			return nil, errors.New("one of the addresses is not an address or network")
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("name at least one address of the other server")
	}
	if len(out) > 20 {
		return nil, errors.New("at most 20 addresses")
	}
	return out, nil
}

// validLinkURL checks the address of the other server.
func validLinkURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || len(raw) > 200 {
		// the settings page shows this message to the administrator, in
		// their language, so it is a sentence and not an error fragment
		//lint:ignore ST1005 a message for the page, translated as written
		return "", errors.New("The address must look like https://host.example.com:8442")
	}
	return raw, nil
}

// PublicPanelURL is how the other server reaches this panel.
func (s *Server) PublicPanelURL(ctx context.Context) string {
	host := s.MailConfig(ctx).Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	port := "8444"
	if _, p, err := net.SplitHostPort(s.RunningMgmt); err == nil && p != "" {
		port = p
	}
	return "https://" + net.JoinHostPort(strings.ToLower(host), port)
}

// certPin is the SHA-256 of the public key of the panel's certificate,
// for a HostZit that cannot check the certificate the usual way. Empty
// when the panel has no certificate of its own yet.
func (s *Server) certPin() string {
	b, err := os.ReadFile(filepath.Join(s.DataDir, "tls", "panel.crt")) // #nosec G304 -- our own data directory
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// handleHostZitCode makes a pairing code and shows it once.
func (s *Server) handleHostZitCode(w http.ResponseWriter, r *http.Request) {
	code, until, err := s.NewPairingCode(r.Context(), userFrom(r).Username)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// the code itself never goes into the audit log
	s.audit(r, "hostzit.code", "settings", "pairing code created (valid until %s)", until.UTC().Format(time.RFC3339))
	d := s.hostzitPage(r.Context())
	d.Code = code
	s.render(w, r, http.StatusOK, "hostzit", &Page{Title: "HostZit", Nav: "settings", Data: d})
}

// handleHostZitUnlink ends the link from this side: EmailZit tells HostZit
// to drop its token, then forgets everything of the link.
func (s *Server) handleHostZitUnlink(w http.ResponseWriter, r *http.Request) {
	l := s.hostzitLink(r.Context())
	if l.URL == "" {
		s.redirect(w, r, "/settings/hostzit", "Not linked.")
		return
	}
	msg := "The link is ended."
	if l.Token != "" {
		if st, _, err := s.hostzitCall(r.Context(), http.MethodDelete, "/api/v1/link/emailzit", nil); err != nil || (st >= 300 && st != 404) {
			msg = "The link is ended here; HostZit could not be reached, so remove the link there as well."
		}
	}
	if err := s.store.SetSetting(r.Context(), settingHostZit, HostZitLink{}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if l.TokenID != "" {
		_ = s.store.DeleteAPIToken(r.Context(), l.TokenID)
	}
	s.dropRelay(r.Context())
	s.ForgetHostedDomains()
	s.audit(r, "hostzit.unlink", "settings", "link with %s ended", l.URL)
	s.redirect(w, r, "/settings/hostzit", msg)
}

// newRelay makes the relay login of the link and returns it for the
// pairing answer: the websites of a HostZit on another server send their
// mail with it (INTEGRATION.md E3). nil when this server takes no mail.
func (s *Server) newRelay(ctx context.Context, ip string) any {
	if s.Mail == nil {
		return nil
	}
	host := s.MailConfig(ctx).Hostname
	if host == "" {
		s.log.Warn("no relay login for HostZit: the mail host name is not set yet")
		return nil
	}
	user := relayUser + "@" + strings.ToLower(host)
	pass := auth.RandomToken(24)
	if _, err := s.store.SetRelayLogin(ctx, user, pass); err != nil {
		s.log.Error("relay login", "err", err)
		return nil
	}
	_ = s.store.Audit(ctx, "-", ip, "hostzit.relay", "settings", "relay login "+user+" created for the websites of HostZit")
	return map[string]any{
		"host":     strings.ToLower(host),
		"port":     submit.RelayPort,
		"username": user,
		"password": pass,
		"starttls": true,
	}
}

// dropRelay removes the relay login (the link ended).
func (s *Server) dropRelay(ctx context.Context) {
	if err := s.store.DeleteRelayLogins(ctx); err != nil {
		s.log.Error("relay login", "err", err)
	}
}
