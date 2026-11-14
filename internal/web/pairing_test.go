package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/submit"
)

// A pairing code works once and only for ten minutes, and EmailZit keeps
// only its hash.
func TestPairingCodeIsOneUseAndExpires(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	now := time.Now()
	s.now = func() time.Time { return now }

	code, until, err := s.NewPairingCode(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, pairingPrefix) {
		t.Fatalf("code %q does not start with %q", code, pairingPrefix)
	}
	if until.Sub(now) != PairingLife {
		t.Errorf("the code lives %v, want %v", until.Sub(now), PairingLife)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairingPrefix))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		V      int    `json:"v"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.V != 1 || body.Secret == "" || !strings.HasPrefix(body.URL, "https://") {
		t.Fatalf("the code holds %+v", body)
	}
	var kept pairing
	if err := st.GetSetting(ctx, settingPairing, &kept); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(kept.Hash, body.Secret) || kept.Hash == body.Secret {
		t.Error("the secret itself is stored, not its hash")
	}

	if err := s.usePairingCode(ctx, "wrong"); err == nil {
		t.Error("a wrong code was accepted")
	}
	// a wrong attempt also uses the code up
	if err := s.usePairingCode(ctx, body.Secret); err == nil {
		t.Error("the code still worked after an attempt")
	}

	code, _, err = s.NewPairingCode(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairingPrefix))
	_ = json.Unmarshal(raw, &body)
	if err := s.usePairingCode(ctx, body.Secret); err != nil {
		t.Fatalf("a fresh code was refused: %v", err)
	}

	code, _, _ = s.NewPairingCode(ctx, "admin")
	raw, _ = base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairingPrefix))
	_ = json.Unmarshal(raw, &body)
	now = now.Add(PairingLife + time.Second)
	if err := s.usePairingCode(ctx, body.Secret); err == nil {
		t.Error("an expired code was accepted")
	}
}

// At most five attempts a minute, per address and for the open code.
func TestPairingLimiter(t *testing.T) {
	var l pairingLimiter
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !l.allow(now, "ip:203.0.113.5", "code") {
			t.Fatalf("attempt %d was already refused", i+1)
		}
	}
	if l.allow(now, "ip:203.0.113.5", "code") {
		t.Error("the sixth attempt within a minute was allowed")
	}
	if l.allow(now, "ip:198.51.100.7", "code") {
		t.Error("another address got through although the code is at its limit")
	}
	if !l.allow(now.Add(61*time.Second), "ip:203.0.113.5", "code") {
		t.Error("after a minute the attempts are not forgotten")
	}
}

// Only addresses and networks of the other server are taken.
func TestValidAddresses(t *testing.T) {
	if _, err := validAddresses(nil); err == nil {
		t.Error("an empty list was accepted")
	}
	got, err := validAddresses([]string{" 144.91.79.144 ", "2a02:c207:2374:9029::1", "", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("kept %v", got)
	}
	if _, err := validAddresses([]string{"h1.maxzit.com"}); err == nil {
		t.Error("a name was accepted as an address")
	}
}

// The pairing hands HostZit everything it needs: an API token of its own
// bound to its addresses, and the login its websites send their mail with.
// The unlink takes both back.
func TestPairingGivesTokenAndRelay(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	s.Mail = &stubMail{}
	if err := st.SetSetting(ctx, settingMail, MailSettings{Hostname: "mail.example.net", MaxMessageMB: 25}); err != nil {
		t.Fatal(err)
	}
	// on a hosting server the panel answers everyone (customers and mail
	// users sign in there), so HostZit reaches it as well
	all, err := netacl.Parse([]string{"0.0.0.0/0", "::/0"})
	if err != nil {
		t.Fatal(err)
	}
	s.MgmtACL.Set(all)
	newCode := func() string {
		t.Helper()
		code, _, err := s.NewPairingCode(ctx, "admin")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairingPrefix))
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Secret string `json:"secret"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		return body.Secret
	}
	ask := func(secret, payload string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/link/hostzit", strings.NewReader(payload))
		r.Header.Set("Authorization", "Pairing "+secret)
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "144.91.79.144:50000"
		// the address HostZit reached this server on (the answer names it,
		// so HostZit can bind its own token to it)
		local := &net.TCPAddr{IP: net.ParseIP("213.136.66.211"), Port: 8444}
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(local)))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	payload := `{"hostzit_url":"https://h1.example.net:8442","server_name":"h1","addresses":["144.91.79.144","2a02:c207::1"]}`
	secret := newCode()
	if w := ask("nonsense", payload); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong code answered %d", w.Code)
	}
	// the code is used up by the attempt
	if w := ask(secret, payload); w.Code != http.StatusUnauthorized {
		t.Fatalf("the code still worked after an attempt (%d)", w.Code)
	}

	w := ask(newCode(), payload)
	if w.Code != http.StatusCreated {
		t.Fatalf("the pairing answered %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Token     string   `json:"api_token"`
		Scopes    []string `json:"scopes"`
		Addresses []string `json:"emailzit_addresses"`
		Relay     struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
			STARTTLS bool   `json:"starttls"`
		} `json:"relay"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.Token, "ezt_") || len(out.Scopes) != 3 {
		t.Errorf("the answer holds %+v", out)
	}
	if len(out.Addresses) != 1 || out.Addresses[0] != "213.136.66.211" {
		t.Errorf("EmailZit's addresses are %v, want the one HostZit reached", out.Addresses)
	}
	if out.Relay.Host != "mail.example.net" || out.Relay.Port != submit.RelayPort || !out.Relay.STARTTLS ||
		out.Relay.Username != relayUser+"@mail.example.net" || len(out.Relay.Password) < 20 {
		t.Errorf("the relay login is %+v", out.Relay)
	}
	if _, err := st.CheckRelayLogin(ctx, out.Relay.Username, out.Relay.Password); err != nil {
		t.Errorf("the relay login does not work: %v", err)
	}
	// the token EmailZit gave works only from HostZit's addresses
	tok, err2 := st.APITokenBySecret(ctx, out.Token, "144.91.79.144")
	if err2 != nil {
		t.Fatal(err2)
	}
	if len(tok.AllowedIPs) != 2 || tok.AllowedIPs[0] != "144.91.79.144" {
		t.Errorf("the token allows %v", tok.AllowedIPs)
	}
	if tok.AllowsIP("203.0.113.9") {
		t.Error("the token works from another address")
	}
	link := s.hostzitLink(ctx)
	if !link.Paired() || link.ServerName != "h1" || link.URL != "https://h1.example.net:8442" {
		t.Errorf("the link is %+v", link)
	}

	// HostZit ends the link: both the token and the relay login go
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/link/hostzit", nil)
	r.Header.Set("Authorization", "Bearer "+out.Token)
	r.RemoteAddr = "144.91.79.144:50001"
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("the unlink answered %d: %s", w.Code, w.Body.String())
	}
	if s.hostzitLink(ctx).URL != "" {
		t.Error("the link is still there")
	}
	if _, err := st.RelayLoginOf(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the relay login is still there: %v", err)
	}
	if _, err := st.APITokenBySecret(ctx, out.Token, "144.91.79.144"); err == nil {
		t.Error("the token of HostZit still works")
	}
}
