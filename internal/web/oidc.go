package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/max-zit/emailzit/internal/auth"
	"github.com/max-zit/emailzit/internal/store"
)

// Company sign-in for staff with OpenID Connect (Microsoft Entra ID, Google
// Workspace, Keycloak, Authentik …). The identity provider proves the e-mail
// address; a staff account with that address as its username must already
// exist (no accounts are made, customers never sign in this way). The web
// always needs a second factor: EmailZit asks its own code unless the
// administrator trusts the provider's and the identity token shows that the
// provider did ask one (amr).

const settingOIDC = "oidc"

// OIDCSettings configure the identity provider.
type OIDCSettings struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // sealed
	Label        string `json:"label"`
	TrustMFA     bool   `json:"trust_mfa"`
}

func (c OIDCSettings) enabled() bool { return c.Issuer != "" && c.ClientID != "" }

func (s *Server) oidcSettings(ctx context.Context) OIDCSettings {
	var c OIDCSettings
	_ = s.store.GetSetting(ctx, settingOIDC, &c)
	return c
}

var oidcCache struct {
	sync.Mutex
	key      string
	provider *oidc.Provider
	at       time.Time
}

func (s *Server) oidcConfig(ctx context.Context, r *http.Request) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	c := s.oidcSettings(ctx)
	if !c.enabled() {
		return nil, nil, fmt.Errorf("company sign-in is not set up")
	}
	oidcCache.Lock()
	defer oidcCache.Unlock()
	if oidcCache.provider == nil || oidcCache.key != c.Issuer || time.Since(oidcCache.at) > time.Hour {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		p, err := oidc.NewProvider(cctx, c.Issuer)
		if err != nil {
			return nil, nil, err
		}
		oidcCache.provider, oidcCache.key, oidcCache.at = p, c.Issuer, time.Now()
	}
	secret, _ := s.store.OpenSecret("oidc.secret", c.ClientSecret)
	conf := &oauth2.Config{ClientID: c.ClientID, ClientSecret: secret, Endpoint: oidcCache.provider.Endpoint(),
		RedirectURL: oidcRedirect(r), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	return conf, oidcCache.provider.Verifier(&oidc.Config{ClientID: c.ClientID}), nil
}

func oidcRedirect(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/login/oidc/callback"
}

// The state cookie carries state, nonce, the PKCE verifier and where to go,
// signed with a key of this process (a restart in between only means
// signing in again).
var stateKey = sync.OnceValue(func() []byte { return []byte(auth.RandomToken(32)) })

func stateMAC(v string) string {
	m := hmac.New(sha256.New, stateKey())
	m.Write([]byte(v))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

const oidcCookie = "ezoidc"

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	conf, _, err := s.oidcConfig(r.Context(), r)
	if err != nil {
		s.log.Warn("company sign-in", "err", err)
		s.redirectErr(w, r, "/login", "Company sign-in is not available.")
		return
	}
	state, nonce, verifier := auth.RandomToken(24), auth.RandomToken(24), oauth2.GenerateVerifier()
	v := state + "|" + nonce + "|" + verifier + "|" + safeNext(r.FormValue("next"))
	// #nosec G124 -- Secure whenever the request came over TLS
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: url.QueryEscape(v + "|" + stateMAC(v)), Path: "/login/oidc", MaxAge: 600, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusSeeOther)
}

// mfaAMR are the "amr" values that show a second factor (RFC 8176).
var mfaAMR = map[string]bool{"mfa": true, "otp": true, "hwk": true, "swk": true, "sms": true, "tel": true, "fido": true, "sc": true}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	refuse := func(msg string) {
		s.guard.fail(r.Context(), ip, "", "company sign-in")
		s.log.Warn("company sign-in failed", "ip", ip, "reason", msg)
		s.auditAs(r, "-", "login.failed", "oidc", "company sign-in: %s", msg)
		s.redirectErr(w, r, "/login", "Company sign-in failed.")
	}
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
		s.redirectErr(w, r, "/login", "Too many failed attempts from your address. Try again later.")
		return
	}
	ck, err := r.Cookie(oidcCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Path: "/login/oidc", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode}) // #nosec G124
	if err != nil {
		refuse("the sign-in took too long")
		return
	}
	raw, _ := url.QueryUnescape(ck.Value)
	i := strings.LastIndex(raw, "|")
	if i < 0 || !hmac.Equal([]byte(raw[i+1:]), []byte(stateMAC(raw[:i]))) {
		refuse("invalid state")
		return
	}
	parts := strings.SplitN(raw[:i], "|", 4)
	if len(parts) != 4 || !hmac.Equal([]byte(r.FormValue("state")), []byte(parts[0])) {
		refuse("invalid state")
		return
	}
	if e := r.FormValue("error"); e != "" {
		refuse("the provider refused: " + trimLen(e, 100))
		return
	}
	conf, verifier, err := s.oidcConfig(r.Context(), r)
	if err != nil {
		refuse(err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok, err := conf.Exchange(ctx, r.FormValue("code"), oauth2.VerifierOption(parts[2]))
	if err != nil {
		refuse("the code was refused")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil || !hmac.Equal([]byte(idt.Nonce), []byte(parts[1])) {
		refuse("invalid identity token")
		return
	}
	var claims struct {
		Email    string   `json:"email"`
		Verified *bool    `json:"email_verified"`
		UPN      string   `json:"preferred_username"`
		AMR      []string `json:"amr"`
	}
	_ = idt.Claims(&claims)
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" && strings.Contains(claims.UPN, "@") {
		email = strings.ToLower(strings.TrimSpace(claims.UPN))
	}
	if email == "" || claims.Verified != nil && !*claims.Verified {
		refuse("the provider sent no verified e-mail address")
		return
	}
	u, err := s.store.StaffByUsername(r.Context(), email)
	if err != nil || u.Disabled {
		refuse("no staff account " + trimLen(email, 120))
		return
	}
	providerMFA := false
	for _, a := range claims.AMR {
		providerMFA = providerMFA || mfaAMR[strings.ToLower(a)]
	}
	next := safeNext(parts[3])
	x := &store.Session{UserID: u.ID, IP: ip, UserAgent: r.UserAgent()}
	if s.DevNo2FA || (providerMFA && s.oidcSettings(r.Context()).TrustMFA) {
		if s.finishLogin(w, r, x, u, "company sign-in") {
			http.Redirect(w, r, next, http.StatusSeeOther)
		}
		return
	}
	t, _, err := s.store.CreateSession(r.Context(), u.ID, store.StageMFA, store.MFATimeout, ip, r.UserAgent())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, t, store.MFATimeout)
	step := "/login/2fa"
	if !u.TOTPEnabled {
		step = "/login/enroll"
	}
	http.Redirect(w, r, step+"?next="+url.QueryEscape(next), http.StatusSeeOther)
}

func trimLen(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type oidcData struct {
	C         OIDCSettings
	HasSecret bool
	Redirect  string
}

func (s *Server) handleOIDCSettings(w http.ResponseWriter, r *http.Request) {
	c := s.oidcSettings(r.Context())
	s.render(w, r, http.StatusOK, "signin", &Page{Title: "Company sign-in", Nav: "settings", Data: &oidcData{C: c, HasSecret: c.ClientSecret != "", Redirect: oidcRedirect(r)}})
}

func (s *Server) handleOIDCSettingsSave(w http.ResponseWriter, r *http.Request) {
	old := s.oidcSettings(r.Context())
	c := OIDCSettings{Issuer: strings.TrimRight(strings.TrimSpace(r.FormValue("issuer")), "/"), ClientID: strings.TrimSpace(r.FormValue("client_id")),
		Label: strings.TrimSpace(r.FormValue("label")), TrustMFA: r.FormValue("trust_mfa") == "1", ClientSecret: old.ClientSecret}
	if sec := r.FormValue("client_secret"); sec != "" {
		c.ClientSecret = s.store.SealSecret("oidc.secret", sec)
	}
	if c.Issuer != "" {
		u, err := url.Parse(c.Issuer)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
			s.redirectErr(w, r, "/settings/signin", "The issuer must start with https://")
			return
		}
	}
	if len(c.Label) > 60 || len(c.ClientID) > 200 || len(c.Issuer) > 300 {
		s.redirectErr(w, r, "/settings/signin", "Too long.")
		return
	}
	if c.Issuer == "" {
		c = OIDCSettings{}
	}
	if err := s.store.SetSetting(r.Context(), settingOIDC, c); err != nil {
		s.serverError(w, r, err)
		return
	}
	oidcCache.Lock()
	oidcCache.provider = nil
	oidcCache.Unlock()
	s.audit(r, "settings.oidc", "settings", "company sign-in %q (provider's second factor trusted: %v)", c.Issuer, c.TrustMFA)
	s.redirect(w, r, "/settings/signin", "Saved.")
}
