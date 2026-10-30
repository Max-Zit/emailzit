package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/max-zit/emailzit/internal/store"
)

// fakeIdP is a minimal OpenID provider (discovery, keys, token).
type fakeIdP struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	nonce string
	email string
	amr   []string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{}
	f.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		claims := map[string]any{"iss": f.srv.URL, "aud": "emailzit", "sub": "u1", "email": f.email, "email_verified": true, "nonce": f.nonce, "amr": f.amr,
			"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
		f.mu.Unlock()
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		b, _ := json.Marshal(claims)
		obj, _ := sig.Sign(b)
		tok, _ := obj.CompactSerialize()
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": tok, "expires_in": 300})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestCompanySignIn(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	f := newFakeIdP(t)
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "Boss@corp.test", Password: "correct horse battery staple", Role: store.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, settingOIDC, OIDCSettings{Issuer: f.srv.URL, ClientID: "emailzit", ClientSecret: st.SealSecret("oidc.secret", "s"), Label: "Corp", TrustMFA: true}); err != nil {
		t.Fatal(err)
	}
	panel := httptest.NewServer(s.Handler())
	defer panel.Close()
	get := func(c *http.Client, path string) (int, string, string) {
		t.Helper()
		resp, err := c.Get(panel.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, resp.Header.Get("Location"), b.String()
	}
	client := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	signIn := func(email string, amr []string) (*http.Client, string) {
		t.Helper()
		c := client()
		if _, _, body := get(c, "/login"); !strings.Contains(body, "Corp") {
			t.Fatal("no company sign-in button")
		}
		_, loc, _ := get(c, "/login/oidc?next=/customers")
		lu, err := url.Parse(loc)
		if err != nil || !strings.HasPrefix(loc, f.srv.URL+"/auth") || lu.Query().Get("code_challenge") == "" {
			t.Fatalf("start went to %q", loc)
		}
		f.mu.Lock()
		f.nonce, f.email, f.amr = lu.Query().Get("nonce"), email, amr
		f.mu.Unlock()
		_, loc, _ = get(c, "/login/oidc/callback?state="+url.QueryEscape(lu.Query().Get("state"))+"&code=abc")
		return c, loc
	}
	// the provider asked a second factor and that is trusted
	c, loc := signIn("boss@corp.test", []string{"pwd", "mfa"})
	if loc != "/customers" {
		t.Fatalf("callback went to %q", loc)
	}
	if code, _, _ := get(c, "/customers"); code != 200 {
		t.Fatalf("not signed in: %d", code)
	}
	// no second factor at the provider: EmailZit asks its own
	if _, loc = signIn("boss@corp.test", []string{"pwd"}); !strings.HasPrefix(loc, "/login/enroll") {
		t.Fatalf("without amr went to %q", loc)
	}
	// unknown addresses and customers' logins do not get in
	if _, loc = signIn("stranger@corp.test", []string{"mfa"}); !strings.HasPrefix(loc, "/login") || strings.HasPrefix(loc, "/login/") {
		t.Fatalf("an unknown address went to %q", loc)
	}
	// a forged state is refused
	c2 := client()
	_, _, _ = get(c2, "/login/oidc")
	if _, loc, _ := get(c2, "/login/oidc/callback?state=forged&code=abc"); loc != "/login" {
		t.Fatalf("forged state went to %q", loc)
	}
}
