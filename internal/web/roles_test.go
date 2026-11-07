package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// TestRoles walks every protected route of the panels and the mail user
// pages: each role that may not use a route is refused (403, or sent to its
// sign-in page), and every page a role may open loads without a server
// error (a crawl with missing objects, so handlers see unknown IDs too).
func TestRoles(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	h := s.Handler()

	p := &store.Package{Slug: "r", Name: "R", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 100, MailboxMB: 10, MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "R C", PackageID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := st.CreateDomain(ctx, store.Staff, c.ID, "roles.test", true)
	mb, err := st.CreateMailbox(ctx, store.Staff, store.NewMailbox{DomainID: d.ID, LocalPart: "ana", Password: "a-long-password-1"})
	if err != nil {
		t.Fatal(err)
	}
	cookies := map[string]*http.Cookie{}
	for _, u := range []store.NewUser{
		{Username: "admin", Role: store.RoleAdmin}, {Username: "operator", Role: store.RoleOperator},
		{Username: "viewer", Role: store.RoleViewer}, {Username: "customer", Role: store.RoleCustomer, CustomerID: c.ID},
	} {
		u.Password = "correct horse battery staple"
		usr, err := st.CreateUser(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		tok, _, err := st.CreateSession(ctx, usr.ID, store.StageFull, time.Hour, "127.0.0.1", "test")
		if err != nil {
			t.Fatal(err)
		}
		cookies[u.Username] = &http.Cookie{Name: "ezsession", Value: tok}
	}
	tok, _, err := st.CreateMailSession(ctx, mb.ID, store.StageFull, time.Hour, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	cookies["mailuser"] = &http.Cookie{Name: "ezmail", Value: tok}
	cookies["anonymous"] = nil

	allowed := map[string][]string{
		"app":        {"admin", "operator", "viewer", "customer"},
		"staff":      {"admin", "operator", "viewer"},
		"staffWrite": {"admin", "operator"},
		"write":      {"admin", "operator", "customer"},
		"admin":      {"admin"},
		"mail":       {"mailuser"},
	}
	wild := regexp.MustCompile(`\{[^}]*\}`)
	do := func(method, path string, ck *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader("x=1"))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Origin", "http://example.com")
		r.Host = "example.com"
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if ck != nil {
			r.AddCookie(ck)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	refused := func(w *httptest.ResponseRecorder) bool {
		loc := w.Header().Get("Location")
		return w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized ||
			(w.Code/100 == 3 && (strings.HasPrefix(loc, "/login") || strings.HasPrefix(loc, "/mail/login") || strings.HasPrefix(loc, "/setup")))
	}
	if len(s.routes) < 50 {
		t.Fatalf("only %d routes recorded", len(s.routes))
	}
	checked := 0
	for _, rt := range s.routes {
		method, pattern, _ := strings.Cut(rt.pattern, " ")
		path := strings.ReplaceAll(pattern, "{$}", "")
		path = wild.ReplaceAllString(path, "00000000-0000-4000-8000-000000000000")
		for role, ck := range cookies {
			ok := false
			for _, a := range allowed[rt.who] {
				ok = ok || a == role
			}
			if !ok {
				if w := do(method, path, ck); !refused(w) {
					t.Errorf("%s %s (%s): %s was not refused: %d %s", method, path, rt.who, role, w.Code, w.Header().Get("Location"))
				}
				checked++
				continue
			}
			if method != http.MethodGet || strings.HasPrefix(path, "/mail/webmail") || path == "/mail/filters" {
				// allowed writes are covered by the handler tests; webmail
				// and the filters need a running Dovecot (without one they sign the
				// user out)
				continue
			}
			w := do(method, path, ck)
			if w.Code >= 500 || refused(w) {
				t.Errorf("%s %s (%s): %s got %d %s", method, path, rt.who, role, w.Code, w.Header().Get("Location"))
			}
			checked++
		}
	}
	// API: a token with one scope is refused on routes that need another
	tokens := map[string]string{}
	for _, sc := range store.Scopes {
		tk, _, err := st.CreateAPIToken(ctx, sc, []string{sc}, nil, 0, "admin")
		if err != nil {
			t.Fatal(err)
		}
		tokens[sc] = tk
	}
	for _, rt := range s.apiRoutes {
		method, pattern, _ := strings.Cut(rt.pattern, " ")
		path := wild.ReplaceAllString(pattern, "00000000-0000-4000-8000-000000000000")
		for sc, tk := range tokens {
			code, _ := call(t, h, method, path, tk, "{}")
			if sc != rt.who && code != http.StatusForbidden {
				t.Errorf("API %s %s needs %s: a %s token got %d", method, path, rt.who, sc, code)
			}
			if sc == rt.who && (code == http.StatusForbidden || code == http.StatusUnauthorized || code >= 500) {
				t.Errorf("API %s %s: its own scope %s got %d", method, path, sc, code)
			}
			checked++
		}
		if code, _ := call(t, h, method, path, "", "{}"); code != http.StatusUnauthorized {
			t.Errorf("API %s %s without a token: %d", method, path, code)
		}
	}
	t.Logf("%d panel routes, %d API routes, %d checks", len(s.routes), len(s.apiRoutes), checked)
}
