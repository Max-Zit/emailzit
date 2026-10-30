package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/testdb"
)

func TestMain(m *testing.M) { os.Exit(testdb.Main(m)) }

func testServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.UseSecretKey(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s, st
}

func call(t *testing.T, h http.Handler, method, path, tok, body string, hdr ...string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func TestAPI(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	h := s.Handler()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.SavePackage(ctx, &store.Package{Slug: "basic", Name: "Basic", MaxDomains: 1, MaxMailboxes: 5, MaxAliases: 5, StorageMB: 1000, MailboxMB: 100, MaxMailboxMB: 500, SendPerHour: 10, SendPerDay: 50, CustomerPerHour: 20, RcptPerMsg: 10}))
	read, _, err := st.CreateAPIToken(ctx, "reader", []string{store.ScopeCustomersRead}, nil, 0, "admin")
	must(err)
	full, _, err := st.CreateAPIToken(ctx, "portal", store.Scopes, nil, 0, "admin")
	must(err)
	limited, _, err := st.CreateAPIToken(ctx, "limited", store.Scopes, []string{"203.0.113.0/24"}, 0, "admin")
	must(err)

	if c, _ := call(t, h, "GET", "/api/v1/customers", "", ""); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c, _ := call(t, h, "GET", "/api/v1/customers", "ezt_wrong", ""); c != 401 {
		t.Fatalf("wrong token: %d", c)
	}
	if c, _ := call(t, h, "GET", "/api/v1/customers", limited, ""); c != 403 {
		t.Fatalf("token from a foreign address: %d", c)
	}
	body := `{"id":"0b8a5b9e-4f1e-4c55-9a3b-2a1f1d6f7e10","external_id":"C-77","username":"acme","name":"Acme","email":"it@acme.test","package":"basic"}`
	if c, _ := call(t, h, "POST", "/api/v1/customers", read, body); c != 403 {
		t.Fatalf("read token created a customer: %d", c)
	}
	c, m := call(t, h, "POST", "/api/v1/customers", full, body, "Idempotency-Key", "k1")
	if c != 201 || m["id"] != "0b8a5b9e-4f1e-4c55-9a3b-2a1f1d6f7e10" || m["package"] != "basic" || m["username"] != "acme" {
		t.Fatalf("create: %d %v", c, m)
	}
	// the same key replays the answer instead of failing on the duplicate
	if c, m := call(t, h, "POST", "/api/v1/customers", full, body, "Idempotency-Key", "k1"); c != 201 || m["id"] == nil {
		t.Fatalf("replay: %d %v", c, m)
	}
	if c, m := call(t, h, "POST", "/api/v1/customers", full, body); c != 409 || m["error"] == nil {
		t.Fatalf("duplicate: %d %v", c, m)
	}
	if c, m := call(t, h, "GET", "/api/v1/customers/ext:C-77", read, ""); c != 200 || m["name"] != "Acme" {
		t.Fatalf("by external id: %d %v", c, m)
	}
	if c, _ := call(t, h, "POST", "/api/v1/customers", full, `{"name":"X","package":"basic","admin":true}`); c != 400 {
		t.Fatalf("unknown field accepted: %d", c)
	}
	if c, m := call(t, h, "POST", "/api/v1/customers/ext:C-77/suspend", full, `{"reason":"billing"}`); c != 200 || m["status"] != "suspended" {
		t.Fatalf("suspend: %d %v", c, m)
	}
	if c, m := call(t, h, "POST", "/api/v1/customers/ext:C-77/sso", full, ""); c != 409 || m["error"].(map[string]any)["code"] != "customer_inactive" {
		t.Fatalf("sso while suspended: %d %v", c, m)
	}
	call(t, h, "POST", "/api/v1/customers/ext:C-77/unsuspend", full, "")
	if c, m := call(t, h, "POST", "/api/v1/customers/ext:C-77/sso", full, ""); c != 409 || m["error"].(map[string]any)["code"] != "no_login" {
		t.Fatalf("sso without login: %d %v", c, m)
	}
	_, err = st.CreateUser(ctx, store.NewUser{Username: "acme-owner", Password: "Test-password-123", CustomerID: "0b8a5b9e-4f1e-4c55-9a3b-2a1f1d6f7e10"})
	must(err)
	c, m = call(t, h, "POST", "/api/v1/customers/ext:C-77/sso", full, "")
	if c != 200 {
		t.Fatalf("sso: %d %v", c, m)
	}
	u := m["url"].(string)
	path := u[strings.Index(u, "/sso/"):]
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/" || !strings.Contains(w.Header().Get("Set-Cookie"), "ezsession=") {
		t.Fatalf("sso link: %d %v", w.Code, w.Header())
	}
	// a link works once
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "127.0.0.1:2"
	h.ServeHTTP(w, r)
	if w.Header().Get("Location") != "/login" {
		t.Fatal("sso link used twice")
	}
	if c, m := call(t, h, "PUT", "/api/v1/customers/ext:C-77/package", full, `{"package":"nope"}`); c != 400 {
		t.Fatalf("unknown package: %d %v", c, m)
	}
	if c, m := call(t, h, "GET", "/api/v1/customers/ext:C-77/usage", full, ""); c != 200 || m["mailboxes"] == nil {
		t.Fatalf("usage: %d %v", c, m)
	}
}
