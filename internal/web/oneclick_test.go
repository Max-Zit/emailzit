package web

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

// One click from a linked HostZit (or the billing system) into the customer
// panel, like a cPanel session from WHM or WHMCS: the first click makes the
// customer's login, the session is not sent to the first password change,
// and the customer may choose a password without the current one while they
// never chose one. A login staff switched off stays off.
func TestOneClickSignIn(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	h := s.Handler()
	if err := st.SavePackage(ctx, &store.Package{Slug: "basic", Name: "Basic", MaxDomains: 1, MaxMailboxes: 5, MaxAliases: 5, StorageMB: 1000, MailboxMB: 100, MaxMailboxMB: 500, SendPerHour: 10, SendPerDay: 50, CustomerPerHour: 20, RcptPerMsg: 10}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := st.CreateAPIToken(ctx, "HostZit (paired)", store.Scopes, nil, 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	const id1 = "5d26365a-3214-4a9a-8c66-c7b8acba3f13"
	const id2 = "6e37476b-4325-4b0b-9d77-d8c9bdcb4024"
	if c, m := call(t, h, "POST", "/api/v1/customers", tok, `{"id":"`+id1+`","username":"oneclick","name":"One Click","package":"basic"}`); c != 201 {
		t.Fatalf("customer: %d %v", c, m)
	}
	if c, m := call(t, h, "POST", "/api/v1/customers", tok, `{"id":"`+id2+`","name":"No Name","package":"basic"}`); c != 201 {
		t.Fatalf("customer without a username: %d %v", c, m)
	}
	sso := func(id string) (int, string) {
		t.Helper()
		c, m := call(t, h, "POST", "/api/v1/customers/"+id+"/sso", tok, "")
		if c != 200 {
			return c, ""
		}
		u := m["url"].(string)
		return c, u[strings.Index(u, "/sso/"):]
	}

	// the first click makes the login: the shared username, or c-<id>
	c, link := sso(id1)
	if c != 200 {
		t.Fatalf("first click: %d", c)
	}
	logins, _ := st.CustomerUsers(ctx, id1)
	if len(logins) != 1 || logins[0].Username != "oneclick" || !logins[0].MustChangePassword {
		t.Fatalf("login made for the click: %+v", logins)
	}
	if c, _ := sso(id2); c != 200 {
		t.Fatalf("first click without a username: %d", c)
	}
	if l2, _ := st.CustomerUsers(ctx, id2); len(l2) != 1 || l2[0].Username != "c-6e37476b4325" {
		t.Fatalf("login of a customer without a username: %+v", l2)
	}
	// a second click uses the same login
	if c, _ := sso(id1); c != 200 {
		t.Fatalf("second click: %d", c)
	}
	if l, _ := st.CustomerUsers(ctx, id1); len(l) != 1 {
		t.Fatalf("second click made another login: %d", len(l))
	}

	// the session from the link goes straight into the panel
	srv := httptest.NewServer(h)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) (int, string, string) {
		t.Helper()
		resp, err := cl.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Location"), string(b)
	}
	if code, loc, _ := get(link); code != http.StatusSeeOther || loc != "/" {
		t.Fatalf("link: %d %s", code, loc)
	}
	if code, loc, _ := get("/"); code != http.StatusOK {
		t.Fatalf("one-click session sent to %d %s", code, loc)
	}
	_, _, page := get("/account")
	if !strings.Contains(page, "You came in with one click") || strings.Contains(page, `name="current"`) {
		t.Fatal("My account asks a one-click customer for a current password")
	}
	// the customer chooses a password without the current one
	const pw = "my own chosen passphrase"
	if loc := post(t, cl, srv.URL, "/account/password", url.Values{"password": {pw}, "password2": {pw}}); loc != "/account" {
		t.Fatalf("choosing a password went to %q", loc)
	}
	u, err := st.CheckPassword(ctx, "oneclick", pw)
	if err != nil || u.MustChangePassword {
		t.Fatalf("chosen password: %v %+v", err, u)
	}
	// from then on the current password is needed, also in a one-click session
	post(t, cl, srv.URL, "/account/password", url.Values{"password": {"another passphrase 1"}, "password2": {"another passphrase 1"}})
	if _, err := st.CheckPassword(ctx, "oneclick", pw); err != nil {
		t.Fatal("password changed without the current one")
	}

	// a login staff switched off stays off: no new login, 409
	if err := st.SetCustomerUserDisabled(ctx, id1, logins[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if c, _ := sso(id1); c != 409 {
		t.Fatalf("switched-off login: %d", c)
	}
	if l, _ := st.CustomerUsers(ctx, id1); len(l) != 1 {
		t.Fatalf("a login was made next to the switched-off one: %d", len(l))
	}
}
