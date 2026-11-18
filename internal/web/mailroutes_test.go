package web

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/mailconf"
	"github.com/max-zit/emailzit/internal/store"
)

// A route is the only answer to a receiver that refuses this server's
// whole address range. It has to reach the mail configuration, it must not
// take the mail of a domain this server hosts off the server, and the
// password of a relay must stay sealed and survive a change that does not
// name it again.
func TestDeliveryRoutes(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	s.DevNo2FA = true
	const pw = "correct horse battery staple"
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "admin", Password: pw, Role: store.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	// a domain of this server, which must not get a route
	p := &store.Package{Slug: "r", Name: "R", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 100, MailboxMB: 10, MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "R C", PackageID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateDomain(ctx, store.Staff, c.ID, "ours.test", true); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if loc := post(t, cl, srv.URL, "/login", url.Values{"username": {"admin"}, "password": {pw}}); loc != "/" {
		t.Fatalf("sign-in went to %q", loc)
	}
	save := func(form url.Values) string {
		return post(t, cl, srv.URL, "/settings/routes", form)
	}
	routes := func() []MailRoute { return s.MailConfig(ctx).Routes }

	t.Run("a relay with a login is saved sealed", func(t *testing.T) {
		if loc := save(url.Values{"domain": {"Hotmail.com "}, "kind": {"relay"}, "host": {"smtp.example.net"},
			"port": {"587"}, "user": {"me"}, "password": {"secret"}, "note": {"S3140"}}); loc != "/settings/routes" {
			t.Fatalf("the form answered %q", loc)
		}
		r := routes()
		if len(r) != 1 || r[0].Domain != "hotmail.com" || r[0].Host != "smtp.example.net" || r[0].Port != 587 || r[0].User != "me" {
			t.Fatalf("saved %+v", r)
		}
		if r[0].Password == "" || strings.Contains(r[0].Password, "secret") {
			t.Fatalf("the password is not sealed: %q", r[0].Password)
		}
		if got, _ := st.OpenSecret(routeSecret, r[0].Password); got != "secret" {
			t.Fatalf("the sealed password reads back as %q", got)
		}
	})

	t.Run("the password stays when the login is not entered again", func(t *testing.T) {
		before := routes()[0].Password
		if loc := save(url.Values{"domain": {"hotmail.com"}, "kind": {"relay"}, "host": {"smtp.example.net"},
			"port": {"2525"}, "user": {"me"}, "note": {"new port"}}); loc != "/settings/routes" {
			t.Fatalf("the form answered %q", loc)
		}
		r := routes()
		if len(r) != 1 || r[0].Port != 2525 {
			t.Fatalf("the route was not changed: %+v", r)
		}
		if r[0].Password != before {
			t.Error("the saved password was lost")
		}
	})

	t.Run("a new user name without a password is refused", func(t *testing.T) {
		before := routes()
		save(url.Values{"domain": {"hotmail.com"}, "kind": {"relay"}, "host": {"smtp.example.net"}, "port": {"587"}, "user": {"other"}})
		if got := routes(); len(got) != 1 || got[0].User != before[0].User {
			t.Fatalf("the route changed although the password was missing: %+v", got)
		}
	})

	t.Run("a domain of this server gets no route", func(t *testing.T) {
		save(url.Values{"domain": {"ours.test"}, "kind": {"direct"}})
		for _, r := range routes() {
			if r.Domain == "ours.test" {
				t.Fatal("the mail of our own domain would leave the server")
			}
		}
	})

	t.Run("a route straight to the domain keeps no relay", func(t *testing.T) {
		save(url.Values{"domain": {"example.org"}, "kind": {"direct"}, "host": {"smtp.example.net"}, "user": {"me"}, "password": {"x"}})
		r, found := s.MailConfig(ctx).route("example.org")
		if !found || !r.Direct() || r.User != "" || r.Password != "" {
			t.Fatalf("saved %+v", r)
		}
	})

	t.Run("what the helper gets carries the open password", func(t *testing.T) {
		m := s.mailWithSecrets(ctx)
		var seen bool
		for _, r := range m.Routes {
			if r.Domain == "hotmail.com" {
				seen = true
				if r.password != "secret" {
					t.Errorf("the helper would sign in with %q", r.password)
				}
			}
		}
		if !seen {
			t.Fatal("the route is missing from the configuration")
		}
		// and the configuration itself writes the route
		files, err := mailconf.Render(mailconf.Settings{Hostname: "mail.example.com", MaxMessageMB: 25, DBName: "emailzit",
			CertFile: "/etc/emailzit/tls/mail.crt", KeyFile: "/etc/emailzit/tls/mail.key",
			Routes: []mailconf.Route{{Domain: "hotmail.com", Host: "smtp.example.net", Port: 2525, User: "me", Password: "secret"}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.Path == mailconf.RouteFile && !strings.Contains(string(f.Content), "hotmail.com ezrelay:[smtp.example.net]:2525") {
				t.Errorf("the routes file says:\n%s", f.Content)
			}
		}
	})

	t.Run("removing a route sends the mail the usual way again", func(t *testing.T) {
		if loc := post(t, cl, srv.URL, "/settings/routes/delete", url.Values{"domain": {"hotmail.com"}}); loc != "/settings/routes" {
			t.Fatalf("the form answered %q", loc)
		}
		if _, found := s.MailConfig(ctx).route("hotmail.com"); found {
			t.Fatal("the route is still there")
		}
	})
}
