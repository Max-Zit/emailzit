package web

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

func TestFourEyes(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	s.DevNo2FA = true // the test signs in with passwords only
	const pw = "correct horse battery staple"
	for _, n := range []string{"anna", "boris"} {
		if _, err := st.CreateUser(ctx, store.NewUser{Username: n, Password: pw, Role: store.RoleAdmin}); err != nil {
			t.Fatal(err)
		}
	}
	p := &store.Package{Slug: "fe", Name: "FE", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 100, MailboxMB: 10, MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, _ := st.CreateCustomer(ctx, store.NewCustomer{Name: "FE C", PackageID: p.ID})
	d, _ := st.CreateDomain(ctx, store.Staff, c.ID, "fe.test", true)
	m, err := st.CreateMailbox(ctx, store.Staff, store.NewMailbox{DomainID: d.ID, LocalPart: "x", Password: "a-long-password-1"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	login := func(user string) *http.Client {
		jar, _ := cookiejar.New(nil)
		cl := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		if loc := post(t, cl, srv.URL, "/login", url.Values{"username": {user}, "password": {pw}}); loc != "/" {
			t.Fatalf("login %s went to %q", user, loc)
		}
		return cl
	}
	anna, boris := login("anna"), login("boris")

	if loc := post(t, anna, srv.URL, "/settings/four-eyes", url.Values{"on": {"1"}}); loc != "/settings/security" || !s.fourEyesOn(ctx) {
		t.Fatalf("turning on went to %q", loc)
	}
	// anna's deletion only waits
	if loc := post(t, anna, srv.URL, "/mailboxes/"+m.ID+"/delete", url.Values{"confirm": {"x@fe.test"}}); loc != "/approvals" {
		t.Fatalf("delete went to %q", loc)
	}
	if _, err := st.MailboxByID(ctx, store.Staff, m.ID); err != nil {
		t.Fatal("deleted without approval")
	}
	list, _ := st.Approvals(ctx)
	if len(list) != 1 || list[0].Action != "mailbox.delete" || list[0].Status != "pending" || strings.Contains(list[0].Form, "x@fe.test") {
		t.Fatalf("request %+v", list)
	}
	id := list[0].ID
	path := "/approvals/" + strconv.FormatInt(id, 10)
	// she cannot approve it herself
	post(t, anna, srv.URL, path, url.Values{"decision": {"approve"}})
	if _, err := st.MailboxByID(ctx, store.Staff, m.ID); err != nil {
		t.Fatal("self-approved")
	}
	// boris approves: it runs now
	if loc := post(t, boris, srv.URL, path, url.Values{"decision": {"approve"}}); loc != "/domains/"+d.ID {
		t.Fatalf("approve went to %q", loc)
	}
	if _, err := st.MailboxByID(ctx, store.Staff, m.ID); err == nil {
		t.Fatal("not deleted after approval")
	}
	// only once
	post(t, boris, srv.URL, path, url.Values{"decision": {"approve"}})
	if list, _ = st.Approvals(ctx); list[0].Status != "approved" || list[0].DecidedBy != "boris" {
		t.Fatalf("after approval %+v", list[0])
	}
	// turning it off needs approval too; a rejected request does nothing
	post(t, anna, srv.URL, "/settings/four-eyes", url.Values{"on": {"0"}})
	if !s.fourEyesOn(ctx) {
		t.Fatal("turned off without approval")
	}
	list, _ = st.Approvals(ctx)
	post(t, boris, srv.URL, "/approvals/"+strconv.FormatInt(list[0].ID, 10), url.Values{"decision": {"reject"}})
	if !s.fourEyesOn(ctx) {
		t.Fatal("rejected request ran")
	}
}

// post sends a form like the browser (same origin) and returns Location.
func post(t *testing.T, c *http.Client, base, path string, form url.Values) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Location")
}
