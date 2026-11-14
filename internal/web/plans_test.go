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

// Staff open a mailbox to help the customer (Stefan, 2026-11-14: "da mogu
// da proveravam kao administrator"): it works without the mailbox's own
// password, it is written to the audit log and shown to the mail user,
// and a customer login can never do it.
func TestStaffOpensMailbox(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	s.DevNo2FA = true // the test signs in with passwords only
	const pw = "correct horse battery staple"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	p := &store.Package{Slug: "op", Name: "OP", MaxDomains: 2, MaxMailboxes: 2, MaxAliases: 2, StorageMB: 1000, MailboxMB: 100,
		MaxMailboxMB: 500, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	must(st.SavePackage(ctx, p))
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "OP C", PackageID: p.ID})
	must(err)
	d, err := st.CreateDomain(ctx, store.Staff, c.ID, "open.test", true)
	must(err)
	m, err := st.CreateMailbox(ctx, store.Staff, store.NewMailbox{DomainID: d.ID, LocalPart: "ana", Password: "a-long-password-1"})
	must(err)
	_, err = st.CreateUser(ctx, store.NewUser{Username: "anna", Password: pw, Role: store.RoleAdmin})
	must(err)
	_, err = st.CreateUser(ctx, store.NewUser{Username: "client", Password: pw, Role: store.RoleCustomer, CustomerID: c.ID})
	must(err)

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

	// a customer login may not open a mailbox at all
	client := login("client")
	post(t, client, srv.URL, "/mailboxes/"+m.ID+"/open", url.Values{})
	if mb, err := st.MailboxByID(ctx, store.Staff, m.ID); err != nil || mb.StaffOpenedAt != nil {
		t.Fatalf("a customer login opened the mailbox: %+v (%v)", mb, err)
	}

	// the administrator opens it and lands in the webmail
	anna := login("anna")
	if loc := post(t, anna, srv.URL, "/mailboxes/"+m.ID+"/open", url.Values{}); loc != "/mail/webmail" {
		t.Fatalf("open went to %q", loc)
	}
	resp, err := anna.Get(srv.URL + "/mail")
	must(err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), m.Address) {
		t.Fatalf("the mail user's page after opening: %d", resp.StatusCode)
	}
	// the mail user sees it on that page, and it is in the audit log
	if !strings.Contains(string(body), "administrator") {
		t.Error("the mail user is not told that staff opened the mailbox")
	}
	mb, err := st.MailboxByID(ctx, store.Staff, m.ID)
	must(err)
	if mb.StaffOpenedAt == nil || mb.StaffOpenedBy != "anna" {
		t.Fatalf("not recorded: %v %q", mb.StaffOpenedAt, mb.StaffOpenedBy)
	}
	entries, err := st.AuditEntries(ctx, store.AuditFilter{Query: "mailbox.open"})
	must(err)
	if len(entries) != 1 || entries[0].Username != "anna" || !strings.Contains(entries[0].Target, m.Address) {
		t.Fatalf("audit entries: %+v", entries)
	}
}

// The billing system sets the mail plans of a customer over the API, and
// what it sent comes back on the customer.
func TestAPIMailboxPackages(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	h := s.Handler()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	small := &store.Package{Slug: "mail-10", Name: "Mail 10", MaxDomains: 2, MaxMailboxes: 1, MaxAliases: 2, StorageMB: 0,
		MailboxMB: 100, MaxMailboxMB: 100, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	big := &store.Package{Slug: "mail-100", Name: "Mail 100", MaxDomains: 2, MaxMailboxes: 1, MaxAliases: 2, StorageMB: 0,
		MailboxMB: 1000, MaxMailboxMB: 1000, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	must(st.SavePackage(ctx, small))
	must(st.SavePackage(ctx, big))
	tok, _, err := st.CreateAPIToken(ctx, "portal", store.Scopes, nil, 0, "admin")
	must(err)

	code, m := call(t, h, "POST", "/api/v1/customers", tok, `{"name":"Acme","package":"mail-10"}`)
	if code != 201 {
		t.Fatalf("create: %d %v", code, m)
	}
	id, _ := m["id"].(string)
	// the customer starts with the mailboxes the base package includes
	if plans, _ := m["mailbox_packages"].([]any); len(plans) != 1 {
		t.Fatalf("plans of a new customer: %v", m["mailbox_packages"])
	}
	// the order: three Mail 10 and two Mail 100
	body := `{"packages":[{"package":"mail-10","mailboxes":3},{"package":"mail-100","mailboxes":2}]}`
	code, m = call(t, h, "PUT", "/api/v1/customers/"+id+"/mailbox-packages", tok, body)
	if code != 200 {
		t.Fatalf("mailbox-packages: %d %v", code, m)
	}
	got := map[string]float64{}
	for _, raw := range m["mailbox_packages"].([]any) {
		p := raw.(map[string]any)
		got[p["package"].(string)] = p["mailboxes"].(float64)
	}
	if got["mail-10"] != 3 || got["mail-100"] != 2 {
		t.Fatalf("plans after the order: %v", got)
	}
	// an unknown package is refused
	if code, _ := call(t, h, "PUT", "/api/v1/customers/"+id+"/mailbox-packages", tok,
		`{"packages":[{"package":"mail-1000","mailboxes":1}]}`); code != 400 {
		t.Fatalf("unknown package: %d", code)
	}
	// and the customer shows the plans
	code, m = call(t, h, "GET", "/api/v1/customers/"+id, tok, "")
	if plans, _ := m["mailbox_packages"].([]any); code != 200 || len(plans) != 2 {
		t.Fatalf("customer: %d %v", code, m["mailbox_packages"])
	}
}
