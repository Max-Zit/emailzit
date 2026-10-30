package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/testdb"
)

func TestMain(m *testing.M) { os.Exit(testdb.Main(m)) }

func open(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.UseSecretKey(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	return st
}

type fixture struct {
	st         *Store
	pkg        *Package
	a, b       *Customer
	da, db     *Domain
	ana, berta *Mailbox
}

const pw = "Test-password-123"

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{st: open(t)}
	f.pkg = &Package{Slug: "small", Name: "Small", MaxDomains: 2, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 3000, MailboxMB: 1000,
		MaxMailboxMB: 2000, SendPerHour: 10, SendPerDay: 50, CustomerPerHour: 20, RcptPerMsg: 10}
	must(t, f.st.SavePackage(ctx, f.pkg))
	var err error
	f.a, err = f.st.CreateCustomer(ctx, NewCustomer{Name: "A", PackageID: f.pkg.ID})
	must(t, err)
	f.b, err = f.st.CreateCustomer(ctx, NewCustomer{Name: "B", PackageID: f.pkg.ID, ExternalID: "ext-b"})
	must(t, err)
	f.da, err = f.st.CreateDomain(ctx, Scope{CustomerID: f.a.ID}, "", "a.test", true)
	must(t, err)
	f.db, err = f.st.CreateDomain(ctx, Staff, f.b.ID, "B.test", true)
	must(t, err)
	f.ana, err = f.st.CreateMailbox(ctx, Scope{CustomerID: f.a.ID}, NewMailbox{DomainID: f.da.ID, LocalPart: "Ana", Password: pw})
	must(t, err)
	f.berta, err = f.st.CreateMailbox(ctx, Staff, NewMailbox{DomainID: f.db.ID, LocalPart: "berta", Password: pw})
	must(t, err)
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// A customer can never see or change another customer's objects, whatever
// IDs it sends.
func TestCustomerIsolation(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	sa := Scope{CustomerID: f.a.ID}
	if f.ana.Address != "ana@a.test" || f.db.Name != "b.test" {
		t.Fatalf("names not normalised: %s %s", f.ana.Address, f.db.Name)
	}
	if _, err := f.st.DomainByID(ctx, sa, f.db.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("domain of B visible to A")
	}
	if _, err := f.st.MailboxByID(ctx, sa, f.berta.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("mailbox of B visible to A")
	}
	// a customer scope ignores the customer ID it passes
	d, err := f.st.CreateDomain(ctx, sa, f.b.ID, "sneaky.test", false)
	must(t, err)
	if d.CustomerID != f.a.ID {
		t.Fatal("domain created for another customer")
	}
	if _, err := f.st.CreateMailbox(ctx, sa, NewMailbox{DomainID: f.db.ID, LocalPart: "x", Password: pw}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mailbox in B's domain: %v", err)
	}
	if _, err := f.st.CreateAlias(ctx, sa, f.db.ID, "x", []string{"ana@a.test"}, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alias in B's domain: %v", err)
	}
	// routing mail into another customer's mailbox by alias is refused
	if _, err := f.st.CreateAlias(ctx, sa, f.da.ID, "x", []string{"berta@b.test"}, false); err == nil || !strings.Contains(err.Error(), "another customer") {
		t.Fatalf("alias to B's mailbox: %v", err)
	}
	if err := f.st.SetCatchAll(ctx, sa, f.da.ID, "berta@b.test"); err == nil {
		t.Fatal("catch-all to B's mailbox")
	}
	for name, err := range map[string]error{
		"update":   f.st.UpdateMailbox(ctx, sa, f.berta.ID, MailboxUpdate{QuotaMB: 10}),
		"password": f.st.SetMailboxPassword(ctx, sa, f.berta.ID, pw+"x"),
		"2fa":      f.st.ResetMailboxTwoFactor(ctx, sa, f.berta.ID),
		"delete":   f.st.DeleteMailbox(ctx, sa, f.berta.ID),
		"domain":   f.st.DeleteDomain(ctx, sa, f.db.ID),
		"verify":   f.st.SetDomainVerified(ctx, sa, f.db.ID, false),
		"catchall": f.st.SetCatchAll(ctx, sa, f.db.ID, ""),
		"bad id":   f.st.DeleteMailbox(ctx, sa, "x'; DROP TABLE mailboxes; --"),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on B's object: %v", name, err)
		}
	}
	list, err := f.st.Mailboxes(ctx, sa, MailboxFilter{CustomerID: f.b.ID})
	must(t, err)
	for _, m := range list {
		if m.CustomerID != f.a.ID {
			t.Fatal("B's mailbox in A's list")
		}
	}
	doms, err := f.st.Domains(ctx, sa, f.b.ID)
	must(t, err)
	for _, d := range doms {
		if d.CustomerID != f.a.ID {
			t.Fatal("B's domain in A's list")
		}
	}
	// B's data is untouched
	if _, err := f.st.MailboxByID(ctx, Staff, f.berta.ID); err != nil {
		t.Fatal(err)
	}
}

func TestPackageLimits(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	sa := Scope{CustomerID: f.a.ID}
	_, err := f.st.CreateDomain(ctx, sa, "", "second.test", true)
	must(t, err)
	if _, err := f.st.CreateDomain(ctx, sa, "", "third.test", true); !errors.Is(err, ErrLimit) {
		t.Fatalf("third domain: %v", err)
	}
	if _, err := f.st.CreateMailbox(ctx, sa, NewMailbox{DomainID: f.da.ID, LocalPart: "big", Password: pw, QuotaMB: 2001}); err == nil {
		t.Fatal("mailbox above the largest size")
	}
	// storage: 3000 MB, ana has 1000
	_, err = f.st.CreateMailbox(ctx, sa, NewMailbox{DomainID: f.da.ID, LocalPart: "b", Password: pw, QuotaMB: 1500})
	must(t, err)
	if _, err := f.st.CreateMailbox(ctx, sa, NewMailbox{DomainID: f.da.ID, LocalPart: "c", Password: pw, QuotaMB: 600}); !errors.Is(err, ErrLimit) {
		t.Fatalf("storage over the package: %v", err)
	}
	_, err = f.st.CreateMailbox(ctx, sa, NewMailbox{DomainID: f.da.ID, LocalPart: "c", Password: pw, QuotaMB: 500})
	must(t, err)
	if _, err := f.st.CreateMailbox(ctx, sa, NewMailbox{DomainID: f.da.ID, LocalPart: "d", Password: pw, QuotaMB: 1}); !errors.Is(err, ErrLimit) {
		t.Fatalf("fourth mailbox: %v", err)
	}
	// a customer cannot lift its own sending limits
	h := 1000
	must(t, f.st.UpdateMailbox(ctx, sa, f.ana.ID, MailboxUpdate{QuotaMB: 1000, SendPerHour: &h}))
	m, _ := f.st.MailboxByID(ctx, Staff, f.ana.ID)
	if m.SendPerHour != nil {
		t.Fatal("customer changed the sending limit")
	}
	// suspended customers cannot add anything
	must(t, f.st.SetCustomerStatus(ctx, f.a.ID, CustomerSuspended, "unpaid"))
	if _, err := f.st.CreateAlias(ctx, sa, f.da.ID, "info", []string{"ana@a.test"}, false); !errors.Is(err, ErrInactive) {
		t.Fatalf("alias while suspended: %v", err)
	}
}

// The views Postfix and Dovecot read follow the state of customers,
// domains and mailboxes.
func TestMailViews(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	db := f.st.Pool()
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		must(t, db.QueryRow(ctx, q, args...).Scan(&n))
		return n
	}
	pw, _, err := f.st.CreateAppPassword(ctx, f.ana.ID, "Thunderbird")
	must(t, err)
	login := func() int {
		return count(`SELECT count(*) FROM mda_logins WHERE username=$1 AND hash=encode(sha256(convert_to($2,'UTF8')),'hex')`, "ana@a.test", pw)
	}
	if login() != 1 {
		t.Fatal("app password not accepted by the Dovecot view")
	}
	if count(`SELECT count(*) FROM mda_logins WHERE username='ana@a.test' AND hash=encode(sha256(convert_to('wrong','UTF8')),'hex')`) != 0 {
		t.Fatal("wrong password accepted")
	}
	if count(`SELECT count(*) FROM mta_sender_logins WHERE sender='ana@a.test' AND login='ana@a.test'`) != 1 {
		t.Fatal("ana may not send as herself")
	}
	_, err = f.st.CreateAlias(ctx, Scope{CustomerID: f.a.ID}, f.da.ID, "info", []string{"ana@a.test", "x@example.org"}, true)
	must(t, err)
	if count(`SELECT count(*) FROM mta_sender_logins WHERE sender='info@a.test' AND login='ana@a.test'`) != 1 {
		t.Fatal("send-as alias missing")
	}
	if count(`SELECT count(*) FROM mta_sender_logins WHERE sender='berta@b.test' AND login='ana@a.test'`) != 0 {
		t.Fatal("ana may send as berta")
	}
	must(t, f.st.SetCatchAll(ctx, Staff, f.da.ID, "ana@a.test"))
	if count(`SELECT count(*) FROM mta_aliases WHERE address='@a.test'`) != 1 || count(`SELECT count(*) FROM mta_aliases WHERE address='ana@a.test'`) != 1 {
		t.Fatal("catch-all or identity alias missing")
	}
	var uid int
	var home string
	must(t, db.QueryRow(ctx, `SELECT uid, home FROM mda_users WHERE username='ana@a.test'`).Scan(&uid, &home))
	if uid != f.a.UID() || home != "/var/vmail/"+f.a.ID+"/a.test/ana" {
		t.Fatalf("uid %d home %s", uid, home)
	}
	var uidB int
	must(t, db.QueryRow(ctx, `SELECT uid FROM mda_users WHERE username='berta@b.test'`).Scan(&uidB))
	if uidB == uid {
		t.Fatal("two customers share a UID")
	}
	// suspension: still receives, cannot sign in or send
	must(t, f.st.SetCustomerStatus(ctx, f.a.ID, CustomerSuspended, ""))
	if login() != 0 || count(`SELECT count(*) FROM mta_sender_logins WHERE login='ana@a.test'`) != 0 {
		t.Fatal("suspended customer can sign in or send")
	}
	if count(`SELECT count(*) FROM mta_mailboxes WHERE address='ana@a.test'`) != 1 {
		t.Fatal("suspended customer no longer receives")
	}
	// termination: mail refused
	must(t, f.st.SetCustomerStatus(ctx, f.a.ID, CustomerTerminated, ""))
	if count(`SELECT count(*) FROM mta_mailboxes WHERE address='ana@a.test'`) != 0 || count(`SELECT count(*) FROM mta_domains WHERE name='a.test'`) != 0 {
		t.Fatal("terminated customer still receives")
	}
	// unverified domains receive nothing
	d, err := f.st.CreateDomain(ctx, Scope{CustomerID: f.b.ID}, "", "new.test", false)
	must(t, err)
	if count(`SELECT count(*) FROM mta_domains WHERE name=$1`, d.Name) != 0 {
		t.Fatal("unverified domain receives mail")
	}
}

func TestMailUserSignIn(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	if _, err := f.st.CheckMailboxPassword(ctx, "ANA@a.test", pw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CheckMailboxPassword(ctx, "ana@a.test", "wrong-password-1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("wrong password accepted")
	}
	must(t, f.st.SetCustomerStatus(ctx, f.a.ID, CustomerSuspended, ""))
	if _, err := f.st.CheckMailboxPassword(ctx, "ana@a.test", pw); !errors.Is(err, ErrNotFound) {
		t.Fatal("mail user of a suspended customer signed in")
	}
}

func TestAppPasswordFormat(t *testing.T) {
	p := NewAppPassword()
	if len(p) != 23 || strings.Count(p, "-") != 3 || strings.ContainsAny(p, "01lo") {
		t.Fatal(p)
	}
	if NewAppPassword() == p {
		t.Fatal("not random")
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{"Example.COM.": "example.com", "bücher.de": "xn--bcher-kva.de", "a.b.c.test": "a.b.c.test"} {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("%s → %s %v", in, got, err)
		}
	}
	for _, bad := range []string{"localhost", "a..b", "-a.test", "a.123", "a_b.test", "x.test/", "a\n.test"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, bad := range []string{".a", "a.", "a..b", "a b", "a@b", "ä", strings.Repeat("a", 65)} {
		if ValidLocalPart(bad) == nil {
			t.Errorf("local part %q accepted", bad)
		}
	}
	if a, err := ParseAddress("Ana.B+tag@Example.COM"); err != nil || a != "ana.b+tag@example.com" {
		t.Fatal(a, err)
	}
	for _, bad := range []string{"ana", "ana@", "<a@b.test>", "a@b.test, c@d.test", "a\r\n@b.test"} {
		if _, err := ParseAddress(bad); err == nil {
			t.Errorf("address %q accepted", bad)
		}
	}
}
