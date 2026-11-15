package web

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

// EmailZit signs a domain only while its DKIM record is in the DNS: an
// unpublished key would make every signature fail at the receiver.
func TestDKIMOnlyWhenPublished(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	mail := &countingMail{}
	s.Mail = mail
	p := &store.Package{Slug: "dk", Name: "DK", MaxDomains: 2, MaxMailboxes: 1, MaxAliases: 1, StorageMB: 0, MailboxMB: 10,
		MaxMailboxMB: 10, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "DK C", PackageID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	d, err := st.CreateDomain(ctx, store.Staff, c.ID, "dkim.test", true)
	if err != nil {
		t.Fatal(err)
	}
	k, err := st.EnsureDKIM(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	// a fresh domain is not signed: the record is not published yet
	s.installDKIM(ctx, d.ID)
	if mail.installed != 0 {
		t.Fatalf("an unpublished key was installed (%d)", mail.installed)
	}

	// the DNS says nothing at all: nothing changes
	s.PublicTXT = func(context.Context, string, string) ([]string, error) { return nil, errors.New("server failure") }
	s.CheckDNS(ctx)
	if mail.installed != 0 || mail.off != 0 {
		t.Fatalf("a resolver failure changed the signing (%d, %d)", mail.installed, mail.off)
	}

	// the record is there: sign from now on
	s.PublicTXT = func(_ context.Context, _, name string) ([]string, error) {
		if name != k.RecordName() {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		return []string{k.Record()}, nil
	}
	s.CheckDNS(ctx)
	if mail.installed != 1 {
		t.Fatalf("the published key was not installed (%d)", mail.installed)
	}
	if got, err := st.DomainByID(ctx, store.Staff, d.ID); err != nil || !got.DKIMPublished {
		t.Fatalf("the domain is %+v (%v)", got, err)
	}
	// nothing changed since: no second call
	s.CheckDNS(ctx)
	if mail.installed != 1 {
		t.Fatalf("the key was installed again (%d)", mail.installed)
	}

	// the record disappears from the DNS: stop signing
	s.PublicTXT = func(context.Context, string, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	s.CheckDNS(ctx)
	if mail.off != 1 {
		t.Fatalf("the signing was not switched off (%d)", mail.off)
	}
	if got, err := st.DomainByID(ctx, store.Staff, d.ID); err != nil || got.DKIMPublished {
		t.Fatalf("the domain still counts as published: %+v (%v)", got, err)
	}
}

// countingMail counts what the panel asks the root helper to do.
type countingMail struct {
	stubMail
	installed, off int
}

func (m *countingMail) DKIM(context.Context, *store.DKIMKey) error {
	m.installed++
	return nil
}

func (m *countingMail) DKIMOff(context.Context, string) error {
	m.off++
	return nil
}

// A name server that answers the test question and then refuses the
// record must not leave the check undecided for ever: the system resolver
// is asked next (found on e1, where one name server of a test domain
// answered "server misbehaving" over IPv6).
func TestDKIMLookupFallsBackToTheSystemResolver(t *testing.T) {
	old := checkResolver
	t.Cleanup(func() { checkResolver = old })
	checkResolver = func(context.Context, string) *net.Resolver {
		return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// a server that is there but says nothing useful
			return net.Dial(network, "127.0.0.1:1")
		}}
	}
	// the system resolver answers (example.com has the documented empty
	// DKIM record under every selector), so the check can decide
	txt, err := publicTXT(context.Background(), "example.com", "ez-no-such-selector._domainkey.example.com")
	if err != nil && !notFound(err) {
		t.Fatalf("the fallback did not decide: %v (records %v)", err, txt)
	}
}

// A domain verifies itself as soon as its record is in the PUBLIC DNS, and
// the records of a domain no HostZit holds yet are offered again later: a
// zone may be created after the domain, and a write that was refused once
// can work the next time (HostZit's joint test J6 found the second case).
func TestTheDomainVerifiesItselfAndTheRecordsAreOfferedAgain(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	s.Mail = &stubMail{}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.SetSetting(ctx, settingMail, MailSettings{Hostname: "mail.example.net", RequireVerification: true, MaxMessageMB: 25}))
	var mu sync.Mutex
	puts := 0
	hz := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		puts++
		if puts == 1 { // the zone is not there yet
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"zone":"late.test"}`)
	}))
	defer hz.Close()
	must(st.SaveHostZitLink(ctx, &store.HostZitLink{URL: hz.URL, Token: st.SealSecret("hostzit.token", "hzt_test"),
		Insecure: true, ScopeAll: true}))
	p := &store.Package{Slug: "vp", Name: "VP", MaxDomains: 2, MaxMailboxes: 1, MaxAliases: 1, StorageMB: 0, MailboxMB: 10,
		MaxMailboxMB: 10, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	must(st.SavePackage(ctx, p))
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "VC", PackageID: p.ID})
	must(err)
	d, err := st.CreateDomain(ctx, store.Staff, c.ID, "late.test", false)
	must(err)

	// the first write is refused, so nothing of the domain is managed
	s.publishDNS(ctx, d.ID, false, nil)
	d, err = st.DomainByID(ctx, store.Staff, d.ID)
	must(err)
	if d.DNSManaged || d.Verified {
		t.Fatalf("the domain counts as managed after a refused write: %+v", d)
	}
	// the DNS says nothing yet either: the domain stays unverified
	s.PublicTXT = func(context.Context, string, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	s.CheckDNS(ctx)
	d, err = st.DomainByID(ctx, store.Staff, d.ID)
	must(err)
	if d.Verified {
		t.Fatal("a domain without its record in the DNS was verified")
	}
	// the zone is there now and the record with it
	s.PublicTXT = func(_ context.Context, _, name string) ([]string, error) {
		if name == d.VerifyName() {
			return []string{d.VerifyValue()}, nil
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	s.publishUnmanagedDNS(ctx)
	d, err = st.DomainByID(ctx, store.Staff, d.ID)
	must(err)
	if !d.DNSManaged {
		t.Fatalf("the records were not offered again: %+v", d)
	}
	if !d.Verified {
		t.Fatalf("the domain was not verified from the public DNS: %+v", d)
	}
}
