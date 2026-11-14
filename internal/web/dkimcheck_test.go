package web

import (
	"context"
	"errors"
	"net"
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
	s.DKIMTXT = func(context.Context, string, string) ([]string, error) { return nil, errors.New("server failure") }
	s.CheckDKIMPublished(ctx)
	if mail.installed != 0 || mail.off != 0 {
		t.Fatalf("a resolver failure changed the signing (%d, %d)", mail.installed, mail.off)
	}

	// the record is there: sign from now on
	s.DKIMTXT = func(_ context.Context, _, name string) ([]string, error) {
		if name != k.RecordName() {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		return []string{k.Record()}, nil
	}
	s.CheckDKIMPublished(ctx)
	if mail.installed != 1 {
		t.Fatalf("the published key was not installed (%d)", mail.installed)
	}
	if got, err := st.DomainByID(ctx, store.Staff, d.ID); err != nil || !got.DKIMPublished {
		t.Fatalf("the domain is %+v (%v)", got, err)
	}
	// nothing changed since: no second call
	s.CheckDKIMPublished(ctx)
	if mail.installed != 1 {
		t.Fatalf("the key was installed again (%d)", mail.installed)
	}

	// the record disappears from the DNS: stop signing
	s.DKIMTXT = func(context.Context, string, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	s.CheckDKIMPublished(ctx)
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
