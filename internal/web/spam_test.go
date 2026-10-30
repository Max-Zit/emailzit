package web

import (
	"context"
	"testing"

	"github.com/max-zit/emailzit/internal/sieve"
	"github.com/max-zit/emailzit/internal/store"
)

func TestSpamSettings(t *testing.T) {
	ctx := context.Background()
	_, st := testServer(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	p := &store.Package{Slug: "sp", Name: "SP", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 100, MailboxMB: 10, MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	must(st.SavePackage(ctx, p))
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "Spam C", PackageID: p.ID})
	must(err)
	other, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "Other", PackageID: p.ID})
	must(err)
	d, err := st.CreateDomain(ctx, store.Staff, c.ID, "spam.test", true)
	must(err)
	m, err := st.CreateMailbox(ctx, store.Staff, store.NewMailbox{DomainID: d.ID, LocalPart: "ana", Password: "a-long-password-1"})
	must(err)

	sp, err := st.MailboxSpamSettings(ctx, store.Staff, m.ID)
	must(err)
	if sp.Level != "" || sp.CustomerLevel != sieve.SpamNormal || sp.Effective() != sieve.SpamNormal || len(sp.Allow) != 0 {
		t.Fatalf("defaults %+v", sp)
	}
	must(st.SetCustomerSpamLevel(ctx, c.ID, sieve.SpamStrict))
	allow, _ := sieve.CleanSenders("boss@x.test\npartner.test")
	must(st.SetMailboxSpam(ctx, store.Scope{CustomerID: c.ID}, m.ID, "", allow, nil))
	sp, _ = st.MailboxSpamSettings(ctx, store.Staff, m.ID)
	if sp.Effective() != sieve.SpamStrict || len(sp.Allow) != 2 || sp.Allow[1] != "partner.test" {
		t.Fatalf("after save %+v", sp)
	}
	must(st.SetMailboxSpam(ctx, store.Staff, m.ID, sieve.SpamOff, nil, []string{"bad.test"}))
	if sp, _ = st.MailboxSpamSettings(ctx, store.Staff, m.ID); sp.Effective() != sieve.SpamOff || len(sp.Block) != 1 {
		t.Fatalf("own level %+v", sp)
	}
	// another customer can neither read nor change it
	if _, err := st.MailboxSpamSettings(ctx, store.Scope{CustomerID: other.ID}, m.ID); err == nil {
		t.Fatal("read by another customer")
	}
	if err := st.SetMailboxSpam(ctx, store.Scope{CustomerID: other.ID}, m.ID, "", nil, nil); err == nil {
		t.Fatal("changed by another customer")
	}
	// the database refuses unknown levels
	if err := st.SetCustomerSpamLevel(ctx, c.ID, "max"); err == nil {
		t.Fatal("unknown level stored")
	}
}
