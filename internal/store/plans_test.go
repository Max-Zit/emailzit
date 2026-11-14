package store

import (
	"context"
	"errors"
	"testing"
)

// A customer mixes plans (Stefan, 2026-11-14: three Mail 10, two Mail 100,
// one Mail 25): every mailbox has the size and the sending limits of its
// own plan, nothing can be made beyond what the customer has, and a plan
// in use cannot be taken away.
func TestMailboxPlans(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	// the base package has little storage in the fixture; the plans here
	// are about the mailboxes, so give the customer room
	f.pkg.StorageMB = 50000
	must(t, f.st.SavePackage(ctx, f.pkg))
	big := &Package{Slug: "big", Name: "Big", MaxDomains: 2, MaxMailboxes: 1, MaxAliases: 3, StorageMB: 0, MailboxMB: 5000,
		MaxMailboxMB: 6000, SendPerHour: 100, SendPerDay: 500, CustomerPerHour: 200, RcptPerMsg: 10}
	must(t, f.st.SavePackage(ctx, big))

	// the base package gave three mailboxes of itself; Ana uses one
	plans, err := f.st.CustomerPackages(ctx, Staff, f.a.ID)
	must(t, err)
	if len(plans) != 1 || plans[0].Mailboxes != 3 || plans[0].Used != 1 || plans[0].Free() != 2 {
		t.Fatalf("plans of a new customer: %+v", plans[0])
	}

	// a mailbox of a plan the customer does not have is refused
	_, err = f.st.CreateMailbox(ctx, Staff, NewMailbox{DomainID: f.da.ID, LocalPart: "nobody", Password: pw, PackageID: big.ID})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("mailbox on a plan the customer has none of: %v", err)
	}

	// one Big mailbox: it gets Big's size and Big's sending limits
	must(t, f.st.SetCustomerPackageCount(ctx, f.a.ID, big.ID, 1))
	m, err := f.st.CreateMailbox(ctx, Staff, NewMailbox{DomainID: f.da.ID, LocalPart: "boss", Password: pw, PackageID: big.ID})
	must(t, err)
	if m.PackageID != big.ID || m.QuotaMB != big.MailboxMB || m.PackageName != big.Name {
		t.Fatalf("mailbox of the Big plan: package %d (%s), quota %d", m.PackageID, m.PackageName, m.QuotaMB)
	}
	l, err := f.st.SendLimitsFor(ctx, m.Address)
	must(t, err)
	if l.PerHour != big.SendPerHour || l.PerDay != big.SendPerDay || l.CustomerPerHour != f.pkg.CustomerPerHour {
		t.Fatalf("limits of a Big mailbox: %+v", l)
	}
	// Ana stays on the base plan with the base plan's limits
	if la, err := f.st.SendLimitsFor(ctx, f.ana.Address); err != nil || la.PerHour != f.pkg.SendPerHour {
		t.Fatalf("limits of a mailbox of the base plan: %+v (%v)", la, err)
	}

	// the second Big mailbox is refused, a third of the base plan is not
	_, err = f.st.CreateMailbox(ctx, Staff, NewMailbox{DomainID: f.da.ID, LocalPart: "boss2", Password: pw, PackageID: big.ID})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("second mailbox of a plan with one: %v", err)
	}
	if _, err := f.st.CreateMailbox(ctx, Staff, NewMailbox{DomainID: f.da.ID, LocalPart: "clerk", Password: pw}); err != nil {
		t.Fatalf("mailbox of the base plan: %v", err)
	}
	// the plan decides the largest size
	if _, err := f.st.CreateMailbox(ctx, Staff, NewMailbox{DomainID: f.da.ID, LocalPart: "huge", Password: pw, QuotaMB: 5000}); err == nil {
		t.Fatal("a mailbox of the base plan may not have the size of the Big plan")
	}

	// a plan with mailboxes cannot be lowered below them, and the package
	// cannot be deleted
	if err := f.st.SetCustomerPackageCount(ctx, f.a.ID, big.ID, 0); err == nil {
		t.Fatal("a plan with a mailbox was removed")
	}
	if err := f.st.DeletePackage(ctx, big.ID); err == nil {
		t.Fatal("a package with mailboxes was deleted")
	}

	// moving a mailbox back to the base plan gives it the base plan's size
	must(t, f.st.UpdateMailbox(ctx, Staff, m.ID, MailboxUpdate{DisplayName: "Boss", QuotaMB: m.QuotaMB, PackageID: f.pkg.ID}))
	moved, err := f.st.MailboxByID(ctx, Staff, m.ID)
	must(t, err)
	if moved.PackageID != f.pkg.ID || moved.QuotaMB != f.pkg.MailboxMB {
		t.Fatalf("after the move: package %d, quota %d", moved.PackageID, moved.QuotaMB)
	}
	// …and the Big plan is free again, so it can be taken away
	must(t, f.st.SetCustomerPackageCount(ctx, f.a.ID, big.ID, 0))
	plans, err = f.st.CustomerPackages(ctx, Staff, f.a.ID)
	must(t, err)
	if len(plans) != 1 || plans[0].Package.ID != f.pkg.ID {
		t.Fatalf("plans after removing Big: %+v", plans)
	}

	// a customer login only ever sees its own plans
	own, err := f.st.CustomerPackages(ctx, Scope{CustomerID: f.b.ID}, f.a.ID)
	must(t, err)
	if len(own) != 1 || own[0].Used != 1 {
		t.Fatalf("a customer asked for another customer's plans: %+v", own)
	}
}

// ReplaceCustomerPackages is what the billing system sends after an order.
func TestReplaceCustomerPackages(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	big := &Package{Slug: "big", Name: "Big", MaxDomains: 1, MaxMailboxes: 0, MaxAliases: 1, StorageMB: 0, MailboxMB: 2000,
		MaxMailboxMB: 2000, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	must(t, f.st.SavePackage(ctx, big))
	must(t, f.st.ReplaceCustomerPackages(ctx, f.a.ID, map[int64]int{f.pkg.ID: 2, big.ID: 3}))
	plans, err := f.st.CustomerPackages(ctx, Staff, f.a.ID)
	must(t, err)
	if len(plans) != 2 {
		t.Fatalf("plans: %+v", plans)
	}
	have := map[int64]int{}
	for _, p := range plans {
		have[p.Package.ID] = p.Mailboxes
	}
	if have[f.pkg.ID] != 2 || have[big.ID] != 3 {
		t.Fatalf("counts: %v", have)
	}
	// a plan that is left out goes, as long as no mailbox uses it
	must(t, f.st.ReplaceCustomerPackages(ctx, f.a.ID, map[int64]int{f.pkg.ID: 1}))
	plans, err = f.st.CustomerPackages(ctx, Staff, f.a.ID)
	must(t, err)
	if len(plans) != 1 || plans[0].Mailboxes != 1 {
		t.Fatalf("plans after the second order: %+v", plans)
	}
	// Ana is on the base plan, so dropping it is refused and nothing of
	// the order is written
	if err := f.st.ReplaceCustomerPackages(ctx, f.a.ID, map[int64]int{big.ID: 5}); err == nil {
		t.Fatal("the plan of an existing mailbox was dropped")
	}
	plans, err = f.st.CustomerPackages(ctx, Staff, f.a.ID)
	must(t, err)
	if len(plans) != 1 || plans[0].Package.ID != f.pkg.ID {
		t.Fatalf("plans after the refused order: %+v", plans)
	}
}
