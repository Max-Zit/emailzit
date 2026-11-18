package store

import (
	"context"
	"strings"
	"testing"
)

// A shared folder stays inside one customer. That is not a rule of
// politeness: every customer runs as its own system user with a 0700 mail
// directory, so a share across customers could not work even if somebody
// wrote it into the database — and a request that tries it must be
// refused here, not only hidden in the panel.
func TestMailboxShares(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	marko, err := f.st.CreateMailbox(ctx, Staff, NewMailbox{DomainID: f.da.ID, LocalPart: "marko", Password: pw})
	must(t, err)
	scopeA := Scope{CustomerID: f.a.ID}

	t.Run("a folder is opened for another mailbox of the customer", func(t *testing.T) {
		owner, with, err := f.st.AddShare(ctx, scopeA, f.ana.ID, marko.ID, "INBOX", ShareWrite)
		must(t, err)
		if owner.ID != f.ana.ID || with.ID != marko.ID {
			t.Fatalf("got %s and %s", owner.Address, with.Address)
		}
		shared, received, err := f.st.SharesOf(ctx, scopeA, f.ana.ID)
		must(t, err)
		if len(shared) != 1 || shared[0].WithAddress != marko.Address || shared[0].Rights != ShareWrite || len(received) != 0 {
			t.Fatalf("ana shares %+v, receives %+v", shared, received)
		}
		shared, received, err = f.st.SharesOf(ctx, scopeA, marko.ID)
		must(t, err)
		if len(received) != 1 || received[0].OwnerAddress != f.ana.Address || len(shared) != 0 {
			t.Fatalf("marko shares %+v, receives %+v", shared, received)
		}
	})

	t.Run("sharing again only changes the rights", func(t *testing.T) {
		_, _, err := f.st.AddShare(ctx, scopeA, f.ana.ID, marko.ID, "INBOX", ShareRead)
		must(t, err)
		shared, _, err := f.st.SharesOf(ctx, scopeA, f.ana.ID)
		must(t, err)
		if len(shared) != 1 || shared[0].Rights != ShareRead {
			t.Fatalf("got %+v", shared)
		}
	})

	t.Run("another customer's mailbox is refused", func(t *testing.T) {
		if _, _, err := f.st.AddShare(ctx, Staff, f.ana.ID, f.berta.ID, "INBOX", ShareRead); err == nil {
			t.Fatal("a folder was shared across customers")
		}
		// and a customer cannot even name a foreign mailbox
		if _, _, err := f.st.AddShare(ctx, scopeA, f.ana.ID, f.berta.ID, "INBOX", ShareRead); err == nil {
			t.Fatal("a customer shared a folder with a foreign mailbox")
		}
	})

	t.Run("a mailbox is not shared with itself", func(t *testing.T) {
		if _, _, err := f.st.AddShare(ctx, scopeA, f.ana.ID, f.ana.ID, "INBOX", ShareRead); err == nil {
			t.Fatal("a mailbox was shared with itself")
		}
	})

	t.Run("a folder name that would break the rights file is refused", func(t *testing.T) {
		for _, name := range []string{"", " ", `In"box`, "In'box", `In\box`, "-u other@a.test", strings.Repeat("x", 200), "In\nbox"} {
			if _, _, err := f.st.AddShare(ctx, scopeA, f.ana.ID, marko.ID, name, ShareRead); err == nil {
				t.Errorf("%q was accepted as a folder", name)
			}
		}
		if _, _, err := f.st.AddShare(ctx, scopeA, f.ana.ID, marko.ID, "INBOX", "admin"); err == nil {
			t.Error("unknown rights were accepted")
		}
	})

	t.Run("every share is listed for the mail server", func(t *testing.T) {
		all, err := f.st.AllShares(ctx)
		must(t, err)
		if len(all) != 1 || all[0].OwnerAddress != f.ana.Address || all[0].WithAddress != marko.Address {
			t.Fatalf("got %+v", all)
		}
	})

	t.Run("closing a folder removes it", func(t *testing.T) {
		if _, _, err := f.st.RemoveShare(ctx, scopeA, f.ana.ID, marko.ID, "INBOX"); err != nil {
			t.Fatal(err)
		}
		if all, _ := f.st.AllShares(ctx); len(all) != 0 {
			t.Fatalf("the share is still there: %+v", all)
		}
		if _, _, err := f.st.RemoveShare(ctx, scopeA, f.ana.ID, marko.ID, "INBOX"); err == nil {
			t.Error("closing a folder twice was not noticed")
		}
	})

	t.Run("a deleted mailbox takes its shares with it", func(t *testing.T) {
		_, _, err := f.st.AddShare(ctx, scopeA, f.ana.ID, marko.ID, "Projects", ShareWrite)
		must(t, err)
		must(t, f.st.DeleteMailbox(ctx, scopeA, marko.ID))
		all, err := f.st.AllShares(ctx)
		must(t, err)
		if len(all) != 0 {
			t.Fatalf("the share of a deleted mailbox is still there: %+v", all)
		}
	})
}
