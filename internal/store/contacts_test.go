package store

import (
	"context"
	"testing"
)

func TestContacts(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	must(t, f.st.SaveContact(ctx, f.ana.ID, "Marko", "Marko@Example.com", false))
	must(t, f.st.SaveContact(ctx, f.ana.ID, "Someone else", "marko@example.com", true)) // auto keeps the name
	must(t, f.st.SaveContact(ctx, f.ana.ID, "", "new@example.com", true))
	cs, err := f.st.Contacts(ctx, f.ana.ID)
	must(t, err)
	if len(cs) != 2 || cs[1].Name != "Marko" && cs[0].Name != "Marko" {
		t.Fatalf("contacts: %+v", cs)
	}
	if other, _ := f.st.Contacts(ctx, f.berta.ID); len(other) != 0 {
		t.Fatalf("berta sees ana's contacts: %+v", other)
	}
	for _, bad := range []string{"not an address", "a@b.c, d@e.f", "x <y@z.test>"} {
		if err := f.st.SaveContact(ctx, f.ana.ID, "", bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	must(t, f.st.DeleteContact(ctx, f.berta.ID, cs[0].ID)) // not hers: nothing happens
	must(t, f.st.DeleteContact(ctx, f.ana.ID, cs[0].ID))
	if cs, _ = f.st.Contacts(ctx, f.ana.ID); len(cs) != 1 {
		t.Fatalf("after delete: %+v", cs)
	}
	must(t, f.st.SetSignature(ctx, f.ana.ID, "Ana\r\nAcme  \n\n"))
	if sig, _ := f.st.Signature(ctx, f.ana.ID); sig != "Ana\nAcme" {
		t.Fatalf("signature %q", sig)
	}
}
