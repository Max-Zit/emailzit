package store

import (
	"context"
	"testing"
)

func TestQuotaChecks(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	use := func(m *Mailbox, mb int64) {
		_, err := f.st.db.Exec(ctx, `UPDATE mailboxes SET used_bytes=$2 WHERE id=$1`, m.ID, mb<<20)
		must(t, err)
	}
	ids := func() map[string]int {
		qs, err := f.st.QuotaChecks(ctx)
		must(t, err)
		out := map[string]int{}
		for _, q := range qs {
			out[q.Address] = q.Warned
		}
		return out
	}
	use(f.ana, 100)
	if got := ids(); len(got) != 0 {
		t.Fatalf("nothing should be due: %v", got)
	}
	use(f.ana, 850) // 85 % of 1000 MB
	if got := ids(); len(got) != 1 {
		t.Fatalf("ana is due: %v", got)
	}
	must(t, f.st.SetQuotaWarned(ctx, f.ana.ID, 80))
	if got := ids(); len(got) != 0 {
		t.Fatalf("warned at 80 %%, nothing due: %v", got)
	}
	use(f.ana, 960)
	if got := ids(); len(got) != 1 {
		t.Fatalf("95 %% is due: %v", got)
	}
	must(t, f.st.SetQuotaWarned(ctx, f.ana.ID, 95))
	use(f.ana, 500)
	if got := ids(); len(got) != 1 {
		t.Fatalf("below 70 %% resets: %v", got)
	}
}
