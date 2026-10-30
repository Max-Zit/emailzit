package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/dmarc"
)

func TestDMARCReports(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	rep := &dmarc.Report{Org: "google.com", ID: "r1", Domain: "a.test", Policy: "none", Begin: now.Add(-24 * time.Hour), End: now,
		Records: []dmarc.Record{
			{SourceIP: netip.MustParseAddr("192.0.2.1"), Count: 10, DKIM: true, Disposition: "none"},
			{SourceIP: netip.MustParseAddr("198.51.100.7"), Count: 4, Disposition: "quarantine"},
		}}
	ok, err := f.st.SaveDMARCReport(ctx, "a.test", rep)
	if err != nil || !ok {
		t.Fatalf("save: %v %v", ok, err)
	}
	if ok, _ := f.st.SaveDMARCReport(ctx, "a.test", rep); ok {
		t.Fatal("the same report was stored twice")
	}
	other := *rep
	other.ID, other.Domain = "r2", "b.test"
	if ok, _ := f.st.SaveDMARCReport(ctx, "a.test", &other); ok {
		t.Fatal("a report about another domain was stored")
	}
	sum, err := f.st.DMARCSummary(ctx, f.da.ID, now.Add(-30*24*time.Hour))
	must(t, err)
	if sum.Reports != 1 || sum.Messages != 14 || sum.Passed != 10 || len(sum.Sources) != 2 || sum.Sources[1].Rejected != 4 {
		t.Fatalf("summary: %+v", sum)
	}
	if err := ValidLocalPart(DMARCAddress); err == nil {
		t.Fatal("dmarc-reports may be used as a mailbox")
	}
	var n int
	must(t, f.st.db.QueryRow(ctx, `SELECT count(*) FROM mta_mailboxes WHERE address='dmarc-reports@a.test'`).Scan(&n))
	if n != 1 {
		t.Fatalf("dmarc-reports@a.test in mta_mailboxes: %d", n)
	}
}
