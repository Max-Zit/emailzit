package web

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// The check asks the name servers of the domain itself. A name that was
// looked up before it existed stays "missing" in the server's own resolver
// for a while, and that must not reach the panel.
func TestCheckRecordsAsksTheDomainsNameServers(t *testing.T) {
	ctx := context.Background()
	s := &Server{}
	asked := ""
	old := checkResolver
	checkResolver = func(_ context.Context, domain string) *net.Resolver {
		asked = domain
		return net.DefaultResolver
	}
	t.Cleanup(func() { checkResolver = old })

	s.checkRecords(ctx, "example.test", []DNSRecord{{Name: "example.test", Type: "MX", Value: "10 mail.example.test."}})
	if asked != "example.test" {
		t.Fatalf("the check asked for %q, want the domain itself", asked)
	}
}

// Every record of the list gets a verdict, also when nothing answers.
func TestCheckRecordsVerdictPerRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := &Server{}
	old := checkResolver
	// a resolver that no one answers: every record must come back missing,
	// never as "ok"
	checkResolver = func(context.Context, string) *net.Resolver {
		return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, "127.0.0.1:1") // nothing listens here
		}}
	}
	t.Cleanup(func() { checkResolver = old })

	list := []DNSRecord{
		{Name: "example.test", Type: "MX", Value: "10 mail.example.test."},
		{Name: "example.test", Type: "TXT", Value: "v=spf1 mx -all"},
		{Name: "autoconfig.example.test", Type: "CNAME", Value: "mail.example.test."},
		{Name: "_imaps._tcp.example.test", Type: "SRV", Value: "0 1 993 mail.example.test."},
	}
	got := s.checkRecords(ctx, "example.test", list)
	if len(got) != len(list) {
		t.Fatalf("%d verdicts for %d records", len(got), len(list))
	}
	for i := range list {
		if got[i] != CheckMissing {
			t.Errorf("record %d: %q, want %q", i, got[i], CheckMissing)
		}
	}
}

// The zone snippet can be pasted at a DNS provider: every record on its own
// line, TXT values quoted and a long one (DKIM) in pieces of 255 bytes.
func TestZoneSnippet(t *testing.T) {
	long := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 400)
	out := zoneSnippet([]DNSRecord{
		{Name: "a.test", Type: "MX", Value: "10 mail.example.test."},
		{Name: "a.test", Type: "TXT", Value: "v=spf1 mx -all"},
		{Name: "ez._domainkey.a.test", Type: "TXT", Value: long},
		{Name: "autoconfig.a.test", Type: "CNAME", Value: "mail.example.test."},
	})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines, want 4:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "a.test. 300 IN MX 10 mail.example.test.") {
		t.Errorf("MX line: %q", lines[0])
	}
	if lines[1] != `a.test. 300 IN TXT "v=spf1 mx -all"` {
		t.Errorf("TXT line: %q", lines[1])
	}
	if !strings.Contains(lines[2], `("v=DKIM1`) || strings.Count(lines[2], `" "`) != 1 {
		t.Errorf("the long TXT is not in two quoted pieces: %q", lines[2])
	}
	for _, p := range strings.Fields(lines[2]) {
		if strings.HasPrefix(p, `"`) && len(strings.Trim(p, `"()`)) > 255 {
			t.Errorf("a piece longer than 255 bytes: %d", len(p))
		}
	}
}
