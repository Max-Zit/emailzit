package policy

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

type fakeStore struct {
	l       store.SendLimits
	sent    int
	refused int
	blocked bool
}

func (f *fakeStore) SendLimitsFor(ctx context.Context, a string) (*store.SendLimits, error) {
	l := f.l
	l.SentHour, l.SentDay, l.CustomerHour = f.sent, f.sent, f.sent
	l.Blocked = f.blocked
	return &l, nil
}
func (f *fakeStore) LogSent(ctx context.Context, l *store.SendLimits, n int, ip string) error {
	f.sent += n
	return nil
}
func (f *fakeStore) LogRefused(ctx context.Context, id, r string) (int, error) {
	f.refused++
	return f.refused, nil
}
func (f *fakeStore) BlockSending(ctx context.Context, id string) error { f.blocked = true; return nil }

func req(state, inst string, rc int) map[string]string {
	m := map[string]string{"request": "smtpd_access_policy", "protocol_state": state, "sasl_username": "Ana@a.test", "instance": inst}
	if rc > 0 {
		m["recipient_count"] = strings.Repeat("", 0) + string(rune('0'+rc))
	}
	return m
}

func TestLimits(t *testing.T) {
	f := &fakeStore{l: store.SendLimits{MailboxID: "m", PerHour: 5, PerDay: 100, CustomerPerHour: 100, RcptPerMsg: 3}}
	var blocked string
	s := &Service{Store: f, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowUID: -1, Blocked: func(a, r string) { blocked = a }}
	ctx := context.Background()
	// unauthenticated mail (port 25) is not limited here
	if a := s.Decide(ctx, map[string]string{"request": "smtpd_access_policy", "protocol_state": "RCPT"}); a != "DUNNO" {
		t.Fatal(a)
	}
	for i := 0; i < 3; i++ {
		if a := s.Decide(ctx, req("RCPT", "i1", 0)); a != "DUNNO" {
			t.Fatalf("rcpt %d: %s", i, a)
		}
	}
	if a := s.Decide(ctx, req("RCPT", "i1", 0)); !strings.HasPrefix(a, "REJECT 5.5.3") {
		t.Fatalf("4th recipient: %s", a)
	}
	s.Decide(ctx, req("DATA", "i1", 3))
	if f.sent != 3 {
		t.Fatalf("sent %d", f.sent)
	}
	// 3 sent this hour, limit 5: two more, then deferred
	s.Decide(ctx, req("RCPT", "i2", 0))
	s.Decide(ctx, req("RCPT", "i2", 0))
	if a := s.Decide(ctx, req("RCPT", "i2", 0)); !strings.HasPrefix(a, "DEFER_IF_PERMIT 4.7.1") {
		t.Fatalf("over the hour: %s", a)
	}
	// a spam run keeps trying: blocked at the threshold
	for i := 0; i < AbuseThreshold; i++ {
		s.Decide(ctx, req("RCPT", "i3", 0))
	}
	if !f.blocked || blocked != "ana@a.test" {
		t.Fatal("not blocked after the abuse threshold")
	}
	if a := s.Decide(ctx, req("RCPT", "i4", 0)); !strings.HasPrefix(a, "REJECT 5.7.1") {
		t.Fatalf("blocked mailbox: %s", a)
	}
}
