package web

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// stubMail stands in for the root mail helper.
type stubMail struct{ applied []MailSettings }

func (m *stubMail) Apply(_ context.Context, s MailSettings) error {
	m.applied = append(m.applied, s)
	return nil
}
func (m *stubMail) CustomerCreated(context.Context, *store.Customer) error { return nil }
func (m *stubMail) DomainDeleted(context.Context, *store.Domain) error     { return nil }
func (m *stubMail) MailboxDeleted(context.Context, *store.Mailbox) error   { return nil }
func (m *stubMail) DKIM(context.Context, *store.DKIMKey) error             { return nil }
func (m *stubMail) Spam(context.Context, string, string) error             { return nil }
func (m *stubMail) Unban(context.Context, string) error                    { return nil }
func (m *stubMail) Notice(context.Context, string, string, string) error   { return nil }

// After a restore the mail services still carry the configuration of the
// machine they were installed on, so the panel writes the settings of the
// backup at its next start — once, then the mark is gone.
func TestSyncMailAfterRestore(t *testing.T) {
	ctx := context.Background()
	s, _ := testServer(t)
	old := helperStartWait
	helperStartWait = time.Millisecond
	t.Cleanup(func() { helperStartWait = old })
	s.DataDir = t.TempDir()
	m := &stubMail{}
	s.Mail = m
	mark := filepath.Join(s.DataDir, ApplyMailMark)

	s.SyncMail(ctx)
	if len(m.applied) != 0 {
		t.Fatalf("the mail configuration was written without a restore (%d times)", len(m.applied))
	}
	if err := os.WriteFile(mark, []byte("2026-11-13T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SyncMail(ctx)
	if len(m.applied) != 1 {
		t.Fatalf("after a restore the mail configuration was written %d times, want 1", len(m.applied))
	}
	if _, err := os.Stat(mark); !os.IsNotExist(err) {
		t.Error("the mark is still there after the settings were written")
	}
	s.SyncMail(ctx)
	if len(m.applied) != 1 {
		t.Errorf("the settings were written again at the next start (%d times)", len(m.applied))
	}
}
