package web

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/testdb"
)

// Nobody reads a delivery log line by line. When a receiver stops taking
// mail from this server, the administrators have to be told — that is the
// whole difference between noticing it today and noticing it in a week,
// as happened to our own server with Outlook.com.
func TestBlockedReceiverNotice(t *testing.T) {
	ctx := context.Background()
	// the same database the server uses, so the test can write log lines
	// the way the root helper does
	url := testdb.URL(t)
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.UseSecretKey(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	logRow := func(rcpt, status, info string) {
		t.Helper()
		if _, err := conn.Exec(ctx, `INSERT INTO mail_log(at, queue_id, sender, recipient, status, dsn, info, relay, outbound)
			VALUES(now(), 'Q', 'post@ours.test', $1, $2, '5.7.1', $3, 'mx[203.0.113.9]:25', true)`, rcpt, status, info); err != nil {
			t.Fatal(err)
		}
	}
	m := s.MailConfig(ctx)
	m.NoticeTo = "admin@ours.test"
	if err := st.SetSetting(ctx, settingMail, m); err != nil {
		t.Fatal(err)
	}
	type notice struct{ subject, body string }
	var sent []notice
	s.SystemMail = func(_ context.Context, _ string, _ []string, subject, body string) error {
		sent = append(sent, notice{subject, body})
		return nil
	}
	now := time.Now()
	s.SetClock(func() time.Time { return now })

	t.Run("nothing is said while the mail flows", func(t *testing.T) {
		for i := 0; i < 6; i++ {
			logRow("user@fine.example", "sent", "250 ok")
		}
		s.blockedReceiverNotice(ctx)
		if len(sent) != 0 {
			t.Fatalf("a notice went out for nothing: %+v", sent)
		}
	})

	t.Run("a receiver that refuses everything is reported once", func(t *testing.T) {
		for i := 0; i < 6; i++ {
			logRow("user@blocked.example", "bounced", "550 5.7.1 messages from [203.0.113.5] weren't sent ... block list (S3140)")
		}
		now = now.Add(7 * time.Hour)
		s.blockedReceiverNotice(ctx)
		if len(sent) != 1 {
			t.Fatalf("expected one notice, got %+v", sent)
		}
		if !strings.Contains(sent[0].body, "blocked.example") || !strings.Contains(sent[0].body, "S3140") {
			t.Errorf("the notice does not say what happened:\n%s", sent[0].body)
		}
		if !strings.Contains(sent[0].body, "Delivery routes") {
			t.Errorf("the notice does not say what can be done:\n%s", sent[0].body)
		}
		// the same state says nothing a second time
		now = now.Add(7 * time.Hour)
		s.blockedReceiverNotice(ctx)
		if len(sent) != 1 {
			t.Fatalf("the same block was reported twice: %+v", sent[1:])
		}
	})

	t.Run("a receiver that takes mail again is reported too", func(t *testing.T) {
		logRow("user@blocked.example", "sent", "250 ok")
		now = now.Add(7 * time.Hour)
		s.blockedReceiverNotice(ctx)
		if len(sent) != 2 {
			t.Fatalf("expected a second notice, got %+v", sent)
		}
		if !strings.Contains(sent[1].body, "blocked.example") || !strings.Contains(sent[1].subject, "again") {
			t.Errorf("the recovery notice is wrong: %+v", sent[1])
		}
	})

	t.Run("the page shows the receivers", func(t *testing.T) {
		recv, err := st.Receivers(ctx, now.AddDate(0, 0, -1), 10)
		if err != nil {
			t.Fatal(err)
		}
		var got store.Receiver
		for _, r := range recv {
			if r.Domain == "blocked.example" {
				got = r
			}
		}
		if got.Bounced != 6 || got.Sent != 1 {
			t.Fatalf("the receiver reads %+v", got)
		}
		if got.Blocked() {
			t.Error("a receiver that delivered again still counts as blocked")
		}
	})
}
