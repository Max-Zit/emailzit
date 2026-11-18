package web

import (
	"context"
	"testing"
	"time"
)

type expungeMail struct {
	stubMail
	junk, trash, calls int
}

func (m *expungeMail) Expunge(_ context.Context, junk, trash int) error {
	m.junk, m.trash = junk, trash
	m.calls++
	return nil
}

// Mail that is deleted cannot be brought back, so the clean-up has to be
// switched on by hand, run at most once a day, and ask for exactly the
// spans the administrator set.
func TestCleanupOfOldMail(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	mail := &expungeMail{}
	s.Mail = mail
	// the store stamps the notices with the time of the database, so the
	// clock of the test stays next to the real one and only moves forward
	now := time.Now()
	if h := now.Hour(); h < cleanupHour+1 {
		now = now.Add(time.Duration(cleanupHour+1-h) * time.Hour)
	}
	s.SetClock(func() time.Time { return now })
	set := func(junk, trash int) {
		t.Helper()
		m := s.MailConfig(ctx)
		m.JunkDays, m.TrashDays = junk, trash
		if err := st.SetSetting(ctx, settingMail, m); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("nothing is deleted while it is switched off", func(t *testing.T) {
		s.cleanupOldMail(ctx)
		if mail.calls != 0 {
			t.Fatalf("the clean-up ran although it is off: %+v", mail)
		}
	})

	t.Run("the spans of the settings are used", func(t *testing.T) {
		set(30, 14)
		s.cleanupOldMail(ctx)
		if mail.calls != 1 || mail.junk != 30 || mail.trash != 14 {
			t.Fatalf("the helper was asked for %+v", mail)
		}
	})

	t.Run("it runs once a day", func(t *testing.T) {
		now = now.Add(3 * time.Hour)
		s.cleanupOldMail(ctx)
		if mail.calls != 1 {
			t.Fatalf("it ran again after three hours: %+v", mail)
		}
		now = now.Add(22 * time.Hour)
		s.cleanupOldMail(ctx)
		if mail.calls != 2 {
			t.Fatalf("it did not run the next day: %+v", mail)
		}
	})

	t.Run("a span that is no time span is refused", func(t *testing.T) {
		m := s.MailConfig(ctx)
		m.JunkDays = 4000
		if err := m.Validate(); err == nil {
			t.Error("4000 days was accepted")
		}
		m.JunkDays = -1
		if err := m.Validate(); err == nil {
			t.Error("a negative span was accepted")
		}
	})

	t.Run("the routes survive a save of the mail settings", func(t *testing.T) {
		// the form of the mail settings carries no routes; they have their
		// own page and must not be lost when the other settings are saved
		m := s.MailConfig(ctx)
		m.Routes = []MailRoute{{Domain: "hotmail.com", Host: "relay.example.net", Port: 587}}
		if err := st.SetSetting(ctx, settingMail, m); err != nil {
			t.Fatal(err)
		}
		if got := s.MailConfig(ctx); len(got.Routes) != 1 {
			t.Fatalf("the routes were not saved: %+v", got.Routes)
		}
	})
}
