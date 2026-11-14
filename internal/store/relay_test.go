package store

import (
	"context"
	"errors"
	"testing"
)

// The relay login belongs to one link: a link has at most one, only its hash
// is kept, and a wrong password is not accepted.
func TestRelayLogin(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	link := &HostZitLink{URL: "https://host.example.test:8442", ScopeAll: true}
	must(t, f.st.SaveHostZitLink(ctx, link))
	l, err := f.st.SetRelayLogin(ctx, link.ID, "HostZit-Relay@mail.test", "first-password")
	must(t, err)
	if l.Username != "hostzit-relay@mail.test" {
		t.Errorf("the user name is %q", l.Username)
	}
	var hash string
	must(t, f.st.db.QueryRow(ctx, `SELECT hash FROM relay_logins`).Scan(&hash))
	if hash == "first-password" {
		t.Error("the password itself is stored")
	}
	if _, _, err := f.st.CheckRelayLogin(ctx, "hostzit-relay@mail.test", "wrong"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a wrong password gave %v", err)
	}
	id, gotLink, err := f.st.CheckRelayLogin(ctx, "HostZit-Relay@MAIL.test", "first-password")
	must(t, err)
	if id != l.ID || gotLink != link.ID {
		t.Errorf("the check found %q of link %d, want %q of %d", id, gotLink, l.ID, link.ID)
	}

	// a second pairing replaces the login
	l2, err := f.st.SetRelayLogin(ctx, link.ID, "hostzit-relay@mail.test", "second-password")
	must(t, err)
	var n int
	must(t, f.st.db.QueryRow(ctx, `SELECT count(*) FROM relay_logins`).Scan(&n))
	if n != 1 {
		t.Errorf("%d logins exist", n)
	}
	if _, _, err := f.st.CheckRelayLogin(ctx, "hostzit-relay@mail.test", "first-password"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the old password still works (%v)", err)
	}
	must(t, f.st.TouchRelayLogin(ctx, l2.ID))
	got, err := f.st.RelayLoginOfLink(ctx, link.ID)
	must(t, err)
	if got.ID != l2.ID || got.LastUsed.IsZero() {
		t.Errorf("the login is %+v", got)
	}

	must(t, f.st.DeleteRelayLoginsOfLink(ctx, link.ID))
	if _, err := f.st.RelayLoginOfLink(ctx, link.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after the unlink: %v", err)
	}
}

// What the relay needs for a message: whose domain it is, the limits of
// that customer, and the counts it writes.
func TestRelayDomainAndLimits(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	if _, err := f.st.DomainCustomer(ctx, "nobody.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown domain gave %v", err)
	}
	cust, err := f.st.DomainCustomer(ctx, "A.test")
	must(t, err)
	if cust != f.a.ID {
		t.Errorf("a.test belongs to %q", cust)
	}
	// an unverified domain may not send
	d, err := f.st.CreateDomain(ctx, Staff, f.a.ID, "new.test", false)
	must(t, err)
	if _, err := f.st.DomainCustomer(ctx, "new.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unverified domain gave %v", err)
	}
	must(t, f.st.SetDomainVerified(ctx, Staff, d.ID, true))
	if _, err := f.st.DomainCustomer(ctx, "new.test"); err != nil {
		t.Errorf("a verified domain gave %v", err)
	}

	l, err := f.st.RelayLimits(ctx, f.a.ID)
	must(t, err)
	if l.Blocked || l.CustomerPerHour != f.pkg.CustomerPerHour || l.RcptPerMsg != f.pkg.RcptPerMsg {
		t.Fatalf("the limits are %+v", l)
	}
	// relayed mail counts towards the customer's hour, together with the
	// mail of the mailboxes
	must(t, f.st.LogRelaySent(ctx, f.a.ID, 4))
	must(t, f.st.LogSent(ctx, &SendLimits{MailboxID: f.ana.ID, CustomerID: f.a.ID}, 2, ""))
	l, err = f.st.RelayLimits(ctx, f.a.ID)
	must(t, err)
	if l.CustomerHour != 6 {
		t.Errorf("the hour counts %d recipients, want 6", l.CustomerHour)
	}
	must(t, f.st.SetCustomerStatus(ctx, f.a.ID, "suspended", "test"))
	l, err = f.st.RelayLimits(ctx, f.a.ID)
	must(t, err)
	if !l.Blocked {
		t.Error("a suspended customer may still send")
	}
}

// The relay log shows the customer their websites' mail, with what became
// of it, and never another customer's.
func TestRelayLog(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	must(t, f.st.LogRelay(ctx, RelayMail{CustomerID: f.a.ID, Sender: "Web@a.test", Rcpts: 2, QueueID: "Q1", Status: "sent", ClientIP: "203.0.113.5"}))
	must(t, f.st.LogRelay(ctx, RelayMail{CustomerID: f.a.ID, Sender: "web@a.test", Rcpts: 1, Status: "refused", Reason: "the From address uses another domain"}))
	must(t, f.st.LogRelay(ctx, RelayMail{CustomerID: f.b.ID, Sender: "web@b.test", Rcpts: 1, QueueID: "Q2", Status: "sent"}))
	// a domain of HostZit whose customer is not here
	must(t, f.st.LogRelay(ctx, RelayMail{Sender: "web@shop.test", Rcpts: 1, QueueID: "Q3", Status: "sent"}))
	_, err := f.st.db.Exec(ctx, `INSERT INTO mail_log(at, queue_id, sender, recipient, status, outbound) VALUES(now(),'Q1','web@a.test','x@example.test','bounced',true)`)
	must(t, err)

	mine, err := f.st.RelayLog(ctx, Scope{CustomerID: f.a.ID}, 50)
	must(t, err)
	if len(mine) != 2 {
		t.Fatalf("the customer sees %d entries", len(mine))
	}
	if mine[0].Status != "refused" || mine[0].Reason == "" {
		t.Errorf("the newest entry is %+v", mine[0])
	}
	if mine[1].Sender != "web@a.test" || mine[1].Delivery != "bounced" {
		t.Errorf("the sent entry is %+v", mine[1])
	}
	all, err := f.st.RelayLog(ctx, Staff, 50)
	must(t, err)
	if len(all) != 4 {
		t.Fatalf("staff see %d entries", len(all))
	}
	sent, refused, err := f.st.RelayCounts(ctx, f.a.CreatedAt)
	must(t, err)
	if sent != 3 || refused != 1 {
		t.Errorf("the report counts %d sent, %d refused", sent, refused)
	}
}
