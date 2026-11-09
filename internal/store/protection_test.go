package store

import (
	"context"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/mailconf"
)

func TestOutboundSpamSenders(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	log := func(qid, sender, status, info string, outbound bool) {
		_, err := f.st.db.Exec(ctx, `INSERT INTO mail_log(at, queue_id, sender, recipient, status, info, outbound) VALUES(now(), $1, $2, 'x@gmail.example', $3, $4, $5)`,
			qid, sender, status, info, outbound)
		must(t, err)
	}
	for i, q := range []string{"Q1", "Q2"} {
		log(q, "ana@a.test", "rejected", "5.7.1 Spam message rejected", true)
		_ = i
	}
	log("Q2", "ana@a.test", "rejected", "5.7.1 Spam message rejected", true)  // same message, second recipient
	log("Q9", "ana@a.test", "rejected", "5.7.1 Spam message rejected", false) // incoming: not counted
	log("Q8", "ana@a.test", "rejected", "4.7.1 Try again later", true)        // not spam
	since := time.Now().Add(-time.Hour)
	got, err := f.st.OutboundSpamSenders(ctx, since, 3)
	must(t, err)
	if len(got) != 0 {
		t.Fatalf("two messages are below the threshold: %+v", got)
	}
	log("Q3", "ana@a.test", "rejected", "5.7.1 Virus found", true)
	got, err = f.st.OutboundSpamSenders(ctx, since, 3)
	must(t, err)
	if len(got) != 1 || got[0].MailboxID != f.ana.ID || got[0].Messages != 3 {
		t.Fatalf("ana should be listed with 3 messages: %+v", got)
	}
	must(t, f.st.BlockSending(ctx, f.ana.ID))
	got, err = f.st.OutboundSpamSenders(ctx, since, 3)
	must(t, err)
	if len(got) != 0 {
		t.Fatalf("a blocked mailbox is listed again: %+v", got)
	}
	st, err := f.st.MailStatsSince(ctx, since)
	must(t, err)
	if st.RefusedOut != 5 || st.RefusedIn != 1 || st.Spam != 4 || st.Viruses != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestOutboundIPs(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	must(t, f.st.SetCustomerOutboundIP(ctx, f.a.ID, "203.0.113.5"))
	if err := f.st.SetCustomerOutboundIP(ctx, f.a.ID, "203.0.113.5; drop"); err == nil {
		t.Fatal("invalid address accepted")
	}
	var dom, tr string
	must(t, f.st.db.QueryRow(ctx, `SELECT domain, transport FROM mta_sender_transport`).Scan(&dom, &tr))
	// same name as mailconf.TransportName("203.0.113.5")
	if dom != "a.test" || tr != mailconf.TransportName("203.0.113.5")+":" {
		t.Fatalf("view: %s %s", dom, tr)
	}
	c, err := f.st.CustomerByID(ctx, f.a.ID)
	must(t, err)
	if c.OutboundIP != "203.0.113.5" {
		t.Fatalf("customer: %q", c.OutboundIP)
	}
	n, err := f.st.ClearOutboundIPs(ctx, []string{"198.51.100.1"})
	must(t, err)
	if n != 1 {
		t.Fatalf("cleared %d", n)
	}
	at, _, err := f.st.AdminNotice(ctx, "x")
	must(t, err)
	if !at.IsZero() {
		t.Fatal("notice never sent")
	}
	must(t, f.st.SetAdminNotice(ctx, "x", "state"))
	if _, s, _ := f.st.AdminNotice(ctx, "x"); s != "state" {
		t.Fatal("notice state")
	}
}
