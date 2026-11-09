package maillog

import (
	"testing"
	"time"
)

func TestParser(t *testing.T) {
	var p Parser
	at := time.Now()
	lines := []struct{ prog, msg string }{
		{"postfix/qmgr", "3C80F260E0: from=<ana@acme.test>, size=618, nrcpt=1 (queue active)"},
		{"postfix/lmtp", "3C80F260E0: to=<berta@beta.test>, relay=mail.emailzit.test[private/dovecot-lmtp], delay=0.49, delays=0.46/0.01/0.01/0, dsn=2.0.0, status=sent (250 2.0.0 <berta@beta.test> JXvKKnRg5GouKgAAqKbpuQ Saved)"},
		{"postfix/smtp", "BD91C25CFB: to=<x@gmail.com>, orig_to=<y@acme.test>, relay=192.168.101.102[192.168.101.102]:1025, delay=0.09, delays=0.07/0.01/0.01/0, dsn=4.4.1, status=deferred (connect to x: Connection refused)"},
		{"postfix/submission/smtpd", "NOQUEUE: reject: RCPT from localhost[127.0.0.1]: 553 5.7.1 <berta@beta.test>: Sender address rejected: not owned by user ana@acme.test; from=<berta@beta.test> to=<marko@acme.test> proto=ESMTP helo=<x>"},
		{"postfix/cleanup", "6421625CF1: milter-reject: END-OF-MESSAGE from unknown[192.168.101.104]: 5.7.1 Gtube pattern; from=<friend@gmail.com> to=<marko@acme.test> proto=ESMTP helo=<gtube.txt>"},
		{"postfix/qmgr", "3C80F260E0: removed"},
	}
	var ev []Event
	for _, l := range lines {
		ev = append(ev, p.Line(at, l.prog, l.msg)...)
	}
	if len(ev) != 4 {
		t.Fatalf("%d events: %+v", len(ev), ev)
	}
	if ev[0].Status != Sent || ev[0].Sender != "ana@acme.test" || ev[0].Recipient != "berta@beta.test" || ev[0].DSN != "2.0.0" {
		t.Errorf("sent: %+v", ev[0])
	}
	if ev[1].Status != Deferred || ev[1].Recipient != "x@gmail.com" || ev[1].Info != "connect to x: Connection refused" {
		t.Errorf("deferred: %+v", ev[1])
	}
	if ev[2].Status != Rejected || ev[2].Sender != "berta@beta.test" || ev[2].Recipient != "marko@acme.test" {
		t.Errorf("rejected: %+v", ev[2])
	}
	if ev[3].Status != Rejected || ev[3].Info != "5.7.1 Gtube pattern" {
		t.Errorf("milter: %+v", ev[3])
	}
	if p.sender("3C80F260E0") != "" {
		t.Error("sender kept after removal")
	}
}

func TestOutboundAndPostscreen(t *testing.T) {
	var p Parser
	at := time.Now()
	ev := p.Line(at, "postfix/submission/smtpd", "4dQ1xY2zK3: milter-reject: END-OF-MESSAGE from client.example[198.51.100.7]: 5.7.1 Spam message rejected; from=<ana@acme.test> to=<x@gmail.com> proto=ESMTP helo=<pc>")
	if len(ev) != 1 || !ev[0].Outbound || Reason(ev[0].Info) != ReasonSpam || ev[0].Sender != "ana@acme.test" {
		t.Fatalf("submission spam: %+v", ev)
	}
	ev = p.Line(at, "postfix/smtpd", "4dQ1xY2zK4: milter-reject: END-OF-MESSAGE from mx.example[203.0.113.9]: 5.7.1 Virus found; from=<a@example.org> to=<ana@acme.test> proto=ESMTP helo=<mx>")
	if len(ev) != 1 || ev[0].Outbound || Reason(ev[0].Info) != ReasonVirus {
		t.Fatalf("inbound virus: %+v", ev)
	}
	ev = p.Line(at, "postfix/postscreen", "NOQUEUE: reject: RCPT from [203.0.113.66]:41234: 550 5.7.1 Service unavailable; client [203.0.113.66] blocked using zen.spamhaus.org; from=<spam@example.net>, to=<ana@acme.test>, proto=ESMTP, helo=<x>")
	if len(ev) != 1 || ev[0].Recipient != "ana@acme.test" || ev[0].Status != Rejected {
		t.Fatalf("postscreen: %+v", ev)
	}
	ev = p.Line(at, "postfix/smtpd", "NOQUEUE: reject: RCPT from unknown[2001:db8::1]: 554 5.7.1 <x@y>: Relay access denied; from=<a@b.example> to=<x@y.example> proto=ESMTP helo=<h>")
	if len(ev) != 1 || ev[0].Sender != "a@b.example" {
		t.Fatalf("smtpd ipv6: %+v", ev)
	}
	if Reason("5.7.1 This server does not accept programs, scripts or documents with macros as attachments.") != ReasonAttachment {
		t.Fatal("attachment reason")
	}
}

func TestOutboundThroughCleanup(t *testing.T) {
	var p Parser
	at := time.Now()
	p.Line(at, "postfix/submission/smtpd", "5B1C2D3E4F: client=localhost[127.0.0.1], sasl_method=PLAIN, sasl_username=marko@acme.test")
	ev := p.Line(at, "postfix/cleanup", "5B1C2D3E4F: milter-reject: END-OF-MESSAGE from localhost[127.0.0.1]: 5.7.1 Gtube pattern; from=<marko@acme.test> to=<friend@gmail.com> proto=ESMTP helo=<ez-mail1>")
	if len(ev) != 1 || !ev[0].Outbound {
		t.Fatalf("%+v", ev)
	}
	ev = p.Line(at, "postfix/cleanup", "6B1C2D3E4F: milter-reject: END-OF-MESSAGE from mx[203.0.113.1]: 5.7.1 Spam message rejected; from=<a@b.example> to=<ana@acme.test> proto=ESMTP helo=<mx>")
	if len(ev) != 1 || ev[0].Outbound {
		t.Fatalf("inbound marked outbound: %+v", ev)
	}
}
