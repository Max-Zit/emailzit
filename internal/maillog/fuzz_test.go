package maillog

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func FuzzLine(f *testing.F) {
	f.Add("postfix/qmgr", "3C80F260E0: from=<ana@acme.test>, size=618, nrcpt=1 (queue active)")
	f.Add("postfix/smtp", "BD91C25CFB: to=<x@gmail.com>, orig_to=<y@acme.test>, relay=r[1.2.3.4]:25, delay=0.09, dsn=4.4.1, status=deferred (x)")
	// found by CI: a recipient of thousands of bytes went into the log unclipped
	f.Add("postfix/smtp", "00000000: to=<"+strings.Repeat("𑑑", 900)+">, relay=none, delay=1, dsn=5.0.0, status=bounced (x)")
	f.Fuzz(func(t *testing.T, prog, msg string) {
		var p Parser
		for _, e := range p.Line(time.Unix(0, 0), prog, msg) {
			if len(e.Recipient) > 254 || len(e.Sender) > 254 || len(e.Info) > 300 || len(e.Relay) > 300 || len(e.DSN) > 300 {
				t.Fatalf("field not clipped: %+v", e)
			}
			for _, s := range []string{e.Recipient, e.Sender, e.Info, e.Relay, e.DSN} {
				if !utf8.ValidString(s) {
					t.Fatalf("invalid UTF-8 kept: %q", s)
				}
			}
		}
	})
}
