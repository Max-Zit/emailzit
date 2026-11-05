package maillog

import (
	"testing"
	"time"
)

func FuzzLine(f *testing.F) {
	f.Add("postfix/qmgr", "3C80F260E0: from=<ana@acme.test>, size=618, nrcpt=1 (queue active)")
	f.Add("postfix/smtp", "BD91C25CFB: to=<x@gmail.com>, orig_to=<y@acme.test>, relay=r[1.2.3.4]:25, delay=0.09, dsn=4.4.1, status=deferred (x)")
	f.Fuzz(func(t *testing.T, prog, msg string) {
		var p Parser
		for _, e := range p.Line(time.Unix(0, 0), prog, msg) {
			if len(e.Info) > 2000 || len(e.Recipient) > 2000 {
				t.Fatalf("field not clipped: %+v", e)
			}
		}
	})
}
