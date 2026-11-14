package submit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func FuzzPrepare(f *testing.F) {
	f.Add("From: web@acme.test\nTo: a@b.test\nBcc: c@d.test\nSubject: x\n\nhi", "web@acme.test", "a@b.test", true)
	f.Add("To: a@b.test\r\n\r\nhi", "", "", false)
	f.Fuzz(func(t *testing.T, msg, sender, rcpt string, extract bool) {
		p, err := prepare(Request{Sender: sender, Extract: extract, Rcpts: []string{rcpt}}, []byte(msg), "mail.acme.test", time.Unix(1793318400, 0))
		if err != nil {
			return
		}
		if len(p.rcpts) == 0 {
			t.Fatal("message without recipients accepted")
		}
		head, _, _ := bytes.Cut(p.data, []byte("\n\n"))
		if bytes.Contains(bytes.ToLower(append([]byte("\n"), head...)), []byte("\nbcc:")) {
			t.Fatalf("Bcc header kept: %q", head)
		}
		for _, r := range p.rcpts {
			if !validAddr(r) {
				t.Fatalf("invalid recipient: %q", r)
			}
		}
	})
}

// FuzzEnvelope checks the parser of MAIL FROM / RCPT TO of the relay: it
// must never take an address that the rest of the code would not accept,
// and never keep a line end or an angle bracket.
func FuzzEnvelope(f *testing.F) {
	f.Add("FROM:<web@acme.test> SIZE=100")
	f.Add("TO:<a@b.test>")
	f.Add("FROM:<@a.test,@b.test:c@d.test>")
	f.Fuzz(func(t *testing.T, arg string) {
		for _, want := range []string{"FROM", "TO"} {
			addr, params, ok := envelope(arg, want)
			if !ok {
				continue
			}
			if strings.ContainsAny(addr, "<>\r\n") {
				t.Fatalf("envelope(%q, %q) = %q", arg, want, addr)
			}
			for _, p := range params {
				if strings.ContainsAny(p, " \r\n") {
					t.Fatalf("parameter %q of %q", p, arg)
				}
			}
		}
	})
}
