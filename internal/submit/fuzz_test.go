package submit

import (
	"bytes"
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
