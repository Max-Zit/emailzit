package webmail

import (
	"testing"

	"github.com/emersion/go-imap"
)

func FuzzParse(f *testing.F) {
	f.Add("From: Ana <ana@acme.test>\r\nTo: b@c.test\r\nSubject: =?utf-8?q?Zdravo_=C5=BE?=\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n--b\r\nContent-Type: application/pdf; name=a.pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n--b--\r\n")
	f.Add("Subject: x\r\n\r\nplain")
	f.Fuzz(func(t *testing.T, raw string) {
		m, err := Parse([]byte(raw))
		if err != nil {
			return
		}
		_ = m.Body()
		for i, a := range m.Attachments {
			if a.Index != i || len(a.Data()) != a.Size {
				t.Fatalf("attachment %d inconsistent: index %d, size %d, data %d", i, a.Index, a.Size, len(a.Data()))
			}
		}
		if m.HTML != "" {
			_ = SafeHTML(m.HTML)
		}
	})
}

func FuzzTargetFolder(f *testing.F) {
	f.Add("INBOX.Sent Items", ".", `\Sent`)
	f.Add("Archiv/2024", "/", "")
	f.Fuzz(func(t *testing.T, name, delim, attr string) {
		roles := map[string]string{imap.SentAttr: "Sent", imap.TrashAttr: "Trash", imap.JunkAttr: "Junk", imap.DraftsAttr: "Drafts"}
		out := targetFolder(&imap.MailboxInfo{Name: name, Delimiter: delim, Attributes: []string{attr}}, nil, roles)
		if out == "" && name != "" {
			t.Fatalf("folder %q mapped to nothing", name)
		}
	})
}
