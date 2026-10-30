package webmail

import (
	"strings"
	"testing"
)

func TestSafeHTML(t *testing.T) {
	in := `<p onclick="x()">Hi <a href="javascript:alert(1)">bad</a> <a href="https://ok.example/">ok</a></p>` +
		`<script>alert(1)</script><style>body{}</style><img src="https://track.example/p.gif"><img src="cid:logo">` +
		`<iframe src="https://x"></iframe><form action="https://x"><input name=a></form><div style="x">t</div><svg><script>1</script></svg>`
	out := SafeHTML(in)
	for _, bad := range []string{"onclick", "javascript:", "<script", "alert", "<style", "track.example", "<iframe", "<form", "<input", "style=", "<svg"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q left in %s", bad, out)
		}
	}
	for _, good := range []string{`href="https://ok.example/"`, `target="_blank"`, `src="cid:logo"`, "Hi", "<p>"} {
		if !strings.Contains(out, good) {
			t.Errorf("%q missing in %s", good, out)
		}
	}
}

func TestBuildAndParse(t *testing.T) {
	d := &Draft{FromName: "Ana Anić", From: "ana@a.test", To: "Marko <marko@b.test>, x@c.test", Bcc: "hidden@d.test",
		Subject: "Zdravo\r\nBcc: injected@evil.test", Text: "Šta ima?\nPozdrav",
		Files: []File{{Name: "a.txt", Type: "text/plain", Data: []byte("file content")}}}
	raw, rcpts, err := d.Build("mail.a.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rcpts) != 3 || rcpts[2] != "hidden@d.test" {
		t.Fatal(rcpts)
	}
	s := string(raw)
	if strings.Contains(s, "hidden@d.test") || strings.Contains(s, "\nBcc:") {
		t.Fatal("Bcc visible or header injected")
	}
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Text, "Šta ima?") || len(m.Attachments) != 1 || m.Attachments[0].Name != "a.txt" || !strings.Contains(m.From, "ana@a.test") {
		t.Fatalf("%+v", m)
	}
	if !strings.HasPrefix(m.Subject, "Zdravo") {
		t.Fatal(m.Subject)
	}
	if _, _, err := (&Draft{From: "a@a.test", To: "not an address"}).Build("h"); err == nil {
		t.Fatal("bad address accepted")
	}
}
