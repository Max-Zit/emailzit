package mailimport

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

type entry struct {
	name, body string
	link       bool
}

func archive(t *testing.T, es []entry) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.link {
			h = &tar.Header{Name: e.name, Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if !e.link {
			_, _ = io.WriteString(tw, e.body)
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return b.Bytes()
}

func TestCPanel(t *testing.T) {
	a := archive(t, []entry{
		{name: "cpmove-bob/homedir/etc/shop.test/passwd", body: "info:x:1001:1001::/home/bob/mail/shop.test/info:/home/bob\nsales:x:1001:1001::/home/bob/mail/shop.test/sales:/home/bob\n"},
		{name: "cpmove-bob/homedir/etc/shop.test/quota", body: "info:524288000\n"},
		{name: "cpmove-bob/homedir/etc/shop.test/shadow", body: "info:$6$secret:19000::::::\n"},
		{name: "cpmove-bob/homedir/mail/shop.test/info/cur/1.mail:2,S", body: "Subject: hi\n\nhello"},
		{name: "cpmove-bob/homedir/mail/shop.test/info/.Sent/cur/2.mail:2,S", body: "x"},
		{name: "cpmove-bob/homedir/mail/shop.test/info/../../../../etc/passwd", body: "evil"},
		{name: "cpmove-bob/homedir/mail/shop.test/info/cur/link", link: true},
		{name: "cpmove-bob/homedir/mail/cur/3.mail", body: "main account mail"},
		{name: "cpmove-bob/va/shop.test", body: "boss@shop.test: info@shop.test, partner@other.test\npipe@shop.test: |/home/bob/script.php\n*: :fail: No Such User Here\n"},
	})
	p, err := Scan(bytes.NewReader(a), FormatCPanel)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Domains, ",") != "shop.test" || len(p.Mailboxes) != 2 || p.Mailboxes[0].Address != "info@shop.test" || p.Mailboxes[0].QuotaMB != 500 || p.MailFiles != 2 {
		t.Fatalf("plan %+v", p)
	}
	if len(p.Aliases) != 1 || p.Aliases[0].Address != "boss@shop.test" || len(p.Aliases[0].Destinations) != 2 {
		t.Fatalf("aliases %+v", p.Aliases)
	}
	var got []string
	err = Each(bytes.NewReader(a), FormatCPanel, func(addr, rel string, h *tar.Header, body io.Reader) error {
		got = append(got, addr+" "+rel)
		return nil
	})
	if err != nil || strings.Join(got, "|") != "info@shop.test cur/1.mail:2,S|info@shop.test .Sent/cur/2.mail:2,S" {
		t.Fatalf("files %v %v", got, err)
	}
	if _, err := Scan(bytes.NewReader(archive(t, []entry{{name: "x/readme", body: "x"}})), FormatCPanel); err == nil {
		t.Fatal("empty archive accepted")
	}
	if _, err := Scan(strings.NewReader("not gzip"), FormatCPanel); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestEmailZit(t *testing.T) {
	man := `{"format":"emailzit-export/1","spam_level":"strict","domains":[{"name":"ex.test"}],
		"mailboxes":[{"address":"ana@ex.test","quota_mb":300,"spam_level":"relaxed","spam_allow":["boss.test"],"filters":{"auto_reply":{"on":true}}},{"address":"Bad Name@ex.test"}],
		"aliases":[{"address":"info@ex.test","destinations":["ana@ex.test"],"send_as":true},{"address":"x@ex.test","destinations":["|prog"]}]}`
	a := archive(t, []entry{
		{name: "manifest.json", body: man},
		{name: "mail/ex.test/ana/Maildir/cur/1:2,S", body: "x"},
		{name: "mail/ex.test/ana/.emailzit/spam.sieve", body: "require"},
		{name: "mail/ex.test/ana/sieve/emailzit.sieve", body: "x"},
	})
	p, err := Scan(bytes.NewReader(a), FormatEmailZit)
	if err != nil {
		t.Fatal(err)
	}
	if p.SpamLevel != "strict" || len(p.Mailboxes) != 1 || p.Mailboxes[0].QuotaMB != 300 || p.Mailboxes[0].SpamLevel != "relaxed" || len(p.Mailboxes[0].Filters) == 0 || p.MailFiles != 1 {
		t.Fatalf("plan %+v", p)
	}
	if len(p.Aliases) != 1 || !p.Aliases[0].SendAs || len(p.Notes) != 2 {
		t.Fatalf("aliases %+v notes %v", p.Aliases, p.Notes)
	}
	if _, err := Scan(bytes.NewReader(archive(t, []entry{{name: "mail/ex.test/ana/Maildir/cur/1", body: "x"}})), FormatEmailZit); err == nil {
		t.Fatal("no manifest accepted")
	}
}
