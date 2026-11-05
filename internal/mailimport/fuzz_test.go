package mailimport

import (
	"archive/tar"
	"bytes"
	"io"
	"path"
	"strings"
	"testing"
)

func FuzzScan(f *testing.F) {
	f.Add(archive(&testing.T{}, []entry{{name: "cpmove-bob/homedir/mail/shop.test/info/cur/1:2,S", body: "Subject: x\n\nhi"},
		{name: "cpmove-bob/homedir/etc/shop.test/passwd", body: "info:x:1:1::/home/bob/mail/shop.test/info:/bin/false\n"}}), "cpanel")
	f.Add(archive(&testing.T{}, []entry{{name: "manifest.json", body: "{}"}, {name: "mail/acme.test/ana/Maildir/cur/1", body: "x"}}), "emailzit")
	f.Add([]byte("not gzip"), "cpanel")
	f.Fuzz(func(t *testing.T, data []byte, format string) {
		if format != "cpanel" && format != "emailzit" {
			format = "cpanel"
		}
		_, _ = Scan(bytes.NewReader(data), format)
		_ = Each(bytes.NewReader(data), format, func(address, rel string, h *tar.Header, body io.Reader) error {
			if !ValidAddress(address) {
				t.Fatalf("invalid address handed out: %q", address)
			}
			if rel == "" || path.IsAbs(rel) || strings.Contains("/"+rel+"/", "/../") || strings.Contains(rel, "\\") {
				t.Fatalf("unsafe path handed out: %q", rel)
			}
			return nil
		})
	})
}

func FuzzMailPath(f *testing.F) {
	f.Add("cpanel", "cpmove-bob/homedir/mail/shop.test/info/cur/1")
	f.Add("emailzit", "mail/acme.test/ana/Maildir/new/1")
	f.Add("cpanel", "x/homedir/mail/a.test/../../../etc/shadow")
	f.Fuzz(func(t *testing.T, format, name string) {
		addr, rel, ok := MailPath(format, name)
		if !ok {
			return
		}
		if !ValidAddress(addr) || rel == "" || path.IsAbs(rel) || strings.Contains("/"+rel+"/", "/../") {
			t.Fatalf("unsafe result for %q: %q %q", name, addr, rel)
		}
	})
}
