package web

import (
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

func FuzzTXTStatus(f *testing.F) {
	f.Add("v=spf1 mx -all", "v=spf1 include:_spf.google.com ~all")
	f.Add("v=DMARC1; p=none; rua=mailto:dmarc-reports@a.test", "v=DMARC1; p=reject")
	f.Add("v=DKIM1; k=rsa; p=MIIB", "v=DKIM1; k=rsa; p=MIIB")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, want, found string) {
		st := txtStatus(want, strings.Split(found, "\n"))
		if st != CheckOK && st != CheckDifferent && st != CheckMissing {
			t.Fatalf("unknown status %q", st)
		}
	})
}

func FuzzAutodiscoverAddress(f *testing.F) {
	f.Add(`<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>ana@acme.test</EMailAddress></Request></Autodiscover>`)
	f.Add(`<!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">]><Autodiscover><Request><EMailAddress>&a;&a;</EMailAddress></Request></Autodiscover>`)
	f.Fuzz(func(t *testing.T, body string) {
		addr := autodiscoverAddress(strings.NewReader(body))
		if a, err := store.ParseAddress(addr); err == nil && (strings.ContainsAny(a, "<>\"&\r\n ") || !strings.Contains(a, "@")) {
			t.Fatalf("unsafe address accepted: %q", a)
		}
	})
}

func FuzzSafeNext(f *testing.F) {
	for _, s := range []string{"/customers", "//evil.example", `/\evil.example`, "/\t/evil.example", "https://evil.example", "/mail?x=1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		for _, out := range []string{safeNext(p), safeMailNext(p)} {
			if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") || strings.HasPrefix(out, "/\\") ||
				strings.IndexFunc(out, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
				t.Fatalf("unsafe redirect target %q from %q", out, p)
			}
		}
	})
}
