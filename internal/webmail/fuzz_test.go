package webmail

import (
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

func FuzzSafeHTML(f *testing.F) {
	for _, s := range []string{`<p onclick="x()">hi</p>`, `<script>alert(1)</script>`, `<a href="javascript:alert(1)">x</a>`,
		`<img src=x onerror=alert(1)>`, `<svg><script>1</script></svg>`, `<style>@import url(x)</style>`, `<iframe src=x>`, `<a href=" jav&#x09;ascript:x">`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := SafeHTML(in)
		// what a browser would build from the output: no active elements,
		// no event handlers, no script URLs
		z := xhtml.NewTokenizer(strings.NewReader(out))
		for {
			tt := z.Next()
			if tt == xhtml.ErrorToken {
				break
			}
			if tt != xhtml.StartTagToken && tt != xhtml.SelfClosingTagToken {
				continue
			}
			tok := z.Token()
			switch tok.Data {
			case "script", "iframe", "object", "embed", "form", "base", "meta", "link", "frame", "frameset":
				t.Fatalf("<%s> kept: %q (from %q)", tok.Data, out, in)
			}
			for _, a := range tok.Attr {
				v := strings.ToLower(strings.Join(strings.Fields(a.Val), ""))
				if strings.HasPrefix(strings.ToLower(a.Key), "on") || strings.Contains(v, "javascript:") || strings.Contains(v, "vbscript:") {
					t.Fatalf("attribute %s=%q kept: %q (from %q)", a.Key, a.Val, out, in)
				}
			}
		}
		_ = HTMLToText(in)
	})
}
