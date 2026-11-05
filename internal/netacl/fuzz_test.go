package netacl

import "testing"

func FuzzParsePrefix(f *testing.F) {
	for _, s := range []string{"10.0.0.0/8", "192.168.1.5", "::1", "fe80::/10", "1.2.3.4/33", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePrefix(s)
		if err == nil && !p.IsValid() {
			t.Fatalf("invalid prefix accepted from %q", s)
		}
		_ = Split(s)
		_, _ = AddrOf(s)
	})
}
