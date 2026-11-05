package sieve

import (
	"strings"
	"testing"
)

func FuzzCleanSenders(f *testing.F) {
	f.Add("boss@example.com\npartner.com")
	f.Add("\"; discard; \"")
	f.Fuzz(func(t *testing.T, text string) {
		list, err := CleanSenders(text)
		if err != nil {
			return
		}
		for _, s := range list {
			if strings.ContainsAny(s, "\"\\\r\n;{} ") {
				t.Fatalf("unsafe entry for a Sieve script: %q", s)
			}
		}
		_ = SpamScript("normal", list, list)
	})
}
