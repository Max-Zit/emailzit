package msgid

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// MSGID_RANDY of SpamAssassin's 20_head_tests.cf (header Message-ID).
var randy = regexp.MustCompile(`<[a-z\d][a-z\d\$-]{10,29}[a-z\d]\@[a-z\d][a-z\d.]{3,12}[a-z\d]>`)

func TestNoSpamPattern(t *testing.T) {
	for _, host := range []string{"backupzit.com", "e1.maxzit.com", "mail.example.org", "a.io"} {
		id := New(host, time.Date(2026, 11, 12, 13, 13, 47, 0, time.UTC))
		if randy.MatchString("<" + id + ">") {
			t.Errorf("%s matches MSGID_RANDY", id)
		}
		if !strings.HasPrefix(id, "20261112131347.") || !strings.HasSuffix(id, "@"+host) {
			t.Errorf("unexpected form %s", id)
		}
	}
	// the earlier form matched, so the pattern above is the right one
	if !randy.MatchString("<3f9a0c1b2d4e5f60718293a4@backupzit.com>") {
		t.Fatal("MSGID_RANDY pattern does not match the old form")
	}
	now := time.Now()
	if a, b := New("x.org", now), New("x.org", now); a == b {
		t.Fatal("two equal Message-IDs")
	}
}
