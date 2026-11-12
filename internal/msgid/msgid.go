// Package msgid makes the Message-ID of messages EmailZit writes itself
// (webmail, mail from websites).
package msgid

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// New returns a Message-ID without the angle brackets:
// <UTC time>.<random hex>@host, e.g. 20261112121347.3f9a…@example.com.
// The dot in the left part matters: a bare run of 11–31 letters and digits
// before the @ matches SpamAssassin's MSGID_RANDY ("Message-Id has pattern
// used in spam", 2.6 points), which the earlier random-hex form did.
func New(host string, now time.Time) string {
	var r [10]byte
	_, _ = rand.Read(r[:])
	return now.UTC().Format("20060102150405") + "." + hex.EncodeToString(r[:]) + "@" + host
}
