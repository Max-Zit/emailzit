package sieve

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Spam levels: how high Rspamd's score must be before a message goes to
// Junk. Rspamd writes the score as stars (X-Spam-Level), one per point.
const (
	SpamOff     = "off"
	SpamRelaxed = "relaxed"
	SpamNormal  = "normal"
	SpamStrict  = "strict"
)

// SpamLevels are the levels in the order the panels show them.
var SpamLevels = []string{SpamStrict, SpamNormal, SpamRelaxed, SpamOff}

var spamStars = map[string]int{SpamStrict: 4, SpamNormal: 6, SpamRelaxed: 10}

// MaxSenders is how many entries an allow or block list holds.
const MaxSenders = 200

// Errors of CleanSenders.
var (
	ErrBadSender      = errors.New("not an address or domain")
	ErrTooManySenders = errors.New("at most 200 entries per list")
)

var senderRE = regexp.MustCompile(`^([a-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$`)

// CleanSenders checks an allow or block list: addresses (ana@example.com)
// and whole domains (example.com or @example.com), one per line or
// separated by commas; duplicates are dropped.
func CleanSenders(text string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t' }) {
		v := strings.TrimPrefix(strings.ToLower(f), "@")
		if !senderRE.MatchString(v) || strings.Contains(v, "..") {
			return nil, fmt.Errorf("%w: %s", ErrBadSender, truncate(f))
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) > MaxSenders {
		return nil, ErrTooManySenders
	}
	return out, nil
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

// SpamScript renders a mailbox's spam rules, run before the user's own
// filters: allowed senders are never moved to Junk, blocked senders always
// are, and other mail goes there when its score reaches the level. Entries
// are expected cleaned (CleanSenders); anything else is left out.
func SpamScript(level string, allow, block []string) string {
	split := func(list []string) (addrs, domains []string) {
		for _, v := range list {
			if !senderRE.MatchString(v) {
				continue
			}
			if strings.Contains(v, "@") {
				addrs = append(addrs, quote(v))
			} else {
				domains = append(domains, quote(v))
			}
		}
		return
	}
	test := func(addrs, domains []string) string {
		var t []string
		if len(addrs) > 0 {
			t = append(t, `address :all :is "from" [`+strings.Join(addrs, ", ")+`]`)
		}
		if len(domains) > 0 {
			t = append(t, `address :domain :is "from" [`+strings.Join(domains, ", ")+`]`)
		}
		switch len(t) {
		case 0:
			return ""
		case 1:
			return t[0]
		}
		return "anyof (" + strings.Join(t, ", ") + ")"
	}
	var b strings.Builder
	b.WriteString("# EmailZit: spam settings of this mailbox (written by the mail helper;\r\n# change them in the panel or in the mail settings)\r\n")
	b.WriteString(`require ["fileinto", "mailbox"];` + "\r\n")
	branch := "if"
	if t := test(split(allow)); t != "" {
		b.WriteString(branch + " " + t + " {\r\n  # allowed sender: never Junk\r\n}\r\n")
		branch = "elsif"
	}
	if t := test(split(block)); t != "" {
		b.WriteString(branch + " " + t + " {\r\n  fileinto :create \"Junk\";\r\n  stop;\r\n}\r\n")
		branch = "elsif"
	}
	if n, ok := spamStars[level]; ok {
		b.WriteString(branch + ` header :contains "X-Spam-Level" ` + quote(strings.Repeat("*", n)) + " {\r\n  fileinto :create \"Junk\";\r\n  stop;\r\n}\r\n")
	}
	return b.String()
}

// ValidSpamLevel tells a known level ("" = the customer's level, for a
// mailbox).
func ValidSpamLevel(l string, inherit bool) bool {
	if l == "" {
		return inherit
	}
	_, ok := spamStars[l]
	return ok || l == SpamOff
}
