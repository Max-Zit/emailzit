package sieve

import (
	"strings"
	"testing"
)

func TestScript(t *testing.T) {
	s := Settings{AutoReply: AutoReply{On: true, Subject: `Away "now"`, Body: "I am away.\nBack on Monday \\ ok", Until: "2026-11-30"},
		Rules: []Rule{{Field: "from", Value: `boss"; discard; #`, Action: "move", Folder: "Boss"}, {Field: "subject", Value: "newsletter", Action: "read"}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	sc := s.Script("ana@a.test")
	for _, want := range []string{`require ["fileinto", "mailbox", "imap4flags", "vacation", "date", "relational"];`,
		`if header :contains "from" "boss\"; discard; #"`, `fileinto :create "Boss";`, `:subject "Away \"now\""`, `Back on Monday \\ ok`,
		`currentdate :value "le" "date" "2026-11-30"`} {
		if !strings.Contains(sc, want) {
			t.Errorf("missing %q in\n%s", want, sc)
		}
	}
	if (&Settings{}).Script("a@b") != "" {
		t.Fatal("empty settings should give no script")
	}
	bad := Settings{Rules: []Rule{{Field: "body", Value: "x", Action: "move", Folder: "a"}}}
	if bad.Validate() == nil {
		t.Fatal("unknown field accepted")
	}
	bad = Settings{Rules: []Rule{{Field: "from", Value: "x", Action: "move", Folder: "a\r\nb"}}}
	if bad.Validate() == nil {
		t.Fatal("folder with newline accepted")
	}
}
