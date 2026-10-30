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

func TestSpamScript(t *testing.T) {
	allow, err := CleanSenders("Boss@Example.com, @partner.test\nfriend.org")
	if err != nil || strings.Join(allow, " ") != "boss@example.com partner.test friend.org" {
		t.Fatal(allow, err)
	}
	for _, bad := range []string{`a"b@x.test`, "x", "a@b", "a@-x.test", "a@x..test", `x.test"; discard; "`} {
		if _, err := CleanSenders(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	s := SpamScript(SpamStrict, allow, []string{"spam@bad.test"})
	for _, want := range []string{
		`if anyof (address :all :is "from" ["boss@example.com"], address :domain :is "from" ["partner.test", "friend.org"]) {`,
		`elsif address :all :is "from" ["spam@bad.test"] {`,
		`elsif header :contains "X-Spam-Level" "****" {`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if s := SpamScript(SpamOff, nil, nil); strings.Contains(s, "if ") {
		t.Fatal(s)
	}
	if s := SpamScript(SpamNormal, nil, nil); !strings.Contains(s, "\r\nif header :contains \"X-Spam-Level\" \"******\" {") {
		t.Fatal(s)
	}
	if !ValidSpamLevel("", true) || ValidSpamLevel("", false) || !ValidSpamLevel(SpamOff, false) || ValidSpamLevel("max", true) {
		t.Fatal("levels")
	}
}
