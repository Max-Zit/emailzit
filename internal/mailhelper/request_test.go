package mailhelper

import "testing"

// The helper checks every request before it runs as root. A ban needs a real
// address; 0 minutes lifts the block, "all" lifts every block.
func TestValidateBan(t *testing.T) {
	cases := []struct {
		name    string
		r       Request
		wantErr bool
	}{
		{"block an address", Request{Action: ActionBan, IP: "203.0.113.5", Minutes: 60}, false},
		{"block an IPv6 address", Request{Action: ActionBan, IP: "2001:db8::5", Minutes: 60}, false},
		{"lift one address", Request{Action: ActionBan, IP: "203.0.113.5", Minutes: 0}, false},
		{"lift every block", Request{Action: ActionBan, IP: "all", Minutes: 0}, false},
		{"not an address", Request{Action: ActionBan, IP: "example.com", Minutes: 60}, true},
		{"the server itself", Request{Action: ActionBan, IP: "127.0.0.1", Minutes: 60}, true},
		{"longer than a week", Request{Action: ActionBan, IP: "203.0.113.5", Minutes: 10081}, true},
		{"negative time", Request{Action: ActionBan, IP: "203.0.113.5", Minutes: -1}, true},
		{"all with a time", Request{Action: ActionBan, IP: "all", Minutes: 60}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.r
			err := r.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate() = %v, want error: %v", err, c.wantErr)
			}
		})
	}
}

// Every action the helper answers has to get through Validate, or the
// panel's call is refused before the helper ever sees it. Found in the
// lab on 2026-11-18: "share" and "expunge" were dispatched by the helper
// and rejected by this check, so a shared folder and the nightly clean-up
// did nothing and the panel only said "the mail server did not take it".
func TestEveryActionGetsThroughTheCheck(t *testing.T) {
	ok := []struct {
		name string
		r    Request
	}{
		{ActionPing, Request{Action: ActionPing}},
		{ActionApply, Request{Action: ActionApply, Hostname: "mail.example.com", MaxMessageMB: 25}},
		{ActionCustomer, Request{Action: ActionCustomer, Customer: "5d26365a-3214-4a9a-8c66-c7b8acba3f13", UID: MinUID}},
		{ActionTrash, Request{Action: ActionTrash, Customer: "5d26365a-3214-4a9a-8c66-c7b8acba3f13", Domain: "example.com", Local: "ana"}},
		{ActionDKIM, Request{Action: ActionDKIM, Domain: "example.com"}}, // without a key: stop signing
		{ActionBan, Request{Action: ActionBan, IP: "203.0.113.5", Minutes: 60}},
		{ActionQueue, Request{Action: ActionQueue, Op: "list"}},
		{ActionStatus, Request{Action: ActionStatus}},
		{ActionNotice, Request{Action: ActionNotice, Domain: "example.com", Local: "ana", Subject: "quota", Body: "full"}},
		{ActionExpunge, Request{Action: ActionExpunge, JunkDays: 30, TrashDays: 14}},
		{ActionShare, Request{Action: ActionShare, Owner: "info@example.com", With: "ana@example.com", Folder: "INBOX", Rights: "write"}},
		{ActionShare + " (closing)", Request{Action: ActionShare, Owner: "info@example.com", With: "ana@example.com", Folder: "INBOX"}},
	}
	for _, c := range ok {
		t.Run(c.name, func(t *testing.T) {
			r := c.r
			if err := r.Validate(); err != nil {
				t.Errorf("a normal request was refused: %v", err)
			}
		})
	}

	bad := map[string]Request{
		"an action nobody knows":  {Action: "rm-rf"},
		"a share with one side":   {Action: ActionShare, Owner: "info@example.com", Folder: "INBOX", Rights: "read"},
		"a share with itself":     {Action: ActionShare, Owner: "info@example.com", With: "info@example.com", Folder: "INBOX", Rights: "read"},
		"a folder that is a flag": {Action: ActionShare, Owner: "info@example.com", With: "ana@example.com", Folder: "-u root", Rights: "read"},
		"a folder with a quote":   {Action: ActionShare, Owner: "info@example.com", With: "ana@example.com", Folder: `In"box`, Rights: "read"},
		"rights nobody knows":     {Action: ActionShare, Owner: "info@example.com", With: "ana@example.com", Folder: "INBOX", Rights: "admin"},
		"a span of ten years":     {Action: ActionExpunge, JunkDays: 4000},
		"a negative span":         {Action: ActionExpunge, TrashDays: -1},
	}
	for name, r := range bad {
		t.Run(name, func(t *testing.T) {
			if err := r.Validate(); err == nil {
				t.Error("the request was accepted")
			}
		})
	}
}
