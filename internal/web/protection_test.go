package web

import (
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

func TestOutboundSettings(t *testing.T) {
	m := defaultMail()
	if err := m.parseOutboundIPs("203.0.113.5  Mail2.Example.com\n\n2001:db8::5 mail3.example.com\n"); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if m.OutboundIPs[0].HELO != "mail2.example.com" || m.OutboundText() != "203.0.113.5 mail2.example.com\n2001:db8::5 mail3.example.com\n" {
		t.Fatalf("%+v", m.OutboundIPs)
	}
	for _, bad := range []string{"203.0.113.5", "203.0.113.5 a b", "nonsense mail.example.com", "127.0.0.1 mail.example.com", "203.0.113.5 mail"} {
		b := defaultMail()
		if err := b.parseOutboundIPs(bad); err == nil {
			if err = b.Validate(); err == nil {
				t.Errorf("accepted %q", bad)
			}
		}
	}
	n := defaultMail()
	n.NoticeTo = "a@example.com; B@Example.com"
	if err := n.Validate(); err != nil || n.NoticeTo != "a@example.com, b@example.com" {
		t.Fatalf("%q %v", n.NoticeTo, err)
	}
	n.NoticeTo = "not an address"
	if n.Validate() == nil {
		t.Fatal("invalid notice address accepted")
	}
}

func TestOutboundSPF(t *testing.T) {
	recs := withOutboundSPF(mailRecords(&store.Domain{Name: "example.com", Verified: true}, MailSettings{Hostname: "mail.example.com"}, nil), "203.0.113.5")
	var spf string
	for _, r := range recs {
		if r.Type == "TXT" && r.Name == "example.com" {
			spf = r.Value
		}
	}
	if spf != "v=spf1 mx ip4:203.0.113.5 ~all" {
		t.Fatalf("spf %q", spf)
	}
	if txtStatus(spf, []string{"v=spf1 mx ~all"}) == CheckOK {
		t.Fatal("a record without the own address counts as present")
	}
	if txtStatus(spf, []string{"v=spf1 mx include:_spf.example.net ip4:203.0.113.5 -all"}) != CheckOK {
		t.Fatal("a record with the address counts as missing")
	}
}
