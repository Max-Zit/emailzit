package mailconf

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	s := Settings{Hostname: "mail.example.com", MaxMessageMB: 25, DBName: "emailzit", CertFile: "/etc/emailzit/tls/mail.crt",
		KeyFile: "/etc/emailzit/tls/mail.key", Relay: "[192.168.1.5]:1025"}
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = string(f.Content)
	}
	main := got[PostfixMain]
	for _, want := range []string{"myhostname = mail.example.com", "message_size_limit = 26214400", "relayhost = [192.168.1.5]:1025",
		"smtpd_sasl_auth_enable = no", "reject_unauth_destination", "localsender.cf"} {
		if !strings.Contains(main, want) {
			t.Errorf("main.cf lacks %q", want)
		}
	}
	if strings.Contains(main, "permit_mynetworks") {
		t.Error("port 25 trusts mynetworks")
	}
	if !strings.Contains(got[PostfixMaster], "reject_sender_login_mismatch") || !strings.Contains(got[PostfixMaster], "smtpd_tls_wrappermode=yes") {
		t.Error("submission without sender check or 465")
	}
	if !strings.Contains(got[DovecotConf], "ssl = required") || !strings.Contains(got[DovecotConf], "mda_logins") {
		t.Error("dovecot.conf")
	}
	if !strings.Contains(got[PostfixMaps+"/localsender.cf"], "REJECT") {
		t.Error("localsender map")
	}
}

// Values that would break out of a configuration line are refused.
func TestRenderRefusesInjection(t *testing.T) {
	base := Settings{Hostname: "mail.example.com", MaxMessageMB: 25, DBName: "emailzit", CertFile: "/a", KeyFile: "/b"}
	for name, mod := range map[string]func(*Settings){
		"host newline": func(s *Settings) { s.Hostname = "mail.example.com\nrelayhost = evil" },
		"host space":   func(s *Settings) { s.Hostname = "mail example.com" },
		"relay":        func(s *Settings) { s.Relay = "evil.example.com" },
		"cert":         func(s *Settings) { s.CertFile = "/a b" },
		"db":           func(s *Settings) { s.DBName = "x; drop" },
		"size":         func(s *Settings) { s.MaxMessageMB = 0 },
		"policy":       func(s *Settings) { s.PolicySocket = "/abs/olute" },
	} {
		s := base
		mod(&s)
		if _, err := Render(s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
