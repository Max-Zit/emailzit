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

func TestRenderRelay(t *testing.T) {
	s := Settings{Hostname: "mail.example.com", MaxMessageMB: 25, DBName: "emailzit", CertFile: "/a", KeyFile: "/b",
		Relay: "[smtp.provider.example]:465", RelayUser: "acct@provider.example", RelayPassword: "p w:#x"}
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	var main, cred string
	var mode uint32
	for _, f := range files {
		switch f.Path {
		case PostfixMain:
			main = string(f.Content)
		case RelayPasswordFile:
			cred, mode = string(f.Content), f.Mode
		}
	}
	for _, want := range []string{"relayhost = [smtp.provider.example]:465", "smtp_sasl_password_maps = texthash:" + RelayPasswordFile, "smtp_tls_security_level = encrypt", "smtp_tls_wrappermode = yes"} {
		if !strings.Contains(main, want) {
			t.Fatalf("main.cf misses %q", want)
		}
	}
	if mode != 0o600 || !strings.Contains(cred, "\n[smtp.provider.example]:465 acct@provider.example:p w:#x\n") {
		t.Fatalf("credentials %o %q", mode, cred)
	}
	// without a login: no SASL, no file
	s.RelayUser, s.RelayPassword = "", ""
	files, _ = Render(s)
	for _, f := range files {
		if f.Path == RelayPasswordFile || (f.Path == PostfixMain && strings.Contains(string(f.Content), "smtp_sasl_auth_enable")) {
			t.Fatal("login written without one")
		}
	}
	for _, bad := range []Settings{
		{RelayUser: "a b", RelayPassword: "x"},
		{RelayUser: "a", RelayPassword: "x\nrelayhost = evil"},
		{RelayUser: "a", RelayPassword: ""},
	} {
		b := s
		b.RelayUser, b.RelayPassword = bad.RelayUser, bad.RelayPassword
		if _, err := Render(b); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
