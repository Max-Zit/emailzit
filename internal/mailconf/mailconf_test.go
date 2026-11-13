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

func TestRenderClamAV(t *testing.T) {
	s := Settings{Hostname: "mail.example.com", MaxMessageMB: 25, DBName: "emailzit", CertFile: "/a", KeyFile: "/b", Rspamd: true}
	has := func() bool {
		files, err := Render(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.Path == RspamdAntivirus {
				return strings.Contains(string(f.Content), `symbol = "CLAM_VIRUS"`)
			}
		}
		return false
	}
	if has() {
		t.Fatal("antivirus without ClamAV")
	}
	s.ClamAV = true
	if !has() {
		t.Fatal("no antivirus with ClamAV")
	}
}

func renderMap(t *testing.T, s Settings) map[string]string {
	t.Helper()
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = string(f.Content)
	}
	return got
}

func TestRenderProtection(t *testing.T) {
	s := Settings{Hostname: "mail.example.com", MaxMessageMB: 25, DBName: "emailzit", CertFile: "/a", KeyFile: "/b", Rspamd: true, ClamAV: true, Unbound: true}
	got := renderMap(t, s)
	mm := got[RspamdLocal+"/multimap.conf"]
	if !strings.Contains(mm, "EMAILZIT_RISKY_ATTACHMENT") || !strings.Contains(got[RspamdRiskyMap], "|exe|") || !strings.Contains(got[RspamdRiskyMap], "|docm|") {
		t.Errorf("risky attachments not refused:\n%s", mm)
	}
	if !strings.Contains(got[RspamdOverride+"/options.inc"], `nameserver = ["127.0.0.1:5335"]`) {
		t.Error("Rspamd does not use the local resolver")
	}
	if u := got[UnboundConf]; !strings.Contains(u, "127.0.0.1@5335") || strings.Contains(u, "@53\n") {
		t.Errorf("unbound.conf:\n%s", u)
	}
	if !strings.Contains(got[RspamdLocal+"/settings.conf"], "authenticated = true") || !strings.Contains(got[RspamdLocal+"/force_actions.conf"], "CLAM_VIRUS") {
		t.Error("outbound settings or virus refusal missing")
	}
	main, master := got[PostfixMain], got[PostfixMaster]
	if !strings.Contains(master, "postscreen") || !strings.Contains(main, "zen.spamhaus.org=127.0.0.[2..11]*3") {
		t.Error("postscreen missing")
	}
	if strings.Contains(main, "dane") || strings.Contains(main, "sender_dependent_default_transport_maps =") {
		t.Error("DANE or sender transports without being asked for")
	}
	fa := got[RspamdLocal+"/force_actions.conf"]
	if !strings.Contains(fa, "DMARC_POLICY_REJECT") || !strings.Contains(fa, "DMARC_POLICY_QUARANTINE") || !strings.Contains(fa, "!MAILLIST") {
		t.Errorf("forged senders not refused:\n%s", fa)
	}
	s.AllowRiskyAttachments = true
	s.AllowDMARCFailures = true
	got = renderMap(t, s)
	if strings.Contains(got[RspamdLocal+"/multimap.conf"], "EMAILZIT_RISKY_ATTACHMENT") {
		t.Error("attachments refused although allowed")
	}
	if strings.Contains(got[RspamdLocal+"/force_actions.conf"], "DMARC_POLICY_REJECT") {
		t.Error("DMARC failures refused although allowed")
	}
}

func TestRenderDANEAndOutbound(t *testing.T) {
	s := Settings{Hostname: "mail.example.com", MaxMessageMB: 25, DBName: "emailzit", CertFile: "/a", KeyFile: "/b", Unbound: true, SystemResolver: true,
		TLSPolicySocket: "emailzit/tlspolicy",
		OutboundIPs:     []OutboundIP{{Address: "203.0.113.5", HELO: "mail2.example.com", Present: true}, {Address: "2001:db8::5", HELO: "mail3.example.com"}}}
	got := renderMap(t, s)
	main, master := got[PostfixMain], got[PostfixMaster]
	for _, want := range []string{"smtp_tls_security_level = dane", "smtp_dns_support_level = dnssec", "smtp_tls_policy_maps = socketmap:unix:emailzit/tlspolicy:mtasts",
		"sender_dependent_default_transport_maps = proxy:pgsql:/etc/postfix/emailzit/sendertransport.cf"} {
		if !strings.Contains(main, want) {
			t.Errorf("main.cf lacks %q", want)
		}
	}
	tr := TransportName("203.0.113.5")
	if !strings.Contains(master, tr+" unix") || !strings.Contains(master, "smtp_bind_address=203.0.113.5") || !strings.Contains(master, "smtp_helo_name=mail2.example.com") {
		t.Errorf("outbound transport:\n%s", master)
	}
	if strings.Contains(master, "smtp_bind_address6=2001:db8::5") {
		t.Error("an address that is not on the server is bound")
	}
	if !strings.Contains(got[UnboundConf], "127.0.0.1@53") {
		t.Error("system resolver not on port 53")
	}
	// a smart host: no DANE, no MTA-STS map, no own addresses
	s.Relay = "[192.168.1.5]:1025"
	main = renderMap(t, s)[PostfixMain]
	if strings.Contains(main, "= dane") || strings.Contains(main, "smtp_tls_policy_maps") || strings.Contains(main, "sender_dependent_default_transport_maps =") {
		t.Error("smart host with DANE, MTA-STS or own addresses")
	}
	for _, bad := range []OutboundIP{{Address: "127.0.0.2", HELO: "a.example.com"}, {Address: "203.0.113.5", HELO: "x\nrelayhost = evil"}, {Address: "203.0.113.5 ", HELO: "a.example.com"}} {
		b := s
		b.OutboundIPs = []OutboundIP{bad}
		if _, err := Render(b); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
