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
	// The list of the shared folders belongs to the customer (two levels
	// above a mailbox home). One file for the whole server would have to
	// be written by root and would show every customer the addresses of
	// the others.
	if !strings.Contains(got[DovecotConf], "path = %{home}/../../shared-mailboxes") {
		t.Error("the list of shared mailboxes is not per customer")
	}
	for _, want := range []string{"acl_driver = vfile", "imap_acl = yes", "namespace shared {", "prefix = shared/$user/"} {
		if !strings.Contains(got[DovecotConf], want) {
			t.Errorf("dovecot.conf lacks %q", want)
		}
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

// A route sends the mail of one recipient domain another way: directly
// past the smart host, over a relay without a login, or over a relay this
// server signs in at. The receiver's own refusal (a provider that blocks
// the whole address range) is nothing the server can mend, so the way out
// has to be changeable per domain.
func TestRenderRoutes(t *testing.T) {
	base := Settings{Hostname: "mail.example.com", MaxMessageMB: 25, DBName: "emailzit",
		CertFile: "/etc/emailzit/tls/mail.crt", KeyFile: "/etc/emailzit/tls/mail.key"}

	t.Run("every kind of route is written", func(t *testing.T) {
		s := base
		s.Relay, s.RelayUser, s.RelayPassword = "[smart.example.net]:587", "smart", "pw"
		s.Routes = []Route{
			{Domain: "hotmail.com", Host: "relay.example.net", Port: 587, User: "me", Password: "secret"},
			{Domain: "example.org"},
			{Domain: "intern.example.com", Host: "10.0.0.5", Port: 25},
		}
		files, err := Render(s)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]File{}
		for _, f := range files {
			got[f.Path] = f
		}
		routes := string(got[RouteFile].Content)
		for _, want := range []string{
			"hotmail.com ezrelay:[relay.example.net]:587",
			"example.org ezdirect:example.org",
			"intern.example.com ezdirect:[10.0.0.5]:25",
		} {
			if !strings.Contains(routes, want) {
				t.Errorf("the routes file lacks %q:\n%s", want, routes)
			}
		}
		if got[RouteFile].Mode != 0o644 {
			t.Errorf("the routes file has mode %o", got[RouteFile].Mode)
		}
		pw := string(got[RoutePasswordFile].Content)
		if !strings.Contains(pw, "[relay.example.net]:587 me:secret") {
			t.Errorf("the login of the route is missing:\n%s", pw)
		}
		if strings.Contains(pw, "10.0.0.5") || strings.Contains(pw, "example.org") {
			t.Errorf("a route without a login has one:\n%s", pw)
		}
		if got[RoutePasswordFile].Mode != 0o600 {
			t.Errorf("the logins of the routes are readable by others (mode %o)", got[RoutePasswordFile].Mode)
		}
		if !strings.Contains(string(got[PostfixMain].Content), "transport_maps = proxy:texthash:"+RouteFile+",") {
			t.Error("main.cf does not read the routes first")
		}
		master := string(got[PostfixMaster].Content)
		for _, want := range []string{"ezdirect  unix", "ezrelay  unix", "-o smtp_sasl_password_maps=texthash:" + RoutePasswordFile,
			"-o smtp_tls_security_level=encrypt", "-o relayhost="} {
			if !strings.Contains(master, want) {
				t.Errorf("master.cf lacks %q", want)
			}
		}
		// the way out of a route never carries the smart host's login
		direct := master[strings.Index(master, "ezdirect  unix"):strings.Index(master, "ezrelay  unix")]
		if !strings.Contains(direct, "-o smtp_sasl_auth_enable=no") {
			t.Errorf("the direct transport may sign in:\n%s", direct)
		}
	})

	t.Run("both files are written without a single route", func(t *testing.T) {
		files, err := Render(base)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, f := range files {
			seen[f.Path] = true
		}
		if !seen[RouteFile] || !seen[RoutePasswordFile] {
			t.Error("the configuration names a file that is not written")
		}
	})

	t.Run("a route that would break a line is refused", func(t *testing.T) {
		for name, r := range map[string]Route{
			"domain with a space":   {Domain: "hot mail.com"},
			"domain with a newline": {Domain: "hotmail.com\nexample.org relay:[evil]:25"},
			"relay with a quote":    {Domain: "hotmail.com", Host: "a\"b", Port: 25},
			"port out of range":     {Domain: "hotmail.com", Host: "relay.example.net", Port: 70000},
			"login without relay":   {Domain: "hotmail.com", User: "me", Password: "pw"},
			"login without pass":    {Domain: "hotmail.com", Host: "relay.example.net", Port: 587, User: "me"},
			"password with newline": {Domain: "hotmail.com", Host: "relay.example.net", Port: 587, User: "me", Password: "a\nb"},
			"login with a colon":    {Domain: "hotmail.com", Host: "relay.example.net", Port: 587, User: "a:b", Password: "pw"},
		} {
			s := base
			s.Routes = []Route{r}
			if _, err := Render(s); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}
	})

	t.Run("the same domain twice is refused", func(t *testing.T) {
		s := base
		s.Routes = []Route{{Domain: "hotmail.com"}, {Domain: "hotmail.com", Host: "relay.example.net", Port: 25}}
		if _, err := Render(s); err == nil {
			t.Error("two routes for one domain were accepted")
		}
	})
}
