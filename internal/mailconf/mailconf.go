// Package mailconf renders the configuration of the mail software EmailZit
// runs (Postfix, Dovecot). The files hold only server-wide settings: what a
// customer changes lives in PostgreSQL, which Postfix and Dovecot read
// through views. So no customer input ever reaches a configuration file.
//
// The root helper writes the files, checks them with the programs' own
// tools and reloads the services; on an error it puts the old files back.
package mailconf

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"text/template"
)

//go:embed templates/*
var tmplFS embed.FS

// Settings are the values the templates use. They are validated before
// rendering, because they end up in configuration files.
type Settings struct {
	Hostname     string // mail.example.com
	MaxMessageMB int
	DBName       string // emailzit
	CertFile     string // full chain of the mail host name
	KeyFile      string
	// Relay sends all outgoing mail through this host ([host]:port);
	// empty = deliver directly (lab: Mailpit).
	Relay string
	// RelayUser and RelayPassword sign in at the relay (texthash file, root
	// only, TLS required).
	RelayUser, RelayPassword string
	// PolicySocket is the EmailZit policy service (sending limits);
	// empty = none yet.
	PolicySocket string // relative to the queue directory, e.g. emailzit/policy
	// AuthPolicyToken switches on the brute-force guard of the panel for
	// Dovecot sign-ins (hex token, also the hash nonce).
	AuthPolicyToken string
	// Rspamd is installed: milter, DKIM signing, spam to Junk.
	Rspamd bool
	// ClamAV is installed and switched on: Rspamd sends every message to it.
	ClamAV bool
	// IPv4Only: mail to other servers goes over IPv4 only (the server has
	// IPv6 but its address has no PTR record; big receivers refuse such mail).
	IPv4Only bool
	// Unbound is installed: a local, validating DNS resolver on
	// 127.0.0.1:5335 for Rspamd (block lists refuse queries that come
	// through big public resolvers).
	Unbound bool
	// SystemResolver: Unbound also answers on 127.0.0.1:53 and the server
	// uses it (no other DNS server on port 53, such as HostZit's). Then
	// Postfix sees DNSSEC-validated answers and checks DANE records of the
	// servers it sends to.
	SystemResolver bool
	// AllowRiskyAttachments switches off the refusal of programs, scripts
	// and macro documents as attachments (on by default).
	AllowRiskyAttachments bool
	// TLSPolicySocket is EmailZit's MTA-STS lookup for outgoing mail
	// (socketmap, relative to the queue directory); empty = none.
	TLSPolicySocket string
	// OutboundIPs are extra addresses for outgoing mail, each with its own
	// host name (HELO, PTR); customers are assigned to one.
	OutboundIPs []OutboundIP
}

// OutboundIP is an extra sending address.
type OutboundIP struct {
	Address string // 203.0.113.5 or 2001:db8::5
	HELO    string // mail2.example.com (its PTR name)
	// Present: the address is configured on this server; otherwise the
	// transport sends from the default address (mail keeps flowing).
	Present bool
}

// Transport is the Postfix service name of an outbound address (stable,
// also computed by the database view mta_sender_transport).
func (o OutboundIP) Transport() string { return TransportName(o.Address) }

// TransportName is "ezo" + the first 10 hex digits of SHA-256 of the
// address (same as the view in migration 015).
func TransportName(addr string) string {
	h := sha256.Sum256([]byte(addr))
	return "ezo" + hex.EncodeToString(h[:])[:10]
}

// IPv6 tells whether the address is an IPv6 address.
func (o OutboundIP) IPv6() bool { return strings.Contains(o.Address, ":") }

// DANE: outgoing mail checks DANE records (needs the system resolver and
// direct delivery).
func (s *Settings) DANE() bool { return s.SystemResolver && s.Relay == "" }

// File is one rendered file.
type File struct {
	Path    string
	Mode    uint32
	Content []byte
}

var (
	hostRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	pathRE      = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	relayRE     = regexp.MustCompile(`^\[[a-z0-9.:-]+\](:[0-9]{1,5})?$`)
	relayCredRE = regexp.MustCompile(`^[^\s:]{1,256}$`)
	dbRE        = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	// relative to the Postfix queue directory (smtpd runs chrooted there)
	relPathRE = regexp.MustCompile(`^[a-z]+/[a-z-]+$`)
	tokenRE   = regexp.MustCompile(`^[0-9a-f]{32,128}$`)
)

// Validate checks every value that goes into a file.
func (s *Settings) Validate() error {
	switch {
	case !hostRE.MatchString(s.Hostname) || len(s.Hostname) > 253:
		return errors.New("invalid host name")
	case s.MaxMessageMB < 1 || s.MaxMessageMB > 200:
		return errors.New("invalid message size")
	case !dbRE.MatchString(s.DBName):
		return errors.New("invalid database name")
	case !pathRE.MatchString(s.CertFile) || !pathRE.MatchString(s.KeyFile):
		return errors.New("invalid certificate path")
	case s.Relay != "" && !relayRE.MatchString(s.Relay):
		return errors.New("invalid relay host")
	case s.RelayUser != "" && (s.Relay == "" || !relayCredRE.MatchString(s.RelayUser) || s.RelayPassword == "" || len(s.RelayPassword) > 256 || strings.ContainsAny(s.RelayPassword, "\r\n\x00")):
		return errors.New("invalid relay login")
	case s.AuthPolicyToken != "" && !tokenRE.MatchString(s.AuthPolicyToken):
		return errors.New("invalid auth policy token")
	case s.PolicySocket != "" && !relPathRE.MatchString(s.PolicySocket):
		return errors.New("invalid policy socket")
	case s.TLSPolicySocket != "" && !relPathRE.MatchString(s.TLSPolicySocket):
		return errors.New("invalid TLS policy socket")
	case len(s.OutboundIPs) > 64:
		return errors.New("too many outbound addresses")
	}
	seen := map[string]bool{}
	for _, o := range s.OutboundIPs {
		ip, err := netip.ParseAddr(o.Address)
		if err != nil || ip.Zone() != "" || ip.String() != o.Address || !ip.IsGlobalUnicast() || seen[o.Address] {
			return errors.New("invalid outbound address")
		}
		if !hostRE.MatchString(o.HELO) || len(o.HELO) > 253 {
			return errors.New("invalid host name of an outbound address")
		}
		seen[o.Address] = true
	}
	return nil
}

// Postfix and Dovecot configuration files.
const (
	PostfixMain   = "/etc/postfix/main.cf"
	PostfixMaster = "/etc/postfix/master.cf"
	PostfixMaps   = "/etc/postfix/emailzit"
	// RelayPasswordFile holds the smart host login (root only).
	RelayPasswordFile = "/etc/postfix/emailzit/relay_passwd" // #nosec G101 -- a file path, not a password
	// PostfixOpenSSL holds the TLS settings main.cf cannot express.
	PostfixOpenSSL = "/etc/postfix/emailzit/openssl.cnf"
	DovecotConf    = "/etc/dovecot/dovecot.conf"
)

// Render returns every file for the settings.
func Render(s Settings) ([]File, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data := struct {
		Settings
		MaxBytes          int
		RelayPasswordFile string
		RelayWrapper      bool // port 465: TLS from the start
		OpenSSLConf       string
		DANE              bool
		SenderTransports  bool // extra outbound addresses (only without a smart host)
	}{s, s.MaxMessageMB << 20, RelayPasswordFile, strings.HasSuffix(s.Relay, ":465"), PostfixOpenSSL, s.DANE(), len(s.OutboundIPs) > 0 && s.Relay == ""}
	out := []File{
		{Path: PostfixMain, Mode: 0o644, Content: nil},
		{Path: PostfixMaster, Mode: 0o644},
		{Path: DovecotConf, Mode: 0o644},
	}
	names := []string{"main.cf", "master.cf", "dovecot.conf"}
	for i, n := range names {
		b, err := render(n, data)
		if err != nil {
			return nil, err
		}
		out[i].Content = b
	}
	// lookup tables: read-only role "postfix" over the local socket
	for _, m := range []struct{ name, query string }{
		{"domains", `SELECT 1 FROM mta_domains WHERE name = '%s'`},
		{"mailboxes", `SELECT 1 FROM mta_mailboxes WHERE address = '%s'`},
		{"aliases", `SELECT destinations FROM mta_aliases WHERE address = '%s'`},
		{"senders", `SELECT login FROM mta_sender_logins WHERE sender = '%s'`},
		{"transport", `SELECT transport FROM mta_transport WHERE address = '%s'`},
		// port 25: nobody may use a domain of this server as sender without
		// signing in (on submission); the lookup key is the sender's domain
		{"localsender", `SELECT 'REJECT Sign in to send from this domain' FROM mta_domains WHERE name = '%s'`},
		// extra outbound address of the sender domain's customer (%d: the domain
		// of the key, which is an address or @domain)
		{"sendertransport", `SELECT transport FROM mta_sender_transport WHERE domain = '%d'`},
	} {
		var b bytes.Buffer
		fmt.Fprintf(&b, "# EmailZit: written by the root helper; changes are overwritten.\nhosts = unix:/var/run/postgresql\nuser = postfix\npassword =\ndbname = %s\nquery = %s\n", s.DBName, m.query)
		// postfix reads them as root before dropping privileges, 0640
		out = append(out, File{Path: PostfixMaps + "/" + m.name + ".cf", Mode: 0o640, Content: b.Bytes()})
	}
	out = append(out, File{Path: PostfixOpenSSL, Mode: 0o644, Content: []byte(postfixOpenSSL)})
	if s.RelayUser != "" {
		// the relay's login, readable by root only; Postfix reads it before
		// dropping privileges
		out = append(out, File{Path: RelayPasswordFile, Mode: 0o600, Content: []byte("# EmailZit: written by the root helper.\n" + s.Relay + " " + s.RelayUser + ":" + s.RelayPassword + "\n")})
	}
	if s.Unbound {
		b, err := render("unbound.conf", data)
		if err != nil {
			return nil, err
		}
		out = append(out, File{Path: UnboundConf, Mode: 0o644, Content: b})
	}
	if s.Rspamd {
		rf, err := rspamdFiles(s)
		if err != nil {
			return nil, err
		}
		out = append(out, rf...)
	}
	return out, nil
}

func render(name string, data any) ([]byte, error) {
	t, err := template.New(path.Base(name)).Option("missingkey=error").ParseFS(tmplFS, "templates/"+name)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}
	if strings.Contains(b.String(), "<no value>") {
		return nil, fmt.Errorf("%s: missing value", name)
	}
	return b.Bytes(), nil
}

// Rspamd and Sieve files (written when Settings.Rspamd is set).
const (
	RspamdLocal    = "/etc/rspamd/local.d"
	RspamdOverride = "/etc/rspamd/override.d"
	// RspamdAntivirus switches the ClamAV scan on (removed when it is off).
	RspamdAntivirus = "/etc/rspamd/local.d/antivirus.conf"
	RspamdDKIM      = "/etc/rspamd/emailzit/dkim"
	RspamdDKIMMap   = "/etc/rspamd/emailzit/dkim_selectors.map"
	// RspamdLocalDomains lists the mail domains of this server as regular
	// expressions (written by the mail helper), for the display name check.
	RspamdLocalDomains = "/etc/rspamd/emailzit/local_domains.map"
	// RspamdRiskyMap holds the refused attachment types (one regular expression).
	RspamdRiskyMap = "/etc/rspamd/emailzit/risky_extensions.map"
	// UnboundConf is the local DNS resolver's settings.
	UnboundConf = "/etc/unbound/unbound.conf.d/emailzit.conf"
	// MailboxSpamSieve is each mailbox's spam script (written by the mail
	// helper from the mailbox's and the customer's spam settings),
	// relative to the mail home.
	MailboxSpamSieve = ".emailzit/spam.sieve"
)

// rspamdFiles are written whenever Rspamd is installed; their contents
// follow the settings, so switching something off rewrites the file
// instead of leaving an old one behind (antivirus.conf alone is removed).
func rspamdFiles(s Settings) ([]File, error) {
	names := []string{"dkim_signing.conf", "arc.conf", "redis.conf", "actions.conf", "milter_headers.conf", "worker-proxy.inc", "worker-controller.inc", "options.inc",
		"multimap.conf", "composites.conf", "settings.conf", "force_actions.conf", "phishing.conf"}
	data := struct {
		Settings
		RiskyMap        string
		LocalDomainsMap string
	}{s, RspamdRiskyMap, RspamdLocalDomains}
	var out []File
	for _, n := range names {
		b, err := render("rspamd/"+n, data)
		if err != nil {
			return nil, err
		}
		dir := RspamdLocal
		if n == "options.inc" {
			dir = RspamdOverride // local.d would keep Rspamd's private networks as local
		}
		out = append(out, File{Path: dir + "/" + n, Mode: 0o644, Content: b})
	}
	out = append(out, File{Path: RspamdRiskyMap, Mode: 0o644,
		Content: []byte("# EmailZit: risky attachment types (written by the root helper)\n/^(" + strings.Join(RiskyExtensions, "|") + ")$/i\n")})
	if s.ClamAV {
		for _, n := range []string{"antivirus.conf", "antivirus_group.conf"} {
			b, err := render("rspamd/"+n, data)
			if err != nil {
				return nil, err
			}
			out = append(out, File{Path: RspamdLocal + "/" + n, Mode: 0o644, Content: b})
		}
	}
	return out, nil
}

// RiskyExtensions are refused as attachments (also inside archives):
// programs, scripts, shortcuts, disk images and Office files with macros.
// Nobody needs to mail these; they are how most ransomware arrives.
var RiskyExtensions = []string{
	"ade", "adp", "app", "application", "appx", "appxbundle", "bas", "bat", "chm", "cmd", "com", "cpl", "diagcab", "dll",
	"docm", "dotm", "exe", "gadget", "hlp", "hta", "img", "inf", "ins", "iso", "isp", "jar", "js", "jse", "lnk", "mde", "msc",
	"msi", "msix", "msixbundle", "msp", "mst", "pif", "potm", "ppam", "ppsm", "pptm", "ps1", "ps1xml", "ps2", "psc1", "psd1", "psm1",
	"reg", "scf", "scr", "sct", "settingcontent-ms", "shb", "shs", "sldm", "url", "vb", "vbe", "vbs", "vhd", "vhdx", "ws", "wsc",
	"wsf", "wsh", "xlam", "xll", "xlsm", "xltm",
}

// postfixOpenSSL is read by Postfix (tls_config_file, section "postfix"):
// TLS 1.2 handshakes sign only with SHA-2 (testssl.sh flags SHA-1/SHA-224).
const postfixOpenSSL = `# EmailZit: written by the root helper; changes are overwritten.
postfix = postfix_settings

[postfix_settings]
ssl_conf = postfix_ssl

[postfix_ssl]
system_default = postfix_tls

[postfix_tls]
SignatureAlgorithms = ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA+SHA256:RSA+SHA384:RSA+SHA512
`
