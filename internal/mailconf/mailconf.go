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
	"embed"
	"errors"
	"fmt"
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
	// PolicySocket is the EmailZit policy service (sending limits);
	// empty = none yet.
	PolicySocket string // relative to the queue directory, e.g. emailzit/policy
	// Rspamd is installed: milter, DKIM signing, spam to Junk.
	Rspamd bool
}

// File is one rendered file.
type File struct {
	Path    string
	Mode    uint32
	Content []byte
}

var (
	hostRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	pathRE  = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	relayRE = regexp.MustCompile(`^\[[a-z0-9.:-]+\](:[0-9]{1,5})?$`)
	dbRE    = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	// relative to the Postfix queue directory (smtpd runs chrooted there)
	relPathRE = regexp.MustCompile(`^[a-z]+/[a-z-]+$`)
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
	case s.PolicySocket != "" && !relPathRE.MatchString(s.PolicySocket):
		return errors.New("invalid policy socket")
	}
	return nil
}

// Postfix and Dovecot configuration files.
const (
	PostfixMain   = "/etc/postfix/main.cf"
	PostfixMaster = "/etc/postfix/master.cf"
	PostfixMaps   = "/etc/postfix/emailzit"
	DovecotConf   = "/etc/dovecot/dovecot.conf"
)

// Render returns every file for the settings.
func Render(s Settings) ([]File, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data := struct {
		Settings
		MaxBytes int
	}{s, s.MaxMessageMB << 20}
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
		// port 25: nobody may use a domain of this server as sender without
		// signing in (on submission); the lookup key is the sender's domain
		{"localsender", `SELECT 'REJECT Sign in to send from this domain' FROM mta_domains WHERE name = '%s'`},
	} {
		var b bytes.Buffer
		fmt.Fprintf(&b, "# EmailZit: written by the root helper; changes are overwritten.\nhosts = unix:/var/run/postgresql\nuser = postfix\npassword =\ndbname = %s\nquery = %s\n", s.DBName, m.query)
		// postfix reads them as root before dropping privileges, 0640
		out = append(out, File{Path: PostfixMaps + "/" + m.name + ".cf", Mode: 0o640, Content: b.Bytes()})
	}
	if s.Rspamd {
		rf, err := rspamdFiles()
		if err != nil {
			return nil, err
		}
		out = append(out, rf...)
	}
	return out, nil
}

func render(name string, data any) ([]byte, error) {
	t, err := template.New(name).Option("missingkey=error").ParseFS(tmplFS, "templates/"+name)
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
	RspamdLocal   = "/etc/rspamd/local.d"
	RspamdDKIM    = "/etc/rspamd/emailzit/dkim"
	RspamdDKIMMap = "/etc/rspamd/emailzit/dkim_selectors.map"
	SpamSieve     = "/etc/dovecot/sieve/spam.sieve"
)

func rspamdFiles() ([]File, error) {
	names := []string{"dkim_signing.conf", "arc.conf", "redis.conf", "actions.conf", "milter_headers.conf", "worker-proxy.inc", "worker-controller.inc", "options.inc"}
	var out []File
	for _, n := range names {
		b, err := tmplFS.ReadFile("templates/rspamd/" + n)
		if err != nil {
			return nil, err
		}
		out = append(out, File{Path: RspamdLocal + "/" + n, Mode: 0o644, Content: b})
	}
	b, err := tmplFS.ReadFile("templates/sieve/spam.sieve")
	if err != nil {
		return nil, err
	}
	return append(out, File{Path: SpamSieve, Mode: 0o644, Content: b}), nil
}
