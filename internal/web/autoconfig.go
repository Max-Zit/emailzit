package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"text/template"

	"github.com/max-zit/emailzit/internal/store"
)

// Mail programs find their settings by themselves:
//   - Thunderbird and others: GET /.well-known/autoconfig/mail/config-v1.1.xml
//     and /mail/config-v1.1.xml (autoconfig.<domain>),
//   - Outlook: POST /autodiscover/autodiscover.xml (autodiscover.<domain>),
//   - iPhone, iPad, Mac: a configuration profile from the mail user's page.
// They need no sign-in and tell nothing but the server's host name, and only
// for domains of this server.

func (s *Server) autoconfigRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/autoconfig/mail/config-v1.1.xml", s.handleAutoconfig)
	mux.HandleFunc("GET /mail/config-v1.1.xml", s.handleAutoconfig)
	mux.HandleFunc("GET /.well-known/mta-sts.txt", s.handleMTASTS)
	mux.HandleFunc("POST /autodiscover/autodiscover.xml", s.handleAutodiscover)
	mux.HandleFunc("POST /Autodiscover/Autodiscover.xml", s.handleAutodiscover)
}

// domainOfAddress returns the domain of a known address ("" if unknown).
func (s *Server) knownDomain(r *http.Request, addr string) (string, string) {
	a, err := store.ParseAddress(addr)
	if err != nil {
		return "", ""
	}
	_, dom, _ := strings.Cut(a, "@")
	d, err := s.store.DomainByName(r.Context(), store.Staff, dom)
	if err != nil || !d.Verified || d.Disabled {
		return "", ""
	}
	return a, d.Name
}

var autoconfigTmpl = template.Must(template.New("").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{{.Domain}}">
    <domain>{{.Domain}}</domain>
    <displayName>{{.Domain}}</displayName>
    <incomingServer type="imap">
      <hostname>{{.Host}}</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>{{.Host}}</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>{{.Host}}</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
`))

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (s *Server) handleAutoconfig(w http.ResponseWriter, r *http.Request) {
	host := s.MailConfig(r.Context()).Hostname
	addr := r.URL.Query().Get("emailaddress")
	dom := ""
	if addr != "" {
		_, dom = s.knownDomain(r, addr)
	} else if h, _, _ := strings.Cut(r.Host, ":"); strings.HasPrefix(h, "autoconfig.") {
		if d, err := s.store.DomainByName(r.Context(), store.Staff, strings.TrimPrefix(h, "autoconfig.")); err == nil && d.Verified {
			dom = d.Name
		}
	}
	if host == "" || dom == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	_ = autoconfigTmpl.Execute(w, map[string]string{"Domain": xmlEscape(dom), "Host": xmlEscape(host)})
}

var autodiscoverTmpl = template.Must(template.New("").Parse(`<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>{{.Host}}</Server>
        <Port>993</Port>
        <LoginName>{{.Addr}}</LoginName>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>{{.Host}}</Server>
        <Port>465</Port>
        <LoginName>{{.Addr}}</LoginName>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
        <UsePOPAuth>off</UsePOPAuth>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
`))

func (s *Server) handleAutodiscover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Request struct {
			EMailAddress string `xml:"EMailAddress"`
		} `xml:"Request"`
	}
	_ = xml.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req)
	host := s.MailConfig(r.Context()).Hostname
	addr, dom := s.knownDomain(r, req.Request.EMailAddress)
	if host == "" || dom == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	_ = autodiscoverTmpl.Execute(w, map[string]string{"Addr": xmlEscape(addr), "Host": xmlEscape(host)})
}

var mobileconfigTmpl = template.Must(template.New("").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>EmailAccountDescription</key><string>{{.Addr}}</string>
      <key>EmailAccountName</key><string>{{.Name}}</string>
      <key>EmailAccountType</key><string>EmailTypeIMAP</string>
      <key>EmailAddress</key><string>{{.Addr}}</string>
      <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>IncomingMailServerHostName</key><string>{{.Host}}</string>
      <key>IncomingMailServerPortNumber</key><integer>993</integer>
      <key>IncomingMailServerUseSSL</key><true/>
      <key>IncomingMailServerUsername</key><string>{{.Addr}}</string>
      <key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>OutgoingMailServerHostName</key><string>{{.Host}}</string>
      <key>OutgoingMailServerPortNumber</key><integer>465</integer>
      <key>OutgoingMailServerUseSSL</key><true/>
      <key>OutgoingMailServerUsername</key><string>{{.Addr}}</string>
      <key>OutgoingPasswordSameAsIncomingPassword</key><true/>
      <key>PayloadDescription</key><string>E-mail</string>
      <key>PayloadDisplayName</key><string>{{.Addr}}</string>
      <key>PayloadIdentifier</key><string>com.maxzit.emailzit.{{.ID}}.mail</string>
      <key>PayloadType</key><string>com.apple.mail.managed</string>
      <key>PayloadUUID</key><string>{{.UUID1}}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>{{.Addr}}</string>
  <key>PayloadIdentifier</key><string>com.maxzit.emailzit.{{.ID}}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{{.UUID2}}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`))

// handleMobileconfig gives an Apple configuration profile (without a
// password: the device asks for an app password when the profile is
// installed).
func (s *Server) handleMobileconfig(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	host := s.MailConfig(r.Context()).Hostname
	if host == "" {
		s.notFound(w, r)
		return
	}
	name := m.DisplayName
	if name == "" {
		name = m.Address
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(m.Address, "@", "-at-")+`.mobileconfig"`)
	_ = mobileconfigTmpl.Execute(w, map[string]string{"Addr": xmlEscape(m.Address), "Name": xmlEscape(name), "Host": xmlEscape(host),
		"ID": strings.ReplaceAll(m.ID, "-", ""), "UUID1": strings.ToUpper(store.NewID()), "UUID2": strings.ToUpper(store.NewID())})
}

// handleMTASTS serves the MTA-STS policy of a domain at
// https://mta-sts.<domain>/.well-known/mta-sts.txt: other servers then
// deliver to this server only over verified TLS. The mode stays "testing"
// until the certificate of the host name is one they trust.
func (s *Server) handleMTASTS(w http.ResponseWriter, r *http.Request) {
	h, _, _ := strings.Cut(r.Host, ":")
	host := s.MailConfig(r.Context()).Hostname
	d, err := s.store.DomainByName(r.Context(), store.Staff, strings.TrimPrefix(h, "mta-sts."))
	if host == "" || !strings.HasPrefix(h, "mta-sts.") || err != nil || !d.Verified {
		http.NotFound(w, r)
		return
	}
	mode := "testing"
	if c := readMailCert(); !c.Missing && !c.SelfSign && c.Days > 0 {
		mode = "enforce"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "version: STSv1\r\nmode: "+mode+"\r\nmx: "+host+"\r\nmax_age: 604800\r\n")
}

// mtaSTSID changes when the policy changes (it depends on the host name and
// the mode).
func mtaSTSID(host string) string {
	h := sha256.Sum256([]byte(host))
	return hex.EncodeToString(h[:6])
}
