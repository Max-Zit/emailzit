package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/sieve"
	"github.com/max-zit/emailzit/internal/store"
)

// The admin and customer panels share these pages. scopeOf decides what a
// login may see: staff everything, a customer login only its customer.
// Every store call gets the scope, so the ownership check lives in the
// store queries, never in the templates.

func scopeOf(r *http.Request) store.Scope {
	u := userFrom(r)
	if u.IsStaff() {
		return store.Staff
	}
	return store.Scope{CustomerID: u.CustomerID}
}

// mailErr turns store errors of mail objects into messages.
func mailErr(err error) string {
	switch {
	case errors.Is(err, store.ErrLimit):
		if s := err.Error(); s != store.ErrLimit.Error() {
			return strings.Replace(s, store.ErrLimit.Error(), "The limit of the package is reached", 1)
		}
		return "The limit of the package is reached."
	case errors.Is(err, store.ErrInactive):
		return "The customer is suspended or terminated; nothing can be added."
	case errors.Is(err, store.ErrConflict):
		return "This address or name is already used."
	}
	return storeErr(err)
}

// ---- mail server settings

const settingMail = "mail"

// MailSettings are the server-wide mail settings.
type MailSettings struct {
	// relayPassword is the smart host's password in plain text, only while
	// the configuration is handed to the helper.
	relayPassword string
	// Hostname is the server's mail name (HELO, certificates, what mail
	// programs connect to), e.g. mail.example.com.
	Hostname string `json:"hostname"`
	// RequireVerification: a customer's new domain receives mail only
	// after a DNS TXT record proves the customer controls it (shared
	// servers; staff can verify by hand).
	RequireVerification bool `json:"require_verification"`
	// Dedicated: the server belongs to one customer (the customer panel is
	// the main view, domains need no verification).
	Dedicated bool `json:"dedicated"`
	// MaxMessageMB is the largest message accepted and sent.
	MaxMessageMB int `json:"max_message_mb"`
	// AllowPrivateImports lets mail be imported from servers in private
	// networks (company servers, test labs); off on hosting servers.
	AllowPrivateImports bool `json:"allow_private_imports"`
	// ClamAV scans every message for viruses (installed by the helper when
	// switched on; needs about 1 GB of memory).
	ClamAV bool `json:"clamav,omitempty"`
	// IPv4Only sends mail to other servers over IPv4 only (for a server
	// whose IPv6 address has no PTR record at the provider).
	IPv4Only bool `json:"ipv4_only,omitempty"`
	// RelayHost sends all outgoing mail through the provider's smart host
	// (host or host:port; 587 when no port is given); empty = deliver directly.
	RelayHost string `json:"relay_host,omitempty"`
	RelayUser string `json:"relay_user,omitempty"`
	// RelayPassword is sealed with the server key.
	RelayPassword string `json:"relay_password,omitempty"`
}

func defaultMail() MailSettings {
	return MailSettings{RequireVerification: true, MaxMessageMB: 50}
}

// Validate checks the settings.
func (m *MailSettings) Validate() error {
	m.Hostname = strings.TrimSpace(strings.ToLower(m.Hostname))
	if m.Hostname != "" {
		h, err := store.NormalizeDomain(m.Hostname)
		if err != nil {
			return errors.New("the host name must be a full name such as mail.example.com")
		}
		m.Hostname = h
	}
	if m.MaxMessageMB < 1 || m.MaxMessageMB > 200 {
		return errors.New("the largest message must be 1–200 MB")
	}
	m.RelayHost, m.RelayUser = strings.ToLower(strings.TrimSpace(m.RelayHost)), strings.TrimSpace(m.RelayUser)
	if m.RelayHost != "" {
		if _, err := m.relay(); err != nil {
			return err
		}
	} else {
		m.RelayUser, m.RelayPassword = "", ""
	}
	if len(m.RelayUser) > 256 || strings.ContainsAny(m.RelayUser, " \t\r\n:") {
		return errors.New("the user name of the smart host is not valid")
	}
	return nil
}

// MailConfig loads the mail settings.
func (s *Server) MailConfig(ctx context.Context) MailSettings {
	m := defaultMail()
	if err := s.store.GetSetting(ctx, settingMail, &m); err != nil || m.Validate() != nil {
		return defaultMail()
	}
	return m
}

func (s *Server) handleMailSettings(w http.ResponseWriter, r *http.Request) {
	s.showMailSettings(w, r, http.StatusOK, s.MailConfig(r.Context()), "")
}

func (s *Server) showMailSettings(w http.ResponseWriter, r *http.Request, status int, m MailSettings, errMsg string) {
	p := &Page{Title: "Mail server", Nav: "settings", Data: &mailSettingsData{MailSettings: m}}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "mailsettings", p)
}

func (s *Server) handleMailSettingsSave(w http.ResponseWriter, r *http.Request) {
	m := MailSettings{Hostname: r.FormValue("hostname"), RequireVerification: r.FormValue("require_verification") == "1",
		Dedicated: r.FormValue("dedicated") == "1", MaxMessageMB: formInt(r, "max_message_mb"), AllowPrivateImports: r.FormValue("allow_private_imports") == "1", ClamAV: r.FormValue("clamav") == "1", IPv4Only: r.FormValue("ipv4_only") == "1",
		RelayHost: r.FormValue("relay_host"), RelayUser: r.FormValue("relay_user")}
	// the saved password stays unless a new one is entered (for the same login)
	old := s.MailConfig(r.Context())
	if p := r.FormValue("relay_password"); p != "" {
		if len(p) > 256 || strings.ContainsAny(p, "\r\n\x00") {
			s.showMailSettings(w, r, http.StatusBadRequest, m, "The password of the smart host is not valid.")
			return
		}
		m.RelayPassword = s.store.SealSecret("mail.relay", p)
	} else if strings.TrimSpace(m.RelayUser) == old.RelayUser {
		m.RelayPassword = old.RelayPassword
	}
	if err := m.Validate(); err != nil {
		s.showMailSettings(w, r, http.StatusBadRequest, m, err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), settingMail, m); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.mail", "settings", "host name %q, verification %v, dedicated %v, max message %d MB, smart host %q (login %q), virus scan %v, IPv4 only %v", m.Hostname, m.RequireVerification, m.Dedicated, m.MaxMessageMB, m.RelayHost, m.RelayUser, m.ClamAV, m.IPv4Only)
	s.applyMail(r)
	go s.publishAllDNS(context.WithoutCancel(r.Context()))
	s.redirect(w, r, "/settings/mail", "Saved.")
}

// applyMail asks the root helper to write the server-wide mail
// configuration again (after a settings change).
func (s *Server) applyMail(r *http.Request) {
	if s.Mail == nil {
		return
	}
	m := s.MailConfig(r.Context())
	if m.RelayPassword != "" {
		m.relayPassword, _ = s.store.OpenSecret("mail.relay", m.RelayPassword)
	}
	if err := s.Mail.Apply(r.Context(), m); err != nil {
		s.log.Error("applying the mail configuration failed", "err", err)
	}
}

// ---- overview

type overviewData struct {
	Totals   store.Totals
	Customer *store.Customer
	Package  *store.Package
	Domains  []*store.Domain
	Mail     MailSettings
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	d := &overviewData{Mail: s.MailConfig(r.Context())}
	var err error
	if u.IsStaff() {
		d.Totals, err = s.store.ServerTotals(r.Context())
	} else {
		d.Customer, err = s.store.CustomerByID(r.Context(), u.CustomerID)
		if err == nil {
			d.Package, err = s.store.PackageByID(r.Context(), d.Customer.PackageID)
		}
		if err == nil {
			d.Domains, err = s.store.Domains(r.Context(), scopeOf(r), "")
		}
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "overview", &Page{Title: "Overview", Nav: "overview", Data: d})
}

// ---- packages

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Packages(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "packages", &Page{Title: "Packages", Nav: "packages", Data: list})
}

type packageData struct {
	P   *store.Package
	New bool
}

func (s *Server) handlePackage(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") == "new" {
		p := &store.Package{MaxDomains: 1, MaxMailboxes: 5, MaxAliases: 20, StorageMB: 5120, MailboxMB: 1024, MaxMailboxMB: 5120,
			SendPerHour: 100, SendPerDay: 500, CustomerPerHour: 300, RcptPerMsg: 50}
		s.render(w, r, http.StatusOK, "package", &Page{Title: "New package", Nav: "packages", Data: &packageData{P: p, New: true}})
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	p, err := s.store.PackageByID(r.Context(), id)
	if err != nil {
		s.notFound(w, r)
		return
	}
	s.render(w, r, http.StatusOK, "package", &Page{Title: "Package", Nav: "packages", Data: &packageData{P: p}})
}

func (s *Server) handlePackageSave(w http.ResponseWriter, r *http.Request) {
	p := &store.Package{Slug: r.FormValue("slug"), Name: r.FormValue("name"), MaxDomains: formInt(r, "max_domains"),
		MaxMailboxes: formInt(r, "max_mailboxes"), MaxAliases: formInt(r, "max_aliases"), StorageMB: formInt(r, "storage_mb"),
		MailboxMB: formInt(r, "mailbox_mb"), MaxMailboxMB: formInt(r, "max_mailbox_mb"), SendPerHour: formInt(r, "send_per_hour"),
		SendPerDay: formInt(r, "send_per_day"), CustomerPerHour: formInt(r, "customer_per_hour"), RcptPerMsg: formInt(r, "rcpt_per_msg")}
	if id := r.PathValue("id"); id != "" {
		n, ok := pathID(r, "id")
		if !ok {
			s.notFound(w, r)
			return
		}
		p.ID = n
	}
	isNew := p.ID == 0
	if err := s.store.SavePackage(r.Context(), p); err != nil {
		title := "Package"
		if isNew {
			title = "New package"
		}
		pg := &Page{Title: title, Nav: "packages", Data: &packageData{P: p, New: isNew}}
		pg.Error = translate(s.lang(r, userFrom(r)), mailErr(err))
		s.render(w, r, http.StatusBadRequest, "package", pg)
		return
	}
	s.audit(r, "package.save", "package:"+p.Slug, "%s: %d domains, %d mailboxes, %d MB, %d/h per mailbox", p.Name, p.MaxDomains, p.MaxMailboxes, p.StorageMB, p.SendPerHour)
	s.redirect(w, r, "/packages", "Saved.")
}

func (s *Server) handlePackageDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	p, err := s.store.PackageByID(r.Context(), id)
	if err == nil {
		err = s.store.DeletePackage(r.Context(), id)
	}
	if err != nil {
		s.redirectErr(w, r, "/packages", mailErr(err))
		return
	}
	s.audit(r, "package.delete", "package:"+p.Slug, "%s deleted", p.Name)
	s.redirect(w, r, "/packages", "Deleted.")
}

// ---- customers

type customersData struct {
	List     []*store.Customer
	Packages []*store.Package
	Q        string
	Status   string
}

func (s *Server) handleCustomers(w http.ResponseWriter, r *http.Request) {
	d := &customersData{Q: strings.TrimSpace(r.FormValue("q")), Status: r.FormValue("status")}
	var err error
	if d.List, err = s.store.Customers(r.Context(), store.CustomerFilter{Query: d.Q, Status: d.Status, Limit: 500}); err == nil {
		d.Packages, err = s.store.Packages(r.Context())
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "customers", &Page{Title: "Customers", Nav: "customers", Data: d})
}

func (s *Server) handleCustomerCreate(w http.ResponseWriter, r *http.Request) {
	pkg, _ := strconv.ParseInt(r.FormValue("package"), 10, 64)
	c, err := s.store.CreateCustomer(r.Context(), store.NewCustomer{Name: r.FormValue("name"), Email: r.FormValue("email"),
		ExternalID: r.FormValue("external_id"), PackageID: pkg})
	if err != nil {
		s.redirectErr(w, r, "/customers", mailErr(err))
		return
	}
	s.audit(r, "customer.create", "customer:"+c.ID, "%s (package %s)", c.Name, c.PackageName)
	if s.Mail != nil {
		if err := s.Mail.CustomerCreated(r.Context(), c); err != nil {
			s.log.Error("customer mail directory", "customer", c.ID, "err", err)
		}
	}
	s.redirect(w, r, "/customers/"+c.ID, "Customer created.")
}

type customerData struct {
	C         *store.Customer
	Package   *store.Package
	Packages  []*store.Package
	Logins    []*store.User
	Domains   []*store.Domain
	Web       []store.WebSender // hosting accounts (HostZit) sending through emailzit-sendmail
	Spam      string            // the customer's spam level
	Levels    []string
	Exports   []exportFile
	Exporting bool // an export is running
	Import    *job // the newest import job
	Verified  bool // new domains are verified at once (no verification required)
}

func (s *Server) loadCustomer(w http.ResponseWriter, r *http.Request) *store.Customer {
	c, err := s.store.CustomerByID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.notFound(w, r)
		return nil
	}
	return c
}

func (s *Server) handleCustomer(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	d := &customerData{C: c}
	var err error
	if d.Package, err = s.store.PackageByID(r.Context(), c.PackageID); err == nil {
		if d.Packages, err = s.store.Packages(r.Context()); err == nil {
			if d.Logins, err = s.store.CustomerUsers(r.Context(), c.ID); err == nil {
				d.Domains, err = s.store.Domains(r.Context(), store.Staff, c.ID)
				if err == nil {
					d.Web, err = s.store.WebSenders(r.Context(), c.ID)
					d.Levels = sieve.SpamLevels
					d.Exports, d.Exporting = s.exportFiles(c.ID), s.exportRunning(c.ID)
					d.Import = s.lastImport(c.ID)
					d.Spam, _ = s.store.CustomerSpamLevel(r.Context(), c.ID)
				}
			}
		}
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "customer", &Page{Title: c.Name, Nav: "customers", Data: d})
}

func (s *Server) handleCustomerUpdate(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	to := "/customers/" + c.ID
	if err := s.store.UpdateCustomer(r.Context(), c.ID, r.FormValue("name"), r.FormValue("email"), r.FormValue("external_id")); err != nil {
		s.redirectErr(w, r, to, mailErr(err))
		return
	}
	pkg, _ := strconv.ParseInt(r.FormValue("package"), 10, 64)
	if pkg != 0 && pkg != c.PackageID {
		if err := s.store.SetCustomerPackage(r.Context(), c.ID, pkg); err != nil {
			s.redirectErr(w, r, to, mailErr(err))
			return
		}
		s.audit(r, "customer.package", "customer:"+c.ID, "package changed from %s to #%d", c.PackageName, pkg)
	}
	s.audit(r, "customer.update", "customer:"+c.ID, "%s", strings.TrimSpace(r.FormValue("name")))
	s.redirect(w, r, to, "Saved.")
}

func (s *Server) handleCustomerStatus(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	st := r.FormValue("status")
	if err := s.store.SetCustomerStatus(r.Context(), c.ID, st, r.FormValue("reason")); err != nil {
		s.redirectErr(w, r, "/customers/"+c.ID, mailErr(err))
		return
	}
	s.audit(r, "customer.status", "customer:"+c.ID, "%s: %s → %s (%s)", c.Name, c.Status, st, strings.TrimSpace(r.FormValue("reason")))
	s.redirect(w, r, "/customers/"+c.ID, "Saved.")
}

// handleCustomerLogin creates a panel login for a customer, or switches
// one on or off.
func (s *Server) handleCustomerLogin(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	to := "/customers/" + c.ID
	if id, err := strconv.ParseInt(r.FormValue("login"), 10, 64); err == nil && id > 0 {
		off := r.FormValue("disabled") == "1"
		if err := s.store.SetCustomerUserDisabled(r.Context(), c.ID, id, off); err != nil {
			s.redirectErr(w, r, to, mailErr(err))
			return
		}
		s.audit(r, "customer.login.state", "customer:"+c.ID, "login #%d disabled=%v", id, off)
		s.redirect(w, r, to, "Saved.")
		return
	}
	u, err := s.store.CreateUser(r.Context(), store.NewUser{Username: r.FormValue("username"), DisplayName: r.FormValue("display_name"),
		Password: r.FormValue("password"), CustomerID: c.ID, MustChangePassword: true})
	if err != nil {
		s.redirectErr(w, r, to, mailErr(err))
		return
	}
	s.audit(r, "customer.login.create", "customer:"+c.ID, "panel login %s created", u.Username)
	s.redirect(w, r, to, "Login created. The customer changes the password and sets up two-factor sign-in at the first sign-in.")
}

// ---- domains

type domainsData struct {
	List      []*store.Domain
	Customers []*store.Customer // staff: whom a new domain belongs to
	Customer  string            // staff: filter
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	sc := scopeOf(r)
	d := &domainsData{Customer: r.FormValue("customer")}
	var err error
	if d.List, err = s.store.Domains(r.Context(), sc, d.Customer); err == nil && !sc.IsCustomer() {
		d.Customers, err = s.store.Customers(r.Context(), store.CustomerFilter{Status: store.CustomerActive, Limit: 500})
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "domains", &Page{Title: "Domains", Nav: "domains", Data: d})
}

func (s *Server) handleDomainCreate(w http.ResponseWriter, r *http.Request) {
	sc := scopeOf(r)
	m := s.MailConfig(r.Context())
	// staff and dedicated servers need no proof; customers on a shared server do
	verified := !sc.IsCustomer() && r.FormValue("verified") == "1" || !m.RequireVerification || m.Dedicated
	d, err := s.store.CreateDomain(r.Context(), sc, r.FormValue("customer"), r.FormValue("name"), verified)
	if err != nil {
		s.redirectErr(w, r, "/domains", mailErr(err))
		return
	}
	s.audit(r, "domain.create", "domain:"+d.Name, "customer %s, verified %v", d.CustomerName, d.Verified)
	s.installDKIM(r.Context(), d.ID)
	s.publishDNS(r.Context(), d.ID, false, nil)
	s.redirect(w, r, "/domains/"+d.ID, "Domain added.")
}

type domainData struct {
	D         *store.Domain
	Mailboxes []*store.Mailbox
	Aliases   []*store.Alias
	Package   *store.Package
	Records   []DNSRecord
	Checked   map[int]string // index in Records → ok, missing, different (after "Check DNS")
	Mail      MailSettings
	Staff     bool
	DMARC     *store.DMARCSummary // reports of the last 30 days
}

func (s *Server) loadDomain(w http.ResponseWriter, r *http.Request) *store.Domain {
	d, err := s.store.DomainByID(r.Context(), scopeOf(r), r.PathValue("id"))
	if err != nil {
		s.notFound(w, r)
		return nil
	}
	return d
}

func (s *Server) handleDomain(w http.ResponseWriter, r *http.Request) {
	dom := s.loadDomain(w, r)
	if dom == nil {
		return
	}
	sc := scopeOf(r)
	d := &domainData{D: dom, Mail: s.MailConfig(r.Context()), Staff: !sc.IsCustomer()}
	var err error
	if d.Mailboxes, err = s.store.Mailboxes(r.Context(), sc, store.MailboxFilter{DomainID: dom.ID}); err == nil {
		if d.Aliases, err = s.store.Aliases(r.Context(), sc, "", dom.ID); err == nil {
			var c *store.Customer
			if c, err = s.store.CustomerByID(r.Context(), dom.CustomerID); err == nil {
				d.Package, err = s.store.PackageByID(r.Context(), c.PackageID)
			}
		}
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	k, _ := s.store.DKIM(r.Context(), dom.ID)
	d.Records = mailRecords(dom, d.Mail, k)
	if r.Method == http.MethodPost {
		d.Checked = s.checkRecords(r.Context(), d.Records)
	}
	if d.DMARC, err = s.store.DMARCSummary(r.Context(), dom.ID, s.now().Add(-30*24*time.Hour)); err != nil {
		s.log.Warn("dmarc summary", "domain", dom.Name, "err", err)
	}
	s.render(w, r, http.StatusOK, "domain", &Page{Title: dom.Unicode(), Nav: "domains", Data: d})
}

func (s *Server) handleDomainUpdate(w http.ResponseWriter, r *http.Request) {
	dom := s.loadDomain(w, r)
	if dom == nil {
		return
	}
	to := "/domains/" + dom.ID
	sc := scopeOf(r)
	if err := s.store.SetCatchAll(r.Context(), sc, dom.ID, r.FormValue("catch_all")); err != nil {
		s.redirectErr(w, r, to, mailErr(err))
		return
	}
	if !sc.IsCustomer() {
		off := r.FormValue("disabled") == "1"
		if off != dom.Disabled {
			if err := s.store.SetDomainDisabled(r.Context(), dom.ID, off); err != nil {
				s.serverError(w, r, err)
				return
			}
		}
	}
	s.audit(r, "domain.update", "domain:"+dom.Name, "catch-all %q, disabled %v", strings.TrimSpace(r.FormValue("catch_all")), r.FormValue("disabled") == "1")
	s.redirect(w, r, to, "Saved.")
}

// handleDomainVerify checks the verification TXT record (customers), or
// marks the domain verified by hand (staff).
func (s *Server) handleDomainVerify(w http.ResponseWriter, r *http.Request) {
	dom := s.loadDomain(w, r)
	if dom == nil {
		return
	}
	to := "/domains/" + dom.ID
	sc := scopeOf(r)
	if !sc.IsCustomer() && r.FormValue("manual") != "" {
		v := r.FormValue("manual") == "1"
		if err := s.store.SetDomainVerified(r.Context(), sc, dom.ID, v); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "domain.verify", "domain:"+dom.Name, "verified=%v by hand", v)
		s.redirect(w, r, to, "Saved.")
		return
	}
	ok, err := s.checkTXT(r.Context(), dom.VerifyName(), dom.VerifyValue())
	if err != nil || !ok {
		msg := translate(s.lang(r, userFrom(r)), "The TXT record %s with the value %s was not found yet. DNS changes can take a while; try again later.", dom.VerifyName(), dom.VerifyValue())
		s.redirectErr(w, r, to, msg)
		return
	}
	if err := s.store.SetDomainVerified(r.Context(), sc, dom.ID, true); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "domain.verify", "domain:"+dom.Name, "verified by TXT record")
	s.redirect(w, r, to, "The domain is verified and receives mail now.")
}

func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	dom := s.loadDomain(w, r)
	if dom == nil {
		return
	}
	if strings.TrimSpace(strings.ToLower(r.FormValue("confirm"))) != dom.Name {
		s.redirectErr(w, r, "/domains/"+dom.ID, "Type the domain name to confirm.")
		return
	}
	if err := s.store.DeleteDomain(r.Context(), scopeOf(r), dom.ID); err != nil {
		s.redirectErr(w, r, "/domains/"+dom.ID, mailErr(err))
		return
	}
	s.audit(r, "domain.delete", "domain:"+dom.Name, "deleted with %d mailboxes and %d aliases", dom.Mailboxes, dom.Aliases)
	s.publishDNS(r.Context(), dom.ID, true, dom)
	if s.Mail != nil {
		if err := s.Mail.DomainDeleted(r.Context(), dom); err != nil {
			s.log.Error("removing the mail files of a domain", "domain", dom.Name, "err", err)
		}
	}
	s.redirect(w, r, "/domains", "Domain deleted.")
}

// ---- mailboxes

type mailboxesData struct {
	List []*store.Mailbox
	Q    string
}

func (s *Server) handleMailboxes(w http.ResponseWriter, r *http.Request) {
	d := &mailboxesData{Q: strings.TrimSpace(r.FormValue("q"))}
	var err error
	d.List, err = s.store.Mailboxes(r.Context(), scopeOf(r), store.MailboxFilter{Query: d.Q, CustomerID: r.FormValue("customer")})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "mailboxes", &Page{Title: "Mailboxes", Nav: "mailboxes", Data: d})
}

func (s *Server) handleMailboxCreate(w http.ResponseWriter, r *http.Request) {
	dom := s.loadDomain(w, r)
	if dom == nil {
		return
	}
	to := "/domains/" + dom.ID
	if r.FormValue("password") != r.FormValue("password2") {
		s.redirectErr(w, r, to, "The passwords do not match.")
		return
	}
	m, err := s.store.CreateMailbox(r.Context(), scopeOf(r), store.NewMailbox{DomainID: dom.ID, LocalPart: r.FormValue("local"),
		DisplayName: r.FormValue("display_name"), Password: r.FormValue("password"), QuotaMB: formInt(r, "quota_mb")})
	if err != nil {
		s.redirectErr(w, r, to, mailErr(err))
		return
	}
	s.audit(r, "mailbox.create", "mailbox:"+m.Address, "%d MB", m.QuotaMB)
	s.syncSpam(r.Context(), m.CustomerID, m.Address)
	s.redirect(w, r, "/mailboxes/"+m.ID, "Mailbox created.")
}

type mailboxData struct {
	Spam         *spamForm
	Imports      []*store.Import
	M            *store.Mailbox
	Sent         store.SentStats
	D            *store.Domain
	AppPasswords []*store.AppPassword
	Package      *store.Package
	Staff        bool
	Mail         MailSettings
}

func (s *Server) loadMailbox(w http.ResponseWriter, r *http.Request) *store.Mailbox {
	m, err := s.store.MailboxByID(r.Context(), scopeOf(r), r.PathValue("id"))
	if err != nil {
		s.notFound(w, r)
		return nil
	}
	return m
}

func (s *Server) handleMailbox(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	sc := scopeOf(r)
	d := &mailboxData{M: m, Staff: !sc.IsCustomer(), Mail: s.MailConfig(r.Context())}
	var err error
	if d.D, err = s.store.DomainByID(r.Context(), sc, m.DomainID); err == nil {
		if d.AppPasswords, err = s.store.AppPasswords(r.Context(), m.ID); err == nil {
			d.Sent, _ = s.store.MailboxSentStats(r.Context(), m.ID)
			d.Imports, _ = s.store.Imports(r.Context(), m.ID)
			if sp, err := s.store.MailboxSpamSettings(r.Context(), sc, m.ID); err == nil {
				d.Spam = newSpamForm("/mailboxes/"+m.ID+"/spam", sp)
			}
			var c *store.Customer
			if c, err = s.store.CustomerByID(r.Context(), m.CustomerID); err == nil {
				d.Package, err = s.store.PackageByID(r.Context(), c.PackageID)
			}
		}
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "mailbox", &Page{Title: m.Address, Nav: "mailboxes", Data: d})
}

func optInt(r *http.Request, k string) *int {
	v := strings.TrimSpace(r.FormValue(k))
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

func (s *Server) handleMailboxUpdate(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	u := store.MailboxUpdate{DisplayName: r.FormValue("display_name"), QuotaMB: formInt(r, "quota_mb"), Disabled: r.FormValue("disabled") == "1",
		SendBlocked: r.FormValue("send_blocked") == "1", SendPerHour: optInt(r, "send_per_hour"), SendPerDay: optInt(r, "send_per_day")}
	if err := s.store.UpdateMailbox(r.Context(), scopeOf(r), m.ID, u); err != nil {
		s.redirectErr(w, r, "/mailboxes/"+m.ID, mailErr(err))
		return
	}
	s.audit(r, "mailbox.update", "mailbox:"+m.Address, "%d MB, disabled %v, sending blocked %v", u.QuotaMB, u.Disabled, u.SendBlocked)
	s.redirect(w, r, "/mailboxes/"+m.ID, "Saved.")
}

func (s *Server) handleMailboxPassword(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	if r.FormValue("password") != r.FormValue("password2") {
		s.redirectErr(w, r, "/mailboxes/"+m.ID, "The passwords do not match.")
		return
	}
	if err := s.store.SetMailboxPassword(r.Context(), scopeOf(r), m.ID, r.FormValue("password")); err != nil {
		s.redirectErr(w, r, "/mailboxes/"+m.ID, mailErr(err))
		return
	}
	s.audit(r, "mailbox.password", "mailbox:"+m.Address, "web password set; the mail user was signed out")
	s.redirect(w, r, "/mailboxes/"+m.ID, "Password changed.")
}

func (s *Server) handleMailboxReset2FA(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	if err := s.store.ResetMailboxTwoFactor(r.Context(), scopeOf(r), m.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "mailbox.reset-2fa", "mailbox:"+m.Address, "two-factor sign-in reset")
	s.redirect(w, r, "/mailboxes/"+m.ID, "Two-factor sign-in reset. The mail user sets it up again at the next sign-in.")
}

func (s *Server) handleMailboxAppPasswordDelete(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	if err := s.store.DeleteAppPassword(r.Context(), m.ID, r.PathValue("pid")); err != nil {
		s.redirectErr(w, r, "/mailboxes/"+m.ID, mailErr(err))
		return
	}
	s.audit(r, "mailbox.apppassword.delete", "mailbox:"+m.Address, "app password %s revoked", r.PathValue("pid"))
	s.redirect(w, r, "/mailboxes/"+m.ID, "App password revoked.")
}

func (s *Server) handleMailboxDelete(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	if strings.TrimSpace(strings.ToLower(r.FormValue("confirm"))) != m.Address {
		s.redirectErr(w, r, "/mailboxes/"+m.ID, "Type the address to confirm.")
		return
	}
	if err := s.store.DeleteMailbox(r.Context(), scopeOf(r), m.ID); err != nil {
		s.redirectErr(w, r, "/mailboxes/"+m.ID, mailErr(err))
		return
	}
	s.audit(r, "mailbox.delete", "mailbox:"+m.Address, "deleted")
	if s.Mail != nil {
		if err := s.Mail.MailboxDeleted(r.Context(), m); err != nil {
			s.log.Error("removing the mail files of a mailbox", "mailbox", m.Address, "err", err)
		}
	}
	s.redirect(w, r, "/domains/"+m.DomainID, "Mailbox deleted.")
}

// ---- aliases and forwarders

type aliasesData struct {
	List    []*store.Alias
	Domains []*store.Domain
}

func (s *Server) handleAliases(w http.ResponseWriter, r *http.Request) {
	sc := scopeOf(r)
	d := &aliasesData{}
	var err error
	if d.List, err = s.store.Aliases(r.Context(), sc, r.FormValue("customer"), ""); err == nil {
		d.Domains, err = s.store.Domains(r.Context(), sc, r.FormValue("customer"))
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "aliases", &Page{Title: "Aliases and forwarders", Nav: "aliases", Data: d})
}

func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == ';' })
}

func (s *Server) handleAliasCreate(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") == "" {
		r.SetPathValue("id", r.FormValue("domain"))
	}
	dom := s.loadDomain(w, r)
	if dom == nil {
		return
	}
	back := "/domains/" + dom.ID
	if r.FormValue("back") == "aliases" {
		back = "/aliases"
	}
	a, err := s.store.CreateAlias(r.Context(), scopeOf(r), dom.ID, r.FormValue("local"), splitList(r.FormValue("destinations")), r.FormValue("send_as") == "1")
	if err != nil {
		s.redirectErr(w, r, back, mailErr(err))
		return
	}
	s.audit(r, "alias.create", "alias:"+a.Address, "→ %s (send as %v)", strings.Join(a.Destinations, ", "), a.SendAs)
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleAliasUpdate(w http.ResponseWriter, r *http.Request) {
	sc := scopeOf(r)
	a, err := s.store.AliasByID(r.Context(), sc, r.PathValue("id"))
	if err != nil {
		s.notFound(w, r)
		return
	}
	back := backTo(r, "/domains/"+a.DomainID)
	if err := s.store.UpdateAlias(r.Context(), sc, a.ID, splitList(r.FormValue("destinations")), r.FormValue("send_as") == "1"); err != nil {
		s.redirectErr(w, r, back, mailErr(err))
		return
	}
	s.audit(r, "alias.update", "alias:"+a.Address, "→ %s", strings.Join(splitList(r.FormValue("destinations")), ", "))
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleAliasDelete(w http.ResponseWriter, r *http.Request) {
	sc := scopeOf(r)
	a, err := s.store.AliasByID(r.Context(), sc, r.PathValue("id"))
	if err != nil {
		s.notFound(w, r)
		return
	}
	back := backTo(r, "/domains/"+a.DomainID)
	if err := s.store.DeleteAlias(r.Context(), sc, a.ID); err != nil {
		s.redirectErr(w, r, back, mailErr(err))
		return
	}
	s.audit(r, "alias.delete", "alias:"+a.Address, "deleted")
	s.redirect(w, r, back, "Deleted.")
}

func backTo(r *http.Request, def string) string {
	if r.FormValue("back") == "aliases" {
		return "/aliases"
	}
	return def
}

// usage is the argument of the usage template.
type usage struct {
	Pct  int
	Text string
}

func init() {
	funcs["mb"] = func(mb int64) string {
		if mb >= 1024 {
			return fmt.Sprintf("%.1f GB", float64(mb)/1024)
		}
		return fmt.Sprintf("%d MB", mb)
	}
	funcs["bytes"] = humanBytes
	funcs["usage"] = func(used int64, quotaMB int64) usage {
		if quotaMB <= 0 {
			return usage{Text: humanBytes(used)}
		}
		p := int(used * 100 / (quotaMB << 20))
		return usage{Pct: min(p, 100), Text: humanBytes(used) + " / " + humanBytes(quotaMB<<20)}
	}
	funcs["i64"] = func(n int) int64 { return int64(n) }
	funcs["deref"] = func(p *int) string {
		if p == nil {
			return ""
		}
		return strconv.Itoa(*p)
	}
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%d KB", b>>10)
	}
	return fmt.Sprintf("%d B", b)
}

// uiErr is an error whose text is shown to the user (and translated).
type uiErr string

func (e uiErr) Error() string { return string(e) }

// rowCtx passes the page and one value to a sub-template.
type rowCtx struct {
	P   *Page
	Row string
}

func init() {
	funcs["rowOf"] = func(p *Page, v string) rowCtx { return rowCtx{P: p, Row: v} }
}

type aliasTableCtx struct {
	P    *Page
	List []*store.Alias
	Back string
}

func init() {
	funcs["aliasTable"] = func(p *Page, l []*store.Alias, back string) aliasTableCtx {
		return aliasTableCtx{P: p, List: l, Back: back}
	}
}

// handleDomainDKIM makes a new DKIM key (rotation, or a key that leaked).
func (s *Server) handleDomainDKIM(w http.ResponseWriter, r *http.Request) {
	dom := s.loadDomain(w, r)
	if dom == nil {
		return
	}
	k, err := s.store.NewDKIM(r.Context(), dom.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if s.Mail != nil {
		if err := s.Mail.DKIM(r.Context(), k); err != nil {
			s.log.Error("installing the DKIM key", "domain", dom.Name, "err", err)
			s.redirectErr(w, r, "/domains/"+dom.ID, "The new key could not be installed on the mail server; try again.")
			return
		}
	}
	s.audit(r, "domain.dkim", "domain:"+dom.Name, "new DKIM key, selector %s", k.Selector)
	s.publishDNS(r.Context(), dom.ID, false, nil)
	s.redirect(w, r, "/domains/"+dom.ID, "New DKIM key created. Put the new DKIM record at the DNS provider; until then receivers cannot check the signature.")
}

// relay is the smart host as Postfix writes it ("[host]:port").
func (m *MailSettings) relay() (string, error) {
	host, port := m.RelayHost, "587"
	if h, p, err := net.SplitHostPort(m.RelayHost); err == nil {
		host, port = h, p
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("the port of the smart host is not valid")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		if h, err := store.NormalizeDomain(host); err != nil || h != host {
			return "", errors.New("the smart host must be a host name or an address, optionally with a port (smtp.example.com:587)")
		}
	}
	return "[" + host + "]:" + port, nil
}
