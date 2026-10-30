// Package web serves the EmailZit panels: the admin panel (server
// administrators), the customer panel (one customer's domains and
// mailboxes) and the mail user's own pages.
package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/store"
)

// Server serves the panels.
type Server struct {
	store *store.Store
	log   *slog.Logger
	tmpl  map[string]*template.Template
	now   func() time.Time
	guard *loginGuard

	// MgmtACL guards the panel listener.
	MgmtACL *netacl.List
	// RunningMgmt is the listen address the server actually uses.
	RunningMgmt string
	// ListenOverride: the address comes from a command-line option.
	ListenOverride bool
	Version        string
	// SetupTokenFile holds the one-time token the first-run setup asks for.
	SetupTokenFile string
	// DevNo2FA skips the second factor (development server only).
	DevNo2FA   bool
	setupToken string
	// DataDir is the server's data directory (the root helper's requests).
	DataDir string
	// HelperAvailable replaces the check for the root helper (tests).
	HelperAvailable func() bool
	// Mail applies mail changes that need root (customer directories, DKIM
	// keys); nil = nothing to apply (development without a mail stack).
	Mail    MailApplier
	upd     updateState
	apiRate apiRate
}

// MailApplier is the part of the root helper the panels use.
type MailApplier interface {
	// Apply writes the server-wide mail configuration and reloads the services.
	Apply(ctx context.Context, m MailSettings) error
	// CustomerCreated makes the mail directory of a new customer.
	CustomerCreated(ctx context.Context, c *store.Customer) error
	// DomainDeleted and MailboxDeleted remove the mail files.
	DomainDeleted(ctx context.Context, d *store.Domain) error
	MailboxDeleted(ctx context.Context, m *store.Mailbox) error
	// DKIM installs the signing key of a domain.
	DKIM(ctx context.Context, k *store.DKIMKey) error
}

// New creates the server; settings are loaded from the database.
func New(ctx context.Context, st *store.Store, log *slog.Logger) (*Server, error) {
	t, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{store: st, log: log, tmpl: t, now: time.Now, Version: "dev"}
	s.guard = newLoginGuard(st, func() time.Time { return s.now() })
	n, err := s.Network(ctx)
	if err != nil {
		return nil, err
	}
	mg, _ := netacl.Parse(n.MgmtAllowed)
	s.MgmtACL = netacl.NewManagement(mg)
	return s, nil
}

// SetClock replaces the clock (tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// SetSetupToken sets the token the first-run setup requires.
func (s *Server) SetSetupToken(tok string) { s.setupToken = tok }

// ---- network settings

const settingNetwork = "network"

// NetworkSettings are the panel listener and who may reach it.
type NetworkSettings struct {
	// MgmtListen is the panel address, e.g. ":8444" or "192.168.1.10:8444".
	MgmtListen string `json:"mgmt_listen"`
	// MgmtAllowed may reach the panels (loopback always may). Customers and
	// mail users reach them too, so on a hosting server this is usually
	// everyone (0.0.0.0/0, ::/0); the default is the private networks.
	MgmtAllowed []string `json:"mgmt_allowed"`
}

// DefaultListen is the panel port when nothing else is set (HostZit uses
// 8443, so both can run on one server).
const DefaultListen = ":8444"

// defaultNetwork is used until the settings are saved (a fresh copy each
// time: JSON decoding into it must not change the package defaults).
func defaultNetwork() NetworkSettings {
	return NetworkSettings{MgmtListen: DefaultListen, MgmtAllowed: append([]string(nil), netacl.DefaultManagement...)}
}

// Validate checks the listen address and the networks.
func (n *NetworkSettings) Validate() error {
	if _, _, err := splitListen(n.MgmtListen); err != nil {
		return fmt.Errorf("panel address: %w", err)
	}
	if _, err := netacl.Parse(n.MgmtAllowed); err != nil {
		return err
	}
	return nil
}

func splitListen(a string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(a))
	if err != nil {
		return "", 0, errors.New("use host:port or :port, e.g. :8444")
	}
	port, err = strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("the port must be 1–65535")
	}
	if h != "" {
		if _, err := netip.ParseAddr(h); err != nil {
			return "", 0, errors.New("the host must be an IP address of this server (or empty for all)")
		}
	}
	return h, port, nil
}

// Network loads the network settings.
func (s *Server) Network(ctx context.Context) (NetworkSettings, error) {
	n := defaultNetwork()
	if err := s.store.GetSetting(ctx, settingNetwork, &n); err != nil {
		return n, err
	}
	if n.Validate() != nil {
		s.log.Warn("invalid network settings in the database; using defaults")
		n = defaultNetwork()
	}
	return n, nil
}

// SaveNetwork stores the settings and applies the allow-list at once.
func (s *Server) SaveNetwork(ctx context.Context, n NetworkSettings) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingNetwork, n); err != nil {
		return err
	}
	mg, _ := netacl.Parse(n.MgmtAllowed)
	s.MgmtACL.Set(mg)
	return nil
}

// ResetMgmtAllowList restores the default panel networks (CLI, for an
// administrator who locked themselves out).
func ResetMgmtAllowList(ctx context.Context, st *store.Store) error {
	n := defaultNetwork()
	if err := st.GetSetting(ctx, settingNetwork, &n); err != nil {
		return err
	}
	n.MgmtAllowed = append([]string(nil), netacl.DefaultManagement...)
	if n.Validate() != nil {
		n = defaultNetwork()
	}
	return st.SetSetting(ctx, settingNetwork, n)
}

// ---- security settings

const settingSecurity = "security"

// SecuritySettings control sessions and the brute-force protection.
type SecuritySettings struct {
	SessionHours int `json:"session_hours"`
	IdleMinutes  int `json:"idle_minutes"`
	// MaxAttempts failed sign-ins of one address within WindowMinutes
	// block it for BlockMinutes (doubling for repeated blocks in a day).
	MaxAttempts   int `json:"max_attempts"`
	WindowMinutes int `json:"window_minutes"`
	BlockMinutes  int `json:"block_minutes"`
}

// DefaultSecurity: the panels of a mail server are reached from
// everywhere, so sessions are short.
var DefaultSecurity = SecuritySettings{SessionHours: 8, IdleMinutes: 30, MaxAttempts: 5, WindowMinutes: 15, BlockMinutes: 30}

// Validate checks the ranges.
func (x SecuritySettings) Validate() error {
	switch {
	case x.SessionHours < 1 || x.SessionHours > 24:
		return errors.New("the session length must be 1–24 hours")
	case x.IdleMinutes < 5 || x.IdleMinutes > 1440:
		return errors.New("the inactivity timeout must be 5–1440 minutes")
	case x.MaxAttempts < 3 || x.MaxAttempts > 50:
		return errors.New("failed attempts must be 3–50")
	case x.WindowMinutes < 1 || x.WindowMinutes > 1440:
		return errors.New("the counting period must be 1–1440 minutes")
	case x.BlockMinutes < 1 || x.BlockMinutes > 10080:
		return errors.New("the block must last 1–10080 minutes")
	}
	return nil
}

func (s *Server) security(ctx context.Context) SecuritySettings {
	x := DefaultSecurity
	if err := s.store.GetSetting(ctx, settingSecurity, &x); err != nil || x.Validate() != nil {
		return DefaultSecurity
	}
	return x
}

// ---- handlers

// Handler serves the panels.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(gzipStatic(sub, http.FileServer(http.FS(sub))))))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.svg", http.StatusMovedPermanently)
	})

	mux.HandleFunc("GET /setup", s.handleSetup)
	mux.HandleFunc("POST /setup", s.handleSetup)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /login/2fa", s.handleLogin2FA)
	mux.HandleFunc("POST /login/2fa", s.handleLogin2FA)
	mux.HandleFunc("GET /login/enroll", s.handleEnroll)
	mux.HandleFunc("POST /login/enroll", s.handleEnroll)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("POST /lang", s.handleLang)
	mux.HandleFunc("GET /sso/{token}", s.handleSSO)

	// app: any panel login (staff or customer); staff: server staff
	// (admin, operator, viewer); write: may change mail objects (admin,
	// operator, customer); admin: server settings and staff accounts.
	app := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(h)) }
	staff := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(s.requireStaff(h))) }
	staffWrite := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, s.requireUser(s.requireStaff(s.requireWrite(h))))
	}
	write := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(s.requireWrite(h))) }
	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(s.requireAdmin(h))) }

	app("GET /{$}", s.handleOverview)
	staff("GET /packages", s.handlePackages)
	staffWrite("POST /packages", s.handlePackageSave)
	staff("GET /packages/{id}", s.handlePackage)
	staffWrite("POST /packages/{id}", s.handlePackageSave)
	staffWrite("POST /packages/{id}/delete", s.handlePackageDelete)
	staff("GET /customers", s.handleCustomers)
	staffWrite("POST /customers", s.handleCustomerCreate)
	staff("GET /customers/{id}", s.handleCustomer)
	staffWrite("POST /customers/{id}", s.handleCustomerUpdate)
	staffWrite("POST /customers/{id}/status", s.handleCustomerStatus)
	staffWrite("POST /customers/{id}/logins", s.handleCustomerLogin)
	app("GET /domains", s.handleDomains)
	write("POST /domains", s.handleDomainCreate)
	app("GET /domains/{id}", s.handleDomain)
	write("POST /domains/{id}", s.handleDomainUpdate)
	write("POST /domains/{id}/verify", s.handleDomainVerify)
	app("POST /domains/{id}/check", s.handleDomain)
	write("POST /domains/{id}/dkim", s.handleDomainDKIM)
	write("POST /domains/{id}/delete", s.handleDomainDelete)
	write("POST /domains/{id}/mailboxes", s.handleMailboxCreate)
	write("POST /domains/{id}/aliases", s.handleAliasCreate)
	write("POST /aliases", s.handleAliasCreate)
	app("GET /mailboxes", s.handleMailboxes)
	app("GET /mailboxes/{id}", s.handleMailbox)
	write("POST /mailboxes/{id}", s.handleMailboxUpdate)
	write("POST /mailboxes/{id}/password", s.handleMailboxPassword)
	write("POST /mailboxes/{id}/reset-2fa", s.handleMailboxReset2FA)
	write("POST /mailboxes/{id}/apppasswords/{pid}/delete", s.handleMailboxAppPasswordDelete)
	write("POST /mailboxes/{id}/delete", s.handleMailboxDelete)
	app("GET /aliases", s.handleAliases)
	write("POST /aliases/{id}", s.handleAliasUpdate)
	write("POST /aliases/{id}/delete", s.handleAliasDelete)
	app("GET /docs", s.handleDocs)
	app("GET /docs/search", s.handleDocsSearch)
	app("GET /docs/{page}", s.handleDocs)
	app("GET /account", s.handleAccount)
	app("POST /account/password", s.handleAccountPassword)
	app("POST /account/recovery", s.handleAccountRecovery)
	app("POST /account/sessions/signout", s.handleAccountSignout)
	admin("GET /users", s.handleUsers)
	admin("POST /users", s.handleUserCreate)
	admin("GET /users/{id}", s.handleUser)
	admin("POST /users/{id}", s.handleUserUpdate)
	admin("POST /users/{id}/password", s.handleUserPassword)
	admin("POST /users/{id}/reset-2fa", s.handleUserReset2FA)
	admin("GET /audit", s.handleAudit)
	admin("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings/mail", http.StatusFound)
	})
	admin("GET /settings/mail", s.handleMailSettings)
	admin("POST /settings/mail", s.handleMailSettingsSave)
	admin("GET /settings/api", s.handleAPITokens)
	admin("POST /settings/api", s.handleAPITokenCreate)
	admin("POST /settings/api/{id}/delete", s.handleAPITokenDelete)
	admin("GET /settings/network", s.handleNetwork)
	admin("POST /settings/network", s.handleNetworkSave)
	admin("GET /settings/security", s.handleSecurity)
	admin("POST /settings/security", s.handleSecuritySave)
	admin("POST /settings/security/unblock", s.handleUnblock)
	admin("GET /settings/version", s.handleVersion)
	admin("POST /settings/version/check", s.handleVersionCheck)
	admin("POST /settings/version/install", s.handleVersionInstall)
	admin("POST /settings/version/settings", s.handleVersionSettings)
	admin("POST /settings/timezone", s.handleTimeZone)
	admin("POST /settings/restart", s.handleRestart)
	admin("POST /settings/server-network", s.handleServerNetwork)

	// mail users (mailbox owners) have their own sign-in and cookie
	s.mailUserRoutes(mux)

	top := http.NewServeMux()
	// mail programs ask for their settings without a session or CSRF token
	auto := http.NewServeMux()
	s.autoconfigRoutes(auto)
	// the REST API signs in with tokens only: no session, no CSRF check
	top.Handle("/api/", s.apiHandler())
	for _, p := range []string{"/.well-known/autoconfig/", "/mail/config-v1.1.xml", "/autodiscover/", "/Autodiscover/"} {
		top.Handle(p, auto)
	}
	top.Handle("/", s.csrf(s.loadMailSession(s.loadSession(mux))))
	return s.secure(s.aclCheck(s.MgmtACL, top))
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// secure sets the security headers of every console response.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin (not no-referrer): browsers then still send a real
		// Origin header on form posts, which the CSRF check needs.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp") // everything the console loads is its own
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// aclCheck repeats the listener's address check per request (defense in
// depth, and the dev HTTP listener has no listener check).
func (s *Server) aclCheck(l *netacl.List, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.AllowsAddr(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrf refuses state-changing requests that do not come from a page of
// this console: the Origin (or, without it, the Referer) must match the
// Host, and Sec-Fetch-Site, where sent, must be same-origin.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			s.log.Warn("cross-site request refused", "ip", clientIP(r), "path", r.URL.Path, "origin", r.Header.Get("Origin"))
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	want := scheme + "://" + r.Host
	if o := r.Header.Get("Origin"); o != "" {
		return o == want
	}
	ref := r.Header.Get("Referer")
	return ref != "" && (ref == want || strings.HasPrefix(ref, want+"/"))
}

// clientIP is the address of the direct peer (no proxy support yet).
func clientIP(r *http.Request) string {
	if a, ok := netacl.AddrOf(r.RemoteAddr); ok {
		return a.String()
	}
	return r.RemoteAddr
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "notfound", &Page{Title: "Not found"})
}

func (s *Server) forbidden(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusForbidden, "forbidden", &Page{Title: "Not allowed"})
}

func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}

// audit records an action of the signed-in user.
func (s *Server) audit(r *http.Request, action, target, format string, args ...any) {
	name := "-"
	if u := userFrom(r); u != nil {
		name = u.Username
	}
	s.auditAs(r, name, action, target, format, args...)
}

func (s *Server) auditAs(r *http.Request, user, action, target, format string, args ...any) {
	detail := format
	if len(args) > 0 {
		detail = fmt.Sprintf(format, args...)
	}
	if err := s.store.Audit(r.Context(), user, clientIP(r), action, target, detail); err != nil {
		s.log.Error("audit log write failed", "action", action, "err", err)
	}
}

// storeErr turns a store error into a message for the user.
func storeErr(err error) string {
	switch {
	case errors.Is(err, store.ErrConflict):
		return "The name is already used."
	case errors.Is(err, store.ErrNotFound):
		return "Not found."
	}
	return err.Error()
}
