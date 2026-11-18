package web

// The way out of single recipient domains.
//
// Everything a server operator can do for deliverability — a matching PTR
// record, SPF, DKIM, DMARC, TLS, low volume — is about this server. It
// does not help when a receiver refuses the ADDRESS RANGE the server
// stands in: Outlook.com answers "messages from [...] weren't sent ...
// part of their network is on our block list", which is a block of the
// provider's range and not of this server (our own e1 has been refused
// that way since 2026-11-12). Then the only remedy is another way out for
// that one receiver: a relay the receiver accepts, or — when a smart host
// carries everything else — straight to the domain itself.
//
// A route is deliberately per RECIPIENT domain and nothing else. Postfix
// looks a recipient up in transport_maps as the whole address first and as
// its domain afterwards, so one line reaches every mailbox of the domain,
// and mail to everyone else keeps going the usual way.

import (
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/max-zit/emailzit/internal/store"
)

type routesData struct {
	Mail   MailSettings
	Routes []MailRoute
	// Edit is the route the form shows (a new, empty one by default).
	Edit MailRoute
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	s.showRoutes(w, r, http.StatusOK, s.MailConfig(r.Context()), MailRoute{Port: defaultRoutePort}, "")
}

func (s *Server) showRoutes(w http.ResponseWriter, r *http.Request, status int, m MailSettings, edit MailRoute, errMsg string) {
	routes := append([]MailRoute(nil), m.Routes...)
	sort.Slice(routes, func(i, j int) bool { return routes[i].Domain < routes[j].Domain })
	p := &Page{Title: "Delivery routes", Nav: "settings", Data: &routesData{Mail: m, Routes: routes, Edit: edit}}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "mailroutes", p)
}

// handleRouteSave adds a route or changes the one of the same domain.
func (s *Server) handleRouteSave(w http.ResponseWriter, r *http.Request) {
	m := s.MailConfig(r.Context())
	route := MailRoute{
		Domain: r.FormValue("domain"),
		Host:   r.FormValue("host"),
		Port:   formInt(r, "port"),
		User:   r.FormValue("user"),
		Note:   strings.TrimSpace(r.FormValue("note")),
	}
	if r.FormValue("kind") == "direct" {
		route.Host, route.Port, route.User = "", 0, ""
	}
	if err := route.normalize(); err != nil {
		s.showRoutes(w, r, http.StatusBadRequest, m, route, err.Error())
		return
	}
	// A route for a domain of this server would take its own mail off the
	// server: transport_maps is read before the local delivery of a virtual
	// domain, so the mail of our own customers would go to the relay.
	if d, err := s.store.DomainByName(r.Context(), store.Staff, route.Domain); err == nil && d != nil {
		s.showRoutes(w, r, http.StatusBadRequest, m, route, "This server receives mail for that domain itself, so it needs no route.")
		return
	}
	old, found := m.route(route.Domain)
	switch pw := r.FormValue("password"); {
	case route.User == "":
		route.Password = ""
	case pw != "":
		if len(pw) > 256 || strings.ContainsAny(pw, " \t\r\n\x00") {
			s.showRoutes(w, r, http.StatusBadRequest, m, route, "The password of the relay is not valid.")
			return
		}
		route.Password = s.store.SealSecret(routeSecret, pw)
	case found && old.User == route.User:
		route.Password = old.Password // unchanged login: the saved password stays
	default:
		s.showRoutes(w, r, http.StatusBadRequest, m, route, "The relay needs a password for that user name.")
		return
	}
	if found {
		m.Routes = m.without(route.Domain)
	}
	m.Routes = append(m.Routes, route)
	if err := m.Validate(); err != nil {
		s.showRoutes(w, r, http.StatusBadRequest, m, route, err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), settingMail, m); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.route", "settings", "mail for %s goes %s", route.Domain, route.way())
	s.applyMail(r)
	s.redirect(w, r, "/settings/routes", "Saved.")
}

func (s *Server) handleRouteDelete(w http.ResponseWriter, r *http.Request) {
	m := s.MailConfig(r.Context())
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	if _, found := m.route(domain); !found {
		s.redirectErr(w, r, "/settings/routes", "There is no route for that domain.")
		return
	}
	m.Routes = m.without(domain)
	if err := s.store.SetSetting(r.Context(), settingMail, m); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.route", "settings", "mail for %s goes the usual way again", domain)
	s.applyMail(r)
	s.redirect(w, r, "/settings/routes", "Saved.")
}

// defaultRoutePort is what a relay gets when no port is given: submission,
// which is where a relay expects mail from a server that signs in.
const defaultRoutePort = 587

// routeSecret is the purpose the passwords of the routes are sealed with.
const routeSecret = "mail.route"

// MailRoute sends the mail of one recipient domain another way.
type MailRoute struct {
	// Domain is the recipient domain, e.g. hotmail.com.
	Domain string `json:"domain"`
	// Host and Port are the relay; without a host the mail goes straight to
	// the domain's own servers, past a smart host.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	// User signs in at the relay, Password is sealed with the server key.
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	// Note says why the route is there (shown in the list).
	Note string `json:"note,omitempty"`
	// password is the plain text of Password, only while the configuration
	// is handed to the helper.
	password string
}

// Direct tells whether the mail goes to the domain itself.
func (r MailRoute) Direct() bool { return r.Host == "" }

// Relay is the relay as it is shown and written ([host]:port).
func (r MailRoute) Relay() string {
	if r.Direct() {
		return ""
	}
	return "[" + r.Host + "]:" + strconv.Itoa(r.Port)
}

// way describes the route for the audit log.
func (r MailRoute) way() string {
	if r.Direct() {
		return "straight to the domain"
	}
	if r.User != "" {
		return "through " + r.Relay() + " as " + r.User
	}
	return "through " + r.Relay()
}

// normalize checks one route as it comes from the form.
func (r *MailRoute) normalize() error {
	d, err := store.NormalizeDomain(r.Domain)
	if err != nil {
		return errors.New("the domain must be a name such as hotmail.com")
	}
	r.Domain = d
	r.Host = strings.ToLower(strings.TrimSpace(r.Host))
	r.User = strings.TrimSpace(r.User)
	if len(r.Note) > 200 {
		r.Note = r.Note[:200]
	}
	if r.Direct() {
		r.Port, r.User, r.Password = 0, "", ""
		return nil
	}
	if r.Port == 0 {
		r.Port = defaultRoutePort
	}
	if r.Port < 1 || r.Port > 65535 {
		return errors.New("the port of the relay must be 1–65535")
	}
	if _, err := netip.ParseAddr(r.Host); err != nil {
		if h, err := store.NormalizeDomain(r.Host); err != nil || h != r.Host {
			return errors.New("the relay must be a host name or an address, e.g. smtp.example.com")
		}
	}
	if strings.ContainsAny(r.User, " \t\r\n:") || len(r.User) > 256 {
		return errors.New("the user name of the relay is not valid")
	}
	return nil
}

// route finds the route of a domain.
func (m MailSettings) route(domain string) (MailRoute, bool) {
	for _, r := range m.Routes {
		if r.Domain == domain {
			return r, true
		}
	}
	return MailRoute{}, false
}

// without returns the routes except the one of a domain.
func (m MailSettings) without(domain string) []MailRoute {
	out := make([]MailRoute, 0, len(m.Routes))
	for _, r := range m.Routes {
		if r.Domain != domain {
			out = append(out, r)
		}
	}
	return out
}

// validateRoutes checks the routes of the settings (called by Validate).
func (m *MailSettings) validateRoutes() error {
	if len(m.Routes) > 64 {
		return errors.New("there can be at most 64 routes")
	}
	seen := map[string]bool{}
	for i := range m.Routes {
		if err := m.Routes[i].normalize(); err != nil {
			return err
		}
		if seen[m.Routes[i].Domain] {
			return errors.New("there is more than one route for the same domain")
		}
		seen[m.Routes[i].Domain] = true
	}
	return nil
}
