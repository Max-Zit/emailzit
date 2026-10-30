package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/store"
)

type networkData struct {
	N           NetworkSettings
	MgmtText    string
	RunningMgmt string
	Restart     bool
	Override    bool
	ClientIP    string
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	n, err := s.Network(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.showNetwork(w, r, http.StatusOK, n, "")
}

func (s *Server) showNetwork(w http.ResponseWriter, r *http.Request, status int, n NetworkSettings, errMsg string) {
	d := &networkData{N: n, MgmtText: strings.Join(n.MgmtAllowed, "\n"), RunningMgmt: s.RunningMgmt, ClientIP: clientIP(r), Override: s.ListenOverride}
	d.Restart = s.RunningMgmt != "" && !s.ListenOverride && n.MgmtListen != s.RunningMgmt
	p := &Page{Title: "Network and access", Nav: "settings", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "network", p)
}

func (s *Server) handleNetworkSave(w http.ResponseWriter, r *http.Request) {
	n := NetworkSettings{MgmtListen: strings.TrimSpace(r.FormValue("mgmt_listen")), MgmtAllowed: netacl.Split(r.FormValue("mgmt_allowed"))}
	if err := n.Validate(); err != nil {
		s.showNetwork(w, r, http.StatusBadRequest, n, err.Error())
		return
	}
	// Refuse a list that would lock out the administrator who saves it.
	mg, _ := netacl.Parse(n.MgmtAllowed)
	probe := netacl.NewManagement(mg)
	if !probe.AllowsAddr(r.RemoteAddr) {
		s.showNetwork(w, r, http.StatusBadRequest, n, "Your own address would not be allowed any more. Add it to the list.")
		return
	}
	if err := s.SaveNetwork(r.Context(), n); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.network", "settings", "panel %s, allowed %s", n.MgmtListen, strings.Join(n.MgmtAllowed, ", "))
	msg := "Saved."
	if s.RunningMgmt != "" && !s.ListenOverride && n.MgmtListen != s.RunningMgmt {
		msg = "Saved. Restart the EmailZit service to use the new port."
	}
	s.redirect(w, r, "/settings/network", msg)
}

type securityData struct {
	X        SecuritySettings
	Blocks   []store.Block
	FourEyes bool
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	s.showSecurity(w, r, http.StatusOK, s.security(r.Context()), "")
}

func (s *Server) showSecurity(w http.ResponseWriter, r *http.Request, status int, x SecuritySettings, errMsg string) {
	blocks, err := s.store.Blocks(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p := &Page{Title: "Sign-in and security", Nav: "settings", Data: &securityData{X: x, Blocks: blocks, FourEyes: s.fourEyesOn(r.Context())}}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "security", p)
}

func formInt(r *http.Request, k string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(k)))
	return n
}

func (s *Server) handleSecuritySave(w http.ResponseWriter, r *http.Request) {
	x := SecuritySettings{SessionHours: formInt(r, "session_hours"), IdleMinutes: formInt(r, "idle_minutes"), MaxAttempts: formInt(r, "max_attempts"),
		WindowMinutes: formInt(r, "window_minutes"), BlockMinutes: formInt(r, "block_minutes")}
	if err := x.Validate(); err != nil {
		s.showSecurity(w, r, http.StatusBadRequest, x, err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), settingSecurity, x); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.security", "settings", "sessions %dh, idle %dmin; block after %d failures in %dmin for %dmin",
		x.SessionHours, x.IdleMinutes, x.MaxAttempts, x.WindowMinutes, x.BlockMinutes)
	s.redirect(w, r, "/settings/security", "Saved.")
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	if _, ok := netacl.AddrOf(ip); !ok && ip != "all" {
		s.showSecurity(w, r, http.StatusBadRequest, s.security(r.Context()), "Not an IP address.")
		return
	}
	if _, err := s.store.Unblock(r.Context(), ip); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "login.unblock", "ip:"+ip, "sign-in block lifted")
	s.redirect(w, r, "/settings/security", "Block lifted.")
}

// ---- audit log

type auditData struct {
	Entries []store.AuditEntry
	Check   store.AuditCheck
	Q       string
	Next    int64
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.FormValue("before"), 10, 64)
	q := strings.TrimSpace(r.FormValue("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	list, err := s.store.AuditEntries(r.Context(), store.AuditFilter{Query: q, Before: before, Limit: 100})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	check, err := s.store.VerifyAudit(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &auditData{Entries: list, Check: check, Q: q}
	if len(list) == 100 {
		d.Next = list[len(list)-1].ID
	}
	s.render(w, r, http.StatusOK, "audit", &Page{Title: "Audit log", Nav: "audit", Data: d})
}
