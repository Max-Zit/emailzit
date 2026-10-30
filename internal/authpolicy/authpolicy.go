// Package authpolicy protects the sign-in of mail programs (IMAP, POP3,
// SMTP submission) against password guessing. Dovecot asks it before every
// sign-in and reports the result afterwards (Dovecot's auth policy
// protocol, JSON over HTTP on the loopback interface with a shared token).
// An address with too many failures is refused for a while and, through
// the root helper, blocked in the firewall; an account attacked from many
// addresses is slowed down (never locked, so attackers cannot lock users
// out).
package authpolicy

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Limits of the guard.
const (
	IPFailures      = 10               // failures of one address …
	IPWindow        = 15 * time.Minute // … within this time …
	IPBan           = time.Hour        // … block it for this long
	AccountFailures = 30               // failures of one account within an hour: slow it down
	AccountDelay    = 5                // seconds
)

// Guard keeps the failure counts.
type Guard struct {
	Token string // the Authorization header Dovecot sends: "Bearer <token>"
	Log   *slog.Logger
	// Ban blocks an address in the firewall (root helper); may be nil.
	Ban func(ip netip.Addr, d time.Duration)
	// Allow are addresses never blocked (the server itself, admin networks).
	Allow func(ip netip.Addr) bool
	Now   func() time.Time

	mu     sync.Mutex
	ips    map[netip.Addr]*entry
	logins map[string]*entry
}

type entry struct {
	fails  []time.Time
	banned time.Time // until
}

func (g *Guard) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// request is what Dovecot sends (the default attributes).
type request struct {
	Login   string `json:"login"`
	Remote  string `json:"remote"`
	Success *bool  `json:"success"`
	// FailType is why it failed (credentials, account, expired, disabled,
	// policy, internal …); PolicyReject: refused by this guard.
	FailType     string `json:"fail_type"`
	PolicyReject bool   `json:"policy_reject"`
}

type reply struct {
	Status int    `json:"status"`
	Msg    string `json:"msg,omitempty"`
}

// ServeHTTP answers /?command=allow and /?command=report.
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	want := "Bearer " + g.Token
	if g.Token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req request
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip, _ := netip.ParseAddr(strings.TrimSpace(req.Remote))
	login := strings.ToLower(strings.TrimSpace(req.Login))
	var rep reply
	switch r.URL.Query().Get("command") {
	case "allow":
		rep = g.allow(ip, login)
	case "report":
		if req.Success != nil && !*req.Success && !req.PolicyReject && req.FailType != "" && req.FailType != "internal" {
			g.fail(ip, login)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}

func prune(l []time.Time, since time.Time) []time.Time {
	i := 0
	for i < len(l) && l[i].Before(since) {
		i++
	}
	return l[i:]
}

func (g *Guard) allow(ip netip.Addr, login string) reply {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if e := g.ips[ip]; ip.IsValid() && e != nil && now.Before(e.banned) {
		return reply{Status: -1, Msg: "Too many failed sign-ins from your address; try again later."}
	}
	if e := g.logins[login]; login != "" && e != nil {
		e.fails = prune(e.fails, now.Add(-time.Hour))
		if len(e.fails) >= AccountFailures {
			return reply{Status: AccountDelay}
		}
	}
	return reply{}
}

// fail counts a failed sign-in.
func (g *Guard) fail(ip netip.Addr, login string) {
	g.mu.Lock()
	now := g.now()
	if g.ips == nil {
		g.ips, g.logins = map[netip.Addr]*entry{}, map[string]*entry{}
	}
	var ban bool
	if ip.IsValid() && !ip.IsLoopback() && (g.Allow == nil || !g.Allow(ip)) {
		e := g.ips[ip]
		if e == nil {
			e = &entry{}
			g.ips[ip] = e
		}
		e.fails = append(prune(e.fails, now.Add(-IPWindow)), now)
		if len(e.fails) >= IPFailures && now.After(e.banned) {
			e.banned, e.fails, ban = now.Add(IPBan), nil, true
		}
	}
	if login != "" {
		e := g.logins[login]
		if e == nil {
			e = &entry{}
			g.logins[login] = e
		}
		e.fails = append(prune(e.fails, now.Add(-time.Hour)), now)
	}
	// keep the maps small
	if len(g.ips) > 100000 || len(g.logins) > 100000 {
		for k, e := range g.ips {
			if now.After(e.banned) && len(prune(e.fails, now.Add(-IPWindow))) == 0 {
				delete(g.ips, k)
			}
		}
		for k, e := range g.logins {
			if len(prune(e.fails, now.Add(-time.Hour))) == 0 {
				delete(g.logins, k)
			}
		}
	}
	g.mu.Unlock()
	if ban {
		if g.Log != nil {
			g.Log.Warn("mail sign-in: address blocked after failed sign-ins", "ip", ip.String(), "login", login, "for", IPBan)
		}
		if g.Ban != nil {
			g.Ban(ip, IPBan)
		}
	}
}

// Banned lists the addresses blocked right now (for the panel).
func (g *Guard) Banned() map[netip.Addr]time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[netip.Addr]time.Time{}
	now := g.now()
	for ip, e := range g.ips {
		if now.Before(e.banned) {
			out[ip] = e.banned
		}
	}
	return out
}

// Unban lifts the block of an address.
func (g *Guard) Unban(ip netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.ips, ip)
}
