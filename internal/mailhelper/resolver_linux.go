package mailhelper

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/mailconf"
)

// The local resolver (Unbound). It always answers on 127.0.0.1:5335 for
// Rspamd. When nothing else uses port 53 (HostZit's PowerDNS binds the
// wildcard address, so no loopback address is free then), it also answers
// on 127.0.0.1:53 and /etc/resolv.conf points to it: Postfix then gets
// DNSSEC-validated answers and checks DANE.

const (
	resolvConf = "/etc/resolv.conf"
	// the server's own resolv.conf before EmailZit replaced it: a copy of
	// the file, or the target of the symbolic link
	resolvSaved    = "/var/lib/emailzit/resolv.conf.orig"
	resolvSavedLnk = "/var/lib/emailzit/resolv.conf.link"
	resolvOurs     = "# EmailZit: the local resolver (Unbound); the original is saved in /var/lib/emailzit/resolv.conf.*\nnameserver 127.0.0.1\noptions edns0 trust-ad\n"
	postfixResolv  = "/var/spool/postfix/etc/resolv.conf"
)

func unboundInstalled() bool {
	_, err := os.Stat("/usr/sbin/unbound")
	return err == nil
}

// systemResolverPossible tells whether Unbound may take 127.0.0.1:53: no
// PowerDNS on the server, and the port is free or already Unbound's.
func (s *Server) systemResolverPossible(ctx context.Context) bool {
	if !unboundInstalled() {
		return false
	}
	if _, err := os.Stat("/usr/sbin/pdns_server"); err == nil {
		return false
	}
	// #nosec G304 -- fixed path
	b, err := os.ReadFile(mailconf.UnboundConf)
	if err == nil && bytes.Contains(b, []byte("127.0.0.1@53\n")) {
		if _, err := s.Run(ctx, "systemctl", "is-active", "--quiet", "unbound"); err == nil {
			return true
		}
	}
	if portFree("127.0.0.1:53") {
		return true
	}
	// Debian's package starts Unbound with its own configuration (port 53)
	// right after it is installed; ours, written next, replaces it
	if err != nil {
		if _, err := s.Run(ctx, "systemctl", "is-active", "--quiet", "unbound"); err == nil {
			_, _ = s.Run(ctx, "systemctl", "stop", "unbound")
			return portFree("127.0.0.1:53")
		}
	}
	return false
}

func portFree(addr string) bool {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = l.Close()
	p, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	_ = p.Close()
	return true
}

// startUnbound (re)starts Unbound after its file changed.
func (s *Server) startUnbound(ctx context.Context) error {
	if out, err := s.Run(ctx, "unbound-checkconf"); err != nil {
		return errors.New("unbound-checkconf: " + firstLine(out, err))
	}
	if out, err := s.Run(ctx, "systemctl", "enable", "unbound"); err != nil {
		return errors.New("unbound: " + firstLine(out, err))
	}
	if out, err := s.Run(ctx, "systemctl", "restart", "unbound"); err != nil {
		return errors.New("unbound: " + firstLine(out, err))
	}
	return nil
}

// resolves tells whether the resolver at addr answers.
func resolves(ctx context.Context, addr string) bool {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	for i := 0; i < 5; i++ {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := r.LookupNS(c, ".")
		cancel()
		if err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
	return false
}

// useSystemResolver points /etc/resolv.conf to Unbound (on) or puts the
// original back (off). Switching on happens only when Unbound answers.
func (s *Server) useSystemResolver(ctx context.Context, on bool) {
	// #nosec G304 -- fixed path
	cur, _ := os.ReadFile(resolvConf)
	ours := bytes.HasPrefix(cur, []byte("# EmailZit"))
	if fi, err := os.Lstat(resolvConf); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		ours = false
	}
	switch {
	case on && !ours:
		if !resolves(ctx, "127.0.0.1:53") {
			s.Log.Warn("the local resolver does not answer; the server keeps its DNS servers (no DANE)")
			return
		}
		if err := os.MkdirAll(filepath.Dir(resolvSaved), 0o755); err != nil { // #nosec G301 -- /var/lib/emailzit exists already
			s.Log.Warn("resolver", "err", err)
			return
		}
		_ = os.Remove(resolvSaved)
		_ = os.Remove(resolvSavedLnk)
		if t, err := os.Readlink(resolvConf); err == nil {
			if err := writeFile(resolvSavedLnk, []byte(t), 0o644); err != nil {
				s.Log.Warn("resolver", "err", err)
				return
			}
		} else if err := writeFile(resolvSaved, cur, 0o644); err != nil {
			s.Log.Warn("resolver", "err", err)
			return
		}
		_ = os.Remove(resolvConf)
		if err := writeFile(resolvConf, []byte(resolvOurs), 0o644); err != nil {
			s.Log.Error("resolver: writing /etc/resolv.conf failed", "err", err)
			s.restoreResolver()
			return
		}
		s.Log.Info("the server resolves through the local resolver (DANE on)")
	case !on && ours:
		s.restoreResolver()
		s.Log.Info("the server's own DNS servers are back in /etc/resolv.conf")
	default:
		return
	}
	// Postfix's chroot keeps a copy
	if b, err := os.ReadFile(resolvConf); err == nil {
		if _, err := os.Stat(filepath.Dir(postfixResolv)); err == nil {
			_ = writeFile(postfixResolv, b, 0o644)
		}
	}
}

func (s *Server) restoreResolver() {
	// #nosec G304 -- fixed paths
	if t, err := os.ReadFile(resolvSavedLnk); err == nil {
		_ = os.Remove(resolvConf)
		if err := os.Symlink(strings.TrimSpace(string(t)), resolvConf); err != nil {
			s.Log.Error("resolver: restoring the link failed", "err", err)
		}
		return
	}
	if b, err := os.ReadFile(resolvSaved); err == nil {
		_ = os.Remove(resolvConf)
		_ = writeFile(resolvConf, b, 0o644)
		return
	}
	// nothing saved: the provider's DHCP will write it again; until then a
	// public resolver keeps the server working
	_ = writeFile(resolvConf, []byte("nameserver 9.9.9.9\nnameserver 1.1.1.1\n"), 0o644)
}

// checkResolver runs in the usage loop: if Unbound stopped answering on
// port 53, or PowerDNS arrived (HostZit installed later), the server gets
// its own DNS servers back and the configuration is written again.
func (s *Server) checkResolver(ctx context.Context) {
	// #nosec G304 -- fixed path
	cur, _ := os.ReadFile(resolvConf)
	if !bytes.HasPrefix(cur, []byte("# EmailZit")) {
		return
	}
	_, pdns := os.Stat("/usr/sbin/pdns_server")
	if pdns != nil && resolves(ctx, "127.0.0.1:53") {
		return
	}
	s.Log.Warn("the local resolver is not usable on port 53; switching back to the server's DNS servers")
	s.restoreResolver()
	if b, err := os.ReadFile(resolvConf); err == nil {
		_ = writeFile(postfixResolv, b, 0o644)
	}
	if s.last != nil {
		if err := s.apply(ctx, *s.last); err != nil {
			s.Log.Warn("applying without the system resolver", "err", err)
		}
	}
	// PowerDNS (HostZit) could not start while Unbound held port 53
	if pdns == nil {
		if _, err := s.Run(ctx, "systemctl", "is-active", "--quiet", "pdns"); err != nil {
			_, _ = s.Run(ctx, "systemctl", "reset-failed", "pdns")
			_, _ = s.Run(ctx, "systemctl", "restart", "pdns")
		}
	}
}

// ---- domains for the display name check (Rspamd multimap)

// writeLocalDomains writes the mail domains of the server as regular
// expressions (a domain as a whole word); Rspamd reloads the map itself.
func (s *Server) writeLocalDomains(ctx context.Context) error {
	if s.DB == nil || !rspamdInstalled() {
		return nil
	}
	rows, err := s.DB.Query(ctx, `SELECT name FROM mta_domains ORDER BY name`)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	b.WriteString("# EmailZit: the mail domains of this server (written by the mail helper)\n")
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		if !domainRE.MatchString(n) {
			continue
		}
		b.WriteString(`/(^|[^a-z0-9.-])` + regexp.QuoteMeta(n) + `($|[^a-z0-9-])/i` + "\n")
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// #nosec G304 -- fixed path
	if old, err := os.ReadFile(mailconf.RspamdLocalDomains); err == nil && bytes.Equal(old, b.Bytes()) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(mailconf.RspamdLocalDomains), 0o750); err != nil {
		return err
	}
	if err := writeFile(mailconf.RspamdLocalDomains, b.Bytes(), 0o644); err != nil {
		return err
	}
	_ = os.Chown(mailconf.RspamdLocalDomains, 0, groupID("_rspamd"))
	return nil
}

// presentAddrs marks the outbound addresses configured on this server.
func presentAddrs(list []mailconf.OutboundIP) []mailconf.OutboundIP {
	have := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				have[n.IP.String()] = true
			}
		}
	}
	out := make([]mailconf.OutboundIP, len(list))
	for i, o := range list {
		o.Present = have[o.Address]
		out[i] = o
	}
	return out
}

// keepUnbound starts Unbound again when its file is there but it stopped.
func (s *Server) keepUnbound(ctx context.Context) {
	if !unboundInstalled() {
		return
	}
	if _, err := os.Stat(mailconf.UnboundConf); err != nil {
		return
	}
	if _, err := s.Run(ctx, "systemctl", "is-active", "--quiet", "unbound"); err != nil {
		if err := s.startUnbound(ctx); err != nil {
			s.Log.Warn("local resolver", "err", err)
		}
	}
}
