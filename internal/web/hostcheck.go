package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// The check of the mail host name (Settings → Mail server): does the name
// point at the server's addresses, and do those addresses point back
// (PTR)? Receivers such as Gmail and Outlook refuse mail from addresses
// without a matching PTR record, over IPv6 even more strictly.

type hostAddr struct {
	IP      netip.Addr
	Public  bool
	Forward bool     // the host name resolves to this address
	PTR     []string // what the address resolves back to
	PTROK   bool     // one of them is the host name
}

type hostCheck struct {
	Hostname string
	Resolved []netip.Addr // A and AAAA of the host name
	Err      string       // the host name does not resolve
	Addrs    []hostAddr   // the addresses this server sends from
	// IPv6Bad: the server sends over a public IPv6 address that does not
	// match the host name both ways (switch on "IPv4 only").
	IPv6Bad bool
}

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// sourceAddrs are the addresses outgoing connections use: a UDP "connect"
// picks the route without sending anything.
func sourceAddrs() []netip.Addr {
	var out []netip.Addr
	for _, target := range []string{"192.0.2.1:25", "[2001:db8::1]:25"} {
		c, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
		_ = c.Close()
	}
	return out
}

func checkHost(ctx context.Context, res resolver, host string, local []netip.Addr) *hostCheck {
	hc := &hostCheck{Hostname: host}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := res.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		hc.Err = label("The host name does not resolve to an address.")
	}
	for _, ip := range ips {
		hc.Resolved = append(hc.Resolved, ip.Unmap())
	}
	for _, ip := range local {
		a := hostAddr{IP: ip, Public: ip.IsGlobalUnicast() && !ip.IsPrivate()}
		for _, r := range hc.Resolved {
			a.Forward = a.Forward || r == ip
		}
		names, _ := res.LookupAddr(ctx, ip.String())
		for _, n := range names {
			n = strings.TrimSuffix(strings.ToLower(n), ".")
			a.PTR = append(a.PTR, n)
			a.PTROK = a.PTROK || n == host
		}
		if ip.Is6() && a.Public && !(a.Forward && a.PTROK) {
			hc.IPv6Bad = true
		}
		hc.Addrs = append(hc.Addrs, a)
	}
	return hc
}

type mailSettingsData struct {
	MailSettings
	Check *hostCheck
}

func (s *Server) handleMailSettingsCheck(w http.ResponseWriter, r *http.Request) {
	m := s.MailConfig(r.Context())
	d := &mailSettingsData{MailSettings: m}
	if m.Hostname != "" {
		d.Check = checkHost(r.Context(), net.DefaultResolver, m.Hostname, sourceAddrs())
	}
	s.render(w, r, http.StatusOK, "mailsettings", &Page{Title: "Mail server", Nav: "settings", Data: d})
}
