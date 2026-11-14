package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/submit"
	"github.com/max-zit/emailzit/internal/tlsutil"
	"github.com/max-zit/emailzit/internal/web"
)

// startHostZitRelay takes mail from the websites of a linked HostZit that runs on
// ANOTHER server (INTEGRATION.md E3). The port is open only while the link
// has a relay login, and only for the addresses of that HostZit: the
// pairing wrote them into the link, and the watcher follows them.
func startHostZitRelay(ctx context.Context, st *store.Store, srv *web.Server, cert tls.Certificate, log *slog.Logger) {
	if srv.Mail == nil {
		return // no mail server on this machine
	}
	go (&relayPort{}).watch(ctx, st, srv, cert, log)
}

// relayPort holds the listener while a relay login exists.
type relayPort struct {
	mu     sync.Mutex
	l      net.Listener
	acl    *netacl.List
	addrs  string // the allowed addresses, as last seen
	failed bool   // the port could not be opened (said once)
}

func (p *relayPort) watch(ctx context.Context, st *store.Store, srv *web.Server, cert tls.Certificate, log *slog.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		login, err := st.RelayLoginOf(ctx)
		switch {
		case err != nil && !errors.Is(err, store.ErrNotFound):
			log.Error("relay: the login cannot be read", "err", err)
		case err != nil: // no link with a relay login
			p.close(log)
		default:
			p.open(ctx, st, srv, cert, login.Username, log)
		}
		select {
		case <-ctx.Done():
			p.close(log)
			return
		case <-t.C:
		}
	}
}

// open starts the listener, or only follows the allowed addresses when it
// already runs.
func (p *relayPort) open(ctx context.Context, st *store.Store, srv *web.Server, cert tls.Certificate, user string, log *slog.Logger) {
	nets, list := relayNets(ctx, srv)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.l != nil {
		if list != p.addrs {
			p.acl.Set(nets)
			p.addrs = list
			log.Info("relay: allowed addresses changed", "addresses", list)
		}
		return
	}
	addr := ":" + strconv.Itoa(submit.RelayPort)
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		// something else holds the port: say so once, not every half minute
		if !p.failed {
			p.failed = true
			log.Error("relay: the port cannot be opened", "addr", addr, "err", err)
		}
		return
	}
	p.failed = false
	p.acl = netacl.NewManagement(nets)
	p.addrs = list
	p.l = &netacl.Listener{Listener: raw, List: p.acl, OnRefuse: func(remote string) {
		log.Warn("relay: connection refused by the allow-list", "remote", remote)
	}}
	cfg := tlsutil.ServerConfig(cert)
	rs := &submit.RelayServer{Store: st, Log: log, TLS: cfg,
		Hostname: func(ctx context.Context) string { return srv.MailConfig(ctx).Hostname },
		MaxBytes: func(ctx context.Context) int64 { return int64(srv.MailConfig(ctx).MaxMessageMB) << 20 },
		Dial:     postfixDial,
		Hosted:   srv.HostedDomain,
	}
	l := p.l
	go func() {
		if err := rs.Serve(ctx, l); err != nil {
			log.Error("relay: stopped", "err", err)
		}
	}()
	log.Info("listening", "listener", "relay for the websites of HostZit", "addr", addr, "user", user, "addresses", list)
}

func (p *relayPort) close(log *slog.Logger) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.l == nil {
		return
	}
	_ = p.l.Close()
	p.l, p.acl, p.addrs = nil, nil, ""
	log.Info("relay: the port is closed again (no link with a relay login)")
}

// relayNets are the addresses of the linked HostZit (loopback always may,
// for a test on the server itself).
func relayNets(ctx context.Context, srv *web.Server) ([]netip.Prefix, string) {
	addrs := srv.HostZitAddresses(ctx)
	nets, err := netacl.Parse(addrs)
	if err != nil {
		nets = nil
	}
	return nets, strings.Join(addrs, ", ")
}
