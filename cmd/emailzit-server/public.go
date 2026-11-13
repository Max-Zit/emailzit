package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/tlsutil"
	"github.com/max-zit/emailzit/internal/web"
)

// webServers are programs that own the ports 80 and 443 when installed
// (HostZit's nginx, or another web server on the same machine).
var webServers = []string{"/usr/sbin/nginx", "/usr/sbin/apache2", "/usr/bin/caddy", "/usr/sbin/lighttpd"}

// startPublic serves autoconfig, Autodiscover and MTA-STS on the standard
// ports 443 and 80 (mode "auto": only on a mail server where no web server
// of its own holds them; "off": never). A web server that appears later
// gets the ports, and when it goes away they are taken back.
func startPublic(ctx context.Context, mode string, srv *web.Server, fallback tls.Certificate, panelAddr string, log *slog.Logger) []*http.Server {
	if mode == "off" || srv.Mail == nil {
		return nil
	}
	// the listeners come and go with the web server of this machine, so
	// they are not handed to the caller; they close when ctx is done
	go (&publicPorts{}).watch(ctx, srv, fallback, panelAddr, log)
	return nil
}

// publicPorts holds the listeners of 80 and 443 while this server has them.
type publicPorts struct {
	mu      sync.Mutex
	servers []*http.Server
}

// watch gives the ports away when a web server of this machine holds them
// and takes them back when it no longer does.
func (p *publicPorts) watch(ctx context.Context, srv *web.Server, fallback tls.Certificate, panelAddr string, log *slog.Logger) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	first := true
	for {
		why := portsTaken()
		p.mu.Lock()
		switch {
		case why != "" && first:
			log.Info("public web ports left to " + why)
		case why != "" && len(p.servers) > 0:
			for _, hs := range p.servers {
				_ = hs.Close()
			}
			p.servers = nil
			log.Info("public web ports handed over to " + why)
		case why == "" && len(p.servers) == 0:
			if !first {
				log.Info("public web ports are free again")
			}
			p.servers = listenPublic(srv, fallback, panelAddr, log)
		}
		first = false
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			p.mu.Lock()
			for _, hs := range p.servers {
				_ = hs.Close()
			}
			p.servers = nil
			p.mu.Unlock()
			return
		case <-t.C:
		}
	}
}

// listenPublic opens 443 and 80 and serves the public pages on them.
func listenPublic(srv *web.Server, fallback tls.Certificate, panelAddr string, log *slog.Logger) []*http.Server {
	_, port, err := net.SplitHostPort(panelAddr)
	if err != nil {
		port = "8444"
	}
	h := srv.PublicHandler(port)
	certs := &fileCert{dir: mailhelper.PublicCertDir, fallback: fallback}
	cfg := tlsutil.ServerConfig(fallback)
	cfg.Certificates = nil
	cfg.GetCertificate = certs.get
	var out []*http.Server
	for _, l := range []struct {
		addr string
		tls  bool
	}{{":443", true}, {":80", false}} {
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			log.Info("public web port not used", "addr", l.addr, "err", err)
			continue
		}
		hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
			IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
		if l.tls {
			ln = tls.NewListener(ln, cfg)
		}
		go func() { _ = hs.Serve(ln) }()
		out = append(out, hs)
		log.Info("listening", "listener", "public (autoconfig, Autodiscover, MTA-STS)", "addr", l.addr)
	}
	return out
}

// portsTaken names the web server of THIS machine that owns the ports 80
// and 443 instead of EmailZit ("" = nobody). A linked HostZit does not
// count: it may run on another server, and then nothing would answer on 80
// and 443 here (MTA-STS, autoconfig and Autodiscover would be dead).
// HostZit on the same machine always installs nginx, which is in the list.
func portsTaken() string {
	for _, p := range webServers {
		if _, err := os.Stat(p); err == nil {
			return "the web server " + p
		}
	}
	return ""
}

// fileCert loads public.crt/public.key (the mail certificate the root
// helper copies for the panel) and reloads them when they change; until
// they exist the panel's own certificate is used.
type fileCert struct {
	dir      string
	fallback tls.Certificate
	mu       sync.Mutex
	cert     *tls.Certificate
	mod      time.Time
	checked  time.Time
}

func (f *fileCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.checked) > time.Minute {
		f.checked = time.Now()
		crt, key := filepath.Join(f.dir, "public.crt"), filepath.Join(f.dir, "public.key")
		if st, err := os.Stat(crt); err == nil && !st.ModTime().Equal(f.mod) {
			if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
				f.cert, f.mod = &c, st.ModTime()
			}
		}
	}
	if f.cert != nil {
		return f.cert, nil
	}
	return &f.fallback, nil
}
