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
// ports 443 and 80 (mode "auto": only on a mail server without a web
// server and without a HostZit link; "off": never).
func startPublic(ctx context.Context, mode string, srv *web.Server, fallback tls.Certificate, panelAddr string, log *slog.Logger) []*http.Server {
	if mode == "off" || srv.Mail == nil {
		return nil
	}
	for _, p := range webServers {
		if _, err := os.Stat(p); err == nil {
			log.Info("public web ports left to the web server", "program", p)
			return nil
		}
	}
	if srv.HostZitLinked(ctx) {
		log.Info("public web ports left to HostZit")
		return nil
	}
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
