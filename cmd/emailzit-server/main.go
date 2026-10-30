// emailzit-server is the EmailZit server: it polls the devices, stores the
// panel, the mail users' pages and the REST API (and, as --helper, the root
// helper).
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/max-zit/emailzit/internal/auth"
	"github.com/max-zit/emailzit/internal/authpolicy"
	"github.com/max-zit/emailzit/internal/helper"
	"github.com/max-zit/emailzit/internal/logfile"
	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/policy"
	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/tlsutil"
	"github.com/max-zit/emailzit/internal/web"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "EmailZit")
		}
	}
	return "/var/lib/emailzit"
}

func run() error {
	dataDir := flag.String("data-dir", env("EMAILZIT_DATA", defaultDataDir()), "data directory (certificates, secret key, logs)")
	dbURL := flag.String("db", os.Getenv("EMAILZIT_DB"), "PostgreSQL URL, e.g. postgres://emailzit:…@localhost/emailzit")
	devDB := flag.Bool("dev-embedded-db", false, "start a private PostgreSQL in the data directory (development and evaluation only)")
	mgmtListen := flag.String("mgmt-listen", "", "panel address; overrides the saved setting (e.g. 127.0.0.1:8444)")
	devHTTP := flag.String("dev-http", "", "also serve the panels over plain HTTP on this loopback address (development only)")
	devNo2FA := flag.Bool("dev-no-2fa", false, "sign in with the password only (development only, needs --dev-embedded-db; shown as a warning and audited)")
	resetACL := flag.Bool("reset-allowlist", false, "allow the panels again from the private networks (10/8, 172.16/12, 192.168/16, fc00::/7) and exit")
	unblock := flag.String("unblock-ip", "", "lift the sign-in block of an address (or \"all\") and exit")
	resetPass := flag.String("reset-password", "", "set a new password for this staff account (read from standard input; it must be changed at the next sign-in), lift sign-in blocks and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	runHelper := flag.Bool("helper", false, "root helper: handle a request of the console (updates, time zone, network) and exit; started by emailzit-helper.service")
	restoreFile := flag.String("restore", "", "restore this backup of the panel (database, keys, certificates) and exit; stop the server first")
	restorePass := flag.String("restore-passphrase-file", "", "file with the passphrase of the backup (or set EMAILZIT_BACKUP_PASSPHRASE)")
	mailHelper := flag.Bool("mail-helper", false, "root mail helper: serve the panel's mail requests (configuration, mail directories) on "+mailhelper.Socket+"; started by emailzit-mail-helper.service")
	mailRelay := flag.String("mail-relay", os.Getenv("EMAILZIT_MAIL_RELAY"), "mail helper: send all outgoing mail through this host, e.g. [192.168.1.5]:1025 (test labs)")
	publicWeb := flag.String("public-web", "auto", "serve autoconfig, Autodiscover and MTA-STS on the ports 443 and 80: auto (only when no web server is installed and HostZit is not linked) or off")
	flag.Parse()

	if *showVersion {
		fmt.Println("emailzit-server", version)
		return nil
	}
	if *devNo2FA && !*devDB {
		return errors.New("--dev-no-2fa works only together with --dev-embedded-db")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *restoreFile != "" {
		if *dbURL == "" {
			return errors.New("database URL required (--db or EMAILZIT_DB)")
		}
		return restoreBackup(ctx, *restoreFile, *restorePass, *dataDir, *dbURL)
	}
	if *mailHelper {
		return runMailHelper(ctx, *dbURL, *mailRelay)
	}
	if *runHelper {
		// Its own log in a directory only root can write.
		out := io.Writer(os.Stdout)
		if lw, err := logfile.Open("/var/log/emailzit-helper/helper.log", 0o644); err == nil {
			_ = os.Chmod("/var/log/emailzit-helper", 0o755) // #nosec G302 -- the console reads it, only root writes
			defer lw.Close()
			out = io.MultiWriter(os.Stdout, lw)
		}
		hlog := slog.New(slog.NewTextHandler(out, nil))
		h := &helper.Helper{DataDir: *dataDir, CacheDir: "/var/cache/emailzit", EnvFile: "/etc/emailzit/server.env", Binary: "/usr/bin/emailzit-server",
			Run: helper.RunCommand, Log: func(format string, args ...any) { hlog.Info(fmt.Sprintf(format, args...)) }}
		return h.Handle(ctx)
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	var logOut io.Writer = os.Stdout
	if lw, err := logfile.Open(filepath.Join(*dataDir, "logs", "server.log"), 0o600); err == nil {
		defer lw.Close()
		logOut = io.MultiWriter(os.Stdout, lw)
	}
	log := slog.New(slog.NewTextHandler(logOut, nil))

	if *devDB {
		pg, url, err := startEmbeddedDB(*dataDir)
		if err != nil {
			return fmt.Errorf("embedded database: %w", err)
		}
		defer pg.Stop()
		*dbURL = url
		log.Warn("using the embedded development database", "dir", filepath.Join(*dataDir, "pgdata"))
	}
	if *dbURL == "" {
		return errors.New("database URL required (--db or EMAILZIT_DB)")
	}
	st, err := store.Open(ctx, *dbURL)
	if err != nil {
		return err
	}
	defer st.Close()
	key, created, err := store.LoadOrCreateSecretKey(*dataDir)
	if err != nil {
		return fmt.Errorf("secret key: %w", err)
	}
	if err := st.GrantMailRoles(ctx); err != nil {
		return fmt.Errorf("database roles of the mail software: %w", err)
	}
	if err := st.UseSecretKey(key); err != nil {
		return err
	}
	if created {
		log.Warn("created a new secret key; back it up together with the database", "file", filepath.Join(*dataDir, store.SecretKeyFile))
	}

	switch {
	case *resetACL:
		if err := web.ResetMgmtAllowList(ctx, st); err != nil {
			return err
		}
		_ = st.Audit(ctx, "-", "local", "settings.network.reset", "settings", "console allow-list reset to the private networks from the command line")
		fmt.Println("The console allows the private networks again. Restart the service if it is running.")
		return nil
	case *resetPass != "":
		u, err := st.StaffByUsername(ctx, *resetPass)
		if err != nil {
			return fmt.Errorf("no staff account %q", *resetPass)
		}
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if err := st.SetPassword(ctx, u.ID, strings.TrimRight(line, "\r\n"), true, ""); err != nil {
			return err
		}
		_, _ = st.Unblock(ctx, "all")
		_ = st.Audit(ctx, "-", "local", "user.password.reset", "user:"+u.Username, "password set from the server's command line (must be changed at the next sign-in); sign-in blocks lifted")
		fmt.Printf("The password of %s is set; it must be changed at the next sign-in. Sign-in blocks were lifted.\n", u.Username)
		return nil
	case *unblock != "":
		n, err := st.Unblock(ctx, *unblock)
		if err != nil {
			return err
		}
		_ = st.Audit(ctx, "-", "local", "login.unblock", "ip:"+*unblock, "sign-in block lifted from the command line")
		fmt.Printf("Lifted %d block(s).\n", n)
		return nil
	}

	srv, err := web.New(ctx, st, log)
	if err != nil {
		return err
	}
	srv.Version = version
	srv.DataDir = *dataDir
	if mailHelperInstalled() {
		srv.Mail = &web.HelperMail{C: &mailhelper.Client{Socket: mailhelper.Socket}}
	} else {
		log.Warn("no mail helper on this system: the panels manage only the database (development)")
	}
	if *devNo2FA {
		srv.DevNo2FA = true
		log.Warn("TEST MODE: two-factor sign-in is switched off (--dev-no-2fa); never use this on a production server")
		_ = st.Audit(ctx, "-", "local", "settings.2fa.off", "server", "server started with --dev-no-2fa: sign-in with the password only")
	}
	net0, err := srv.Network(ctx)
	if err != nil {
		return err
	}
	if *mgmtListen != "" {
		net0.MgmtListen = *mgmtListen
	}
	if err := net0.Validate(); err != nil {
		return err
	}
	srv.RunningMgmt = net0.MgmtListen
	srv.ListenOverride = *mgmtListen != ""

	consoleCert, err := tlsutil.LoadOrCreate(filepath.Join(*dataDir, "tls"), "panel", "EmailZit panel", 5)
	if err != nil {
		return fmt.Errorf("console certificate: %w", err)
	}

	if n, err := st.UserCount(ctx); err != nil {
		return err
	} else if n == 0 {
		tok := auth.RandomToken(18)
		p := filepath.Join(*dataDir, "setup-token.txt")
		if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
			return err
		}
		srv.SetSetupToken(tok)
		srv.SetupTokenFile = p
		log.Warn("no users yet: open the console and finish the setup; the setup token is in the file", "file", p)
	}

	errc := make(chan error, 3)
	var servers []*http.Server
	raw, err := net.Listen("tcp", net0.MgmtListen)
	if err != nil {
		return fmt.Errorf("console listener %s: %w", net0.MgmtListen, err)
	}
	cfg := tlsutil.ServerConfig(consoleCert)
	l := tls.NewListener(&netacl.Listener{Listener: raw, List: srv.MgmtACL, OnRefuse: func(remote string) {
		log.Debug("connection refused by allow-list", "remote", remote)
	}}, cfg)
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
	servers = append(servers, hs)
	go func() { errc <- hs.Serve(l) }()
	log.Info("listening", "listener", "console", "addr", raw.Addr().String())
	servers = append(servers, startPublic(ctx, *publicWeb, srv, consoleCert, raw.Addr().String(), log)...)
	if *devHTTP != "" {
		a, ok := netacl.AddrOf(*devHTTP)
		if !ok || !a.IsLoopback() {
			return errors.New("--dev-http must be a loopback address such as 127.0.0.1:8080")
		}
		dh := &http.Server{Addr: *devHTTP, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, dh)
		go func() { errc <- dh.ListenAndServe() }()
		log.Warn("development HTTP console (no TLS)", "addr", *devHTTP)
	}
	if tok := readAuthPolicyToken(); tok != "" {
		g := &authpolicy.Guard{Token: tok, Log: log}
		if srv.Mail != nil {
			hc := &mailhelper.Client{Socket: mailhelper.Socket}
			g.Ban = func(ip netip.Addr, d time.Duration) {
				if err := hc.Call(context.Background(), mailhelper.Request{Action: mailhelper.ActionBan, IP: ip.String(), Minutes: int(d.Minutes()), By: "auth-guard"}); err != nil {
					log.Error("firewall block", "ip", ip, "err", err)
				}
				_ = st.Audit(context.Background(), "-", ip.String(), "mail.login.blocked", "ip:"+ip.String(), "address blocked after failed mail sign-ins")
			}
		}
		gs := &http.Server{Addr: "127.0.0.1:10032", Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
		servers = append(servers, gs)
		go func() {
			if err := gs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("mail sign-in guard stopped", "err", err)
			}
		}()
		log.Info("mail sign-in guard listening", "addr", gs.Addr)
	}
	log.Info("EmailZit server started", "version", version)

	go srv.RunUpdates(ctx)
	go srv.SyncMail(ctx)
	go srv.RunImports(ctx)
	go srv.RunQuotaWarnings(ctx)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			srv.RunBackups(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	if pl, err := listenPolicy(); err != nil {
		log.Error("policy service (sending limits) not started", "err", err)
	} else if pl != nil {
		ps := &policy.Service{Store: st, Log: log, AllowUID: mailhelper.PostfixUID(), PeerUID: mailhelper.PeerUID,
			Blocked: func(address, reason string) {
				_ = st.Audit(context.Background(), "-", "local", "mailbox.send.blocked", "mailbox:"+address, "sending blocked automatically: "+reason)
			}}
		go func() {
			if err := ps.Serve(ctx, pl); err != nil {
				log.Error("policy service stopped", "err", err)
			}
		}()
		log.Info("policy service listening", "socket", pl.Addr().String())
	}
	startSubmit(ctx, st, srv, log)
	// For the root helper: which version runs and where (it checks this after an update).
	if err := helper.WriteServerInfo(*dataDir, helper.ServerInfo{Version: version, MgmtListen: net0.MgmtListen}); err != nil {
		log.Warn("cannot write the helper information", "err", err)
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = st.PurgeSessions(ctx)
				_ = st.PurgeMailSessions(ctx)
				_ = st.PurgeSendLog(ctx)
			}
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	stop()
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, h := range servers {
		_ = h.Shutdown(shut)
	}
	log.Info("stopped")
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// startEmbeddedDB runs PostgreSQL from the data directory on a fixed
// loopback port (development only).
func startEmbeddedDB(dir string) (*embeddedpostgres.EmbeddedPostgres, string, error) {
	const port = 54359
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().Port(port).
		DataPath(filepath.Join(dir, "pgdata")).RuntimePath(filepath.Join(dir, "pgrt")).
		BinariesPath(filepath.Join(dir, "pgbin")).Database("emailzit").Logger(io.Discard))
	// A server that was killed (not stopped) leaves its PostgreSQL running;
	// stop that one first so a restart works.
	if _, err := os.Stat(filepath.Join(dir, "pgdata", "postmaster.pid")); err == nil {
		ctl := filepath.Join(dir, "pgbin", "bin", "pg_ctl")
		if runtime.GOOS == "windows" {
			ctl += ".exe"
		}
		_ = exec.Command(ctl, "stop", "-D", filepath.Join(dir, "pgdata"), "-m", "fast").Run() // #nosec G204 -- our own binary in the data directory
	}
	if err := pg.Start(); err != nil {
		return nil, "", err
	}
	return pg, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/emailzit?sslmode=disable", port), nil
}
