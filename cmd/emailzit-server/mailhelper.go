package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/max-zit/emailzit/internal/logfile"
	"github.com/max-zit/emailzit/internal/mailhelper"
)

// runMailHelper is the root mail helper service. It connects to the
// database as role root over the local socket (peer authentication), writes
// the mail configuration once at start, then serves the panel.
func runMailHelper(ctx context.Context, dbURL, relay string) error {
	if os.Geteuid() != 0 {
		return errors.New("the mail helper must run as root")
	}
	out := io.Writer(os.Stdout)
	if lw, err := logfile.Open("/var/log/emailzit-helper/mail-helper.log", 0o640); err == nil {
		defer lw.Close()
		out = io.MultiWriter(os.Stdout, lw)
	}
	log := slog.New(slog.NewTextHandler(out, nil))
	if dbURL == "" {
		dbURL = "postgres:///emailzit?host=/var/run/postgresql&user=root"
	}
	db, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return err
	}
	defer db.Close()
	u, err := user.Lookup("emailzit")
	if err != nil {
		return fmt.Errorf("user emailzit: %w", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	s := &mailhelper.Server{Log: log, DB: db, DBName: "emailzit", CertFile: "/etc/emailzit/tls/mail.crt", KeyFile: "/etc/emailzit/tls/mail.key",
		Relay: relay, VMail: "/var/vmail", AllowUID: uid}
	// the configuration as saved in the panel (defaults until then)
	req := mailhelper.Request{Action: mailhelper.ActionApply, MaxMessageMB: 50, By: "start"}
	var raw []byte
	if err := db.QueryRow(ctx, `SELECT value::text FROM settings WHERE key='mail'`).Scan(&raw); err == nil {
		var m struct {
			Hostname     string `json:"hostname"`
			MaxMessageMB int    `json:"max_message_mb"`
		}
		if json.Unmarshal(raw, &m) == nil {
			req.Hostname = m.Hostname
			if m.MaxMessageMB > 0 {
				req.MaxMessageMB = m.MaxMessageMB
			}
		}
	}
	if err := s.Start(ctx, req); err != nil {
		log.Error("writing the mail configuration at start failed", "err", err)
	}
	if err := s.EnsureCustomerDirs(ctx); err != nil {
		log.Error("customer mail directories", "err", err)
	}
	return s.Serve(ctx, mailhelper.Socket)
}

// mailHelperInstalled reports a system with the mail helper service (the
// Linux packages); without it the panels only manage the database.
func mailHelperInstalled() bool {
	for _, p := range []string{"/etc/systemd/system/emailzit-mail-helper.service", "/usr/lib/systemd/system/emailzit-mail-helper.service", "/lib/systemd/system/emailzit-mail-helper.service"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// listenPolicy opens the policy socket inside the Postfix queue directory
// (prepared by the mail helper); nil without a mail system.
func listenPolicy() (net.Listener, error) {
	if _, err := os.Stat(mailhelper.PolicyDir); err != nil {
		return nil, nil
	}
	p := filepath.Join(mailhelper.PolicyDir, "policy")
	_ = os.Remove(p)
	l, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	// the directory admits only the group postfix; every caller is checked
	// by its user ID
	// #nosec G302 -- see above
	if err := os.Chmod(p, 0o666); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}
