package mailhelper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// notice puts a message from the server (quota warning) straight into the
// Inbox of a mailbox: written as a new Maildir file owned by the mailbox's
// user, no SMTP involved.
func (s *Server) notice(ctx context.Context, r Request) error {
	addr := r.Local + "@" + r.Domain
	var uid int
	var home string
	if err := s.DB.QueryRow(ctx, `SELECT uid, home FROM mda_users WHERE username=$1`, addr).Scan(&uid, &home); err != nil {
		return errors.New("unknown mailbox")
	}
	customer := strings.TrimPrefix(home, s.VMail+"/")
	if i := strings.IndexByte(customer, '/'); i > 0 {
		customer = customer[:i]
	}
	if err := s.prepareMaildir(customer, home, uid); err != nil {
		return err
	}
	dir := filepath.Join(home, "Maildir")
	for _, sub := range []string{"tmp", "new", "cur"} {
		if err := ownedDir(filepath.Join(dir, sub), uid, true); err != nil {
			return err
		}
	}
	host, _ := os.Hostname()
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	now := time.Now()
	name := fmt.Sprintf("%d.%s.%s", now.Unix(), hex.EncodeToString(b), strings.ReplaceAll(host, "/", "_"))
	msg := "From: " + mime.QEncoding.Encode("utf-8", "Mail server") + " <postmaster@" + s.nginxHostOr(host) + ">\r\n" +
		"To: <" + addr + ">\r\n" +
		"Subject: " + mime.QEncoding.Encode("utf-8", r.Subject) + "\r\n" +
		"Date: " + now.Format(time.RFC1123Z) + "\r\n" +
		"Message-ID: <" + hex.EncodeToString(b) + "@emailzit>\r\n" +
		"Auto-Submitted: auto-generated\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(r.Body, "\n", "\r\n") + "\r\n"
	tmp := filepath.Join(dir, "tmp", name)
	// #nosec G304 -- a new file in the mailbox user's own tmp directory (checked above)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(msg)
	if err := f.Chown(uid, uid); werr == nil {
		werr = err
	}
	if err := f.Close(); werr == nil {
		werr = err
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	return os.Rename(tmp, filepath.Join(dir, "new", name))
}

func (s *Server) nginxHostOr(fallback string) string {
	if s.nginxHost != "" {
		return s.nginxHost
	}
	return fallback
}
