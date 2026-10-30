package mailhelper

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/max-zit/emailzit/internal/mailimport"
)

// importMail writes the mail files of an uploaded archive
// (/var/lib/emailzit/imports/<customer>/<name>.tar.gz) into the Maildirs of
// the customer's mailboxes. Only mailboxes of that customer that exist in the
// database are filled; existing files are never overwritten (running it
// again is harmless); every path stays inside the mailbox through os.Root.
func (s *Server) importMail(ctx context.Context, r Request) (*ImportResult, error) {
	rows, err := s.DB.Query(ctx, `SELECT username, uid, home FROM mda_users WHERE home LIKE $1`, "/var/vmail/"+r.Customer+"/%")
	if err != nil {
		return nil, err
	}
	type box struct {
		uid  int
		home string
	}
	boxes := map[string]box{}
	for rows.Next() {
		var a string
		var b box
		if err := rows.Scan(&a, &b.uid, &b.home); err != nil {
			rows.Close()
			return nil, err
		}
		boxes[strings.ToLower(a)] = b
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	src := filepath.Join(ImportDir, r.Customer, r.Name+".tar.gz")
	st, err := os.Lstat(src)
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("the uploaded archive is missing")
	}
	// #nosec G304 -- customer UUID and name validated, a regular file checked above
	f, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &ImportResult{}
	roots := map[string]*os.Root{}
	defer func() {
		for _, rt := range roots {
			_ = rt.Close()
		}
	}()
	unknown := map[string]bool{}
	err = mailimport.Each(f, r.Format, func(addr, rel string, h *tar.Header, body io.Reader) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, ok := boxes[addr]
		if !ok {
			if !unknown[addr] {
				unknown[addr] = true
				res.UnknownMailboxes = append(res.UnknownMailboxes, addr)
			}
			return nil
		}
		if skipFile(rel) {
			return nil
		}
		rt := roots[addr]
		if rt == nil {
			if err := s.prepareMaildir(r.Customer, b.home, b.uid); err != nil {
				return fmt.Errorf("%s: %w", addr, err)
			}
			var err error
			if rt, err = os.OpenRoot(filepath.Join(b.home, "Maildir")); err != nil {
				return fmt.Errorf("%s: %w", addr, err)
			}
			roots[addr] = rt
		}
		// the folders on the way, owned by the mailbox user
		dir := ""
		for _, p := range strings.Split(path.Dir(rel), "/") {
			if p == "." {
				break
			}
			dir = path.Join(dir, p)
			if err := rt.Mkdir(dir, 0o700); err == nil {
				_ = rt.Lchown(dir, b.uid, b.uid)
			} else if !errors.Is(err, fs.ErrExist) {
				return nil // a name that cannot be a folder here: skip the file
			}
		}
		out, err := rt.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if errors.Is(err, fs.ErrExist) {
			res.Existing++
			return nil
		}
		if err != nil {
			return nil
		}
		_, werr := io.Copy(out, io.LimitReader(body, h.Size))
		if err := out.Chown(b.uid, b.uid); werr == nil {
			werr = err
		}
		if err := out.Close(); werr == nil {
			werr = err
		}
		if werr != nil {
			_ = rt.Remove(rel)
			return werr
		}
		_ = rt.Chtimes(rel, h.ModTime, h.ModTime)
		res.Files++
		res.Bytes += h.Size
		if !contains(res.Mailboxes, addr) {
			res.Mailboxes = append(res.Mailboxes, addr)
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	// Dovecot counts the new mail against the quota
	for _, a := range res.Mailboxes {
		_, _ = s.Run(ctx, "doveadm", "quota", "recalc", "-u", a)
	}
	return res, nil
}

// skipFile leaves out what the old server's Dovecot or cPanel rebuild
// anyway (indexes, quota file); the UID list stays so mail programs keep
// their state.
func skipFile(rel string) bool {
	b := path.Base(rel)
	return strings.HasPrefix(b, "dovecot.index") || strings.HasPrefix(b, "dovecot.list.index") || b == "maildirsize" || strings.HasPrefix(b, ".nfs")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// prepareMaildir makes the home and its Maildir, owned by the mailbox user.
func (s *Server) prepareMaildir(customer, home string, uid int) error {
	base := filepath.Join(s.VMail, customer)
	rel, err := filepath.Rel(base, home)
	parts := strings.Split(rel, string(filepath.Separator))
	if err != nil || len(parts) != 2 || !domainRE.MatchString(parts[0]) || !localRE.MatchString(parts[1]) {
		return errors.New("unexpected mail home")
	}
	if err := ownedDir(base, uid, false); err != nil {
		return err
	}
	dir := base
	for _, p := range append(parts, "Maildir") {
		dir = filepath.Join(dir, p)
		if err := ownedDir(dir, uid, true); err != nil {
			return err
		}
	}
	return nil
}
