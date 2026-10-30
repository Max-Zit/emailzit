package mailhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/max-zit/emailzit/internal/mailconf"
	"github.com/max-zit/emailzit/internal/sieve"
)

// writeSpam writes the Sieve spam script into the mail home of every
// mailbox (or of one customer, or one mailbox) from the database; Dovecot
// runs it before the user's own filters. Only changed scripts are written.
func (s *Server) writeSpam(ctx context.Context, r Request) error {
	q := `SELECT address, customer_id::text, uid, home, level, allow, block FROM mda_spam WHERE ($1 = '' OR customer_id::text = $1)`
	args := []any{r.Customer}
	if r.Local != "" {
		q += ` AND address = $2`
		args = append(args, r.Local+"@"+r.Domain)
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return err
	}
	type box struct {
		address, customer, home, level string
		uid                            int
		allow, block                   []string
	}
	var list []box
	for rows.Next() {
		var b box
		if err := rows.Scan(&b.address, &b.customer, &b.uid, &b.home, &b.level, &b.allow, &b.block); err != nil {
			rows.Close()
			return err
		}
		list = append(list, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var failed int
	for _, b := range list {
		if err := s.writeSpamScript(b.customer, b.home, b.uid, sieve.SpamScript(b.level, b.allow, b.block)); err != nil {
			failed++
			s.Log.Warn("spam script", "mailbox", b.address, "err", err)
		}
	}
	if failed > 0 && r.Local != "" {
		return errors.New("the spam settings could not be written")
	}
	return nil
}

// writeSpamScript puts one script into a mail home, creating the home when
// the mailbox never received mail. Every directory on the way must be a
// real directory of the mailbox's user; nothing is followed.
func (s *Server) writeSpamScript(customer, home string, uid int, script string) error {
	if uid < MinUID || uid > MaxUID {
		return errors.New("invalid user ID")
	}
	base := filepath.Join(s.VMail, customer)
	rel, err := filepath.Rel(base, home)
	if !uuidRE.MatchString(customer) || err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return errors.New("unexpected mail home")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 || !domainRE.MatchString(parts[0]) || !localRE.MatchString(parts[1]) {
		return errors.New("unexpected mail home")
	}
	if err := ownedDir(base, uid, false); err != nil {
		return err
	}
	dir := base
	for _, p := range append(parts, filepath.Dir(mailconf.MailboxSpamSieve)) {
		dir = filepath.Join(dir, p)
		if err := ownedDir(dir, uid, true); err != nil {
			return err
		}
	}
	path := filepath.Join(dir, filepath.Base(mailconf.MailboxSpamSieve))
	// #nosec G304 -- path built from the validated customer, domain and local part; only compared
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, []byte(script)) {
		return nil
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	// #nosec G304 -- see above; O_EXCL|O_NOFOLLOW in a directory checked to be the mailbox user's
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(script)
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
	return os.Rename(tmp, path)
}

// ownedDir checks (and with create, makes) a directory owned by uid.
func ownedDir(dir string, uid int, create bool) error {
	st, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		return os.Chown(dir, uid, uid)
	}
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || int(sys.Uid) != uid {
		return fmt.Errorf("%s is not a directory of the mailbox's user", dir)
	}
	return nil
}
