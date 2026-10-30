//go:build linux

package mailhelper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"

	"github.com/max-zit/emailzit/internal/mailconf"
)

// Server is the helper service (runs as root).
type Server struct {
	Log *slog.Logger
	// DB reads what the helper must check (role root: SELECT on the
	// mail views, UPDATE of the usage columns only).
	DB *pgxpool.Pool
	// Settings are completed by the helper (database, certificates).
	DBName   string
	CertFile string
	KeyFile  string
	Relay    string // lab: all outgoing mail to a sink
	Policy   string // policy socket
	// VMail is the root of the mail directories.
	VMail string
	// AllowUID may call besides root (the emailzit user).
	AllowUID int
	Run      func(ctx context.Context, name string, args ...string) ([]byte, error)
	mu       sync.Mutex // one change at a time
}

// Serve listens on the socket until ctx ends.
func (s *Server) Serve(ctx context.Context, path string) error {
	if s.Run == nil {
		s.Run = run
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer l.Close()
	// root and the group of the panel user only
	if u, err := user.LookupId(strconv.Itoa(s.AllowUID)); err == nil {
		if g, err := strconv.Atoi(u.Gid); err == nil {
			_ = os.Chown(path, 0, g)
			_ = os.Chown(filepath.Dir(path), 0, g)
		}
	}
	// #nosec G302 -- a socket: the panel's group must connect; every caller is checked by its user ID
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	go s.usageLoop(ctx)
	s.Log.Info("mail helper listening", "socket", path)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, c.(*net.UnixConn))
	}
}

func (s *Server) handle(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Minute))
	reply := func(err error) {
		r := Reply{OK: err == nil}
		if err != nil {
			r.Error = err.Error()
		}
		_ = json.NewEncoder(c).Encode(r)
	}
	uid, err := peerUID(c)
	if err != nil || (uid != 0 && uid != s.AllowUID) {
		s.Log.Warn("mail helper: caller refused", "uid", uid, "err", err)
		reply(errors.New("not allowed"))
		return
	}
	var req Request
	dec := json.NewDecoder(io.LimitReader(bufio.NewReader(c), 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		reply(errors.New("bad request"))
		return
	}
	if err := req.Validate(); err != nil {
		s.Log.Warn("mail helper: invalid request", "action", req.Action, "err", err)
		reply(err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.do(ctx, req)
	if err != nil {
		s.Log.Error("mail helper: request failed", "action", req.Action, "by", req.By, "err", err)
	} else if req.Action != ActionPing {
		s.Log.Info("mail helper: done", "action", req.Action, "by", req.By, "customer", req.Customer, "domain", req.Domain, "local", req.Local)
	}
	reply(err)
}

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if cerr != nil {
		return -1, cerr
	}
	return int(cred.Uid), nil
}

func (s *Server) do(ctx context.Context, r Request) error {
	switch r.Action {
	case ActionPing:
		return nil
	case ActionApply:
		return s.apply(ctx, r)
	case ActionCustomer:
		return s.customerDir(ctx, r)
	case ActionTrash:
		return s.trash(ctx, r)
	}
	return errors.New("unknown action")
}

// ---- configuration

// apply writes the configuration, checks it and reloads; on any error the
// previous files are put back.
func (s *Server) apply(ctx context.Context, r Request) error {
	host := r.Hostname
	if host == "" {
		h, _ := os.Hostname()
		host = strings.ToLower(h)
		if !strings.Contains(host, ".") {
			host += ".localdomain"
		}
	}
	files, err := mailconf.Render(mailconf.Settings{Hostname: host, MaxMessageMB: r.MaxMessageMB, DBName: s.DBName,
		CertFile: s.CertFile, KeyFile: s.KeyFile, Relay: s.Relay, PolicySocket: s.Policy})
	if err != nil {
		return err
	}
	// #nosec G301 -- /etc/postfix/emailzit holds no secret; Postfix reads it
	if err := os.MkdirAll(mailconf.PostfixMaps, 0o755); err != nil {
		return err
	}
	old := map[string][]byte{}
	changed := false
	for _, f := range files {
		prev, err := os.ReadFile(f.Path)
		if err == nil {
			old[f.Path] = prev
			if bytes.Equal(prev, f.Content) {
				continue
			}
		}
		changed = true
		if err := writeFile(f.Path, f.Content, os.FileMode(f.Mode)); err != nil {
			s.restore(old, files)
			return err
		}
		if strings.HasPrefix(f.Path, mailconf.PostfixMaps+"/") {
			// the maps hold no secret, but only Postfix needs them
			_ = os.Chown(f.Path, 0, groupID("postfix"))
		}
	}
	if !changed {
		return nil
	}
	if out, err := s.Run(ctx, "postfix", "check"); err != nil {
		s.restore(old, files)
		return fmt.Errorf("postfix check: %s", firstLine(out, err))
	}
	if out, err := s.Run(ctx, "doveconf", "-n"); err != nil {
		s.restore(old, files)
		return fmt.Errorf("doveconf: %s", firstLine(out, err))
	}
	for _, svc := range []string{"postfix", "dovecot"} {
		if out, err := s.Run(ctx, "systemctl", "reload-or-restart", svc); err != nil {
			s.restore(old, files)
			_, _ = s.Run(ctx, "systemctl", "reload-or-restart", svc)
			return fmt.Errorf("%s: %s", svc, firstLine(out, err))
		}
	}
	return nil
}

func (s *Server) restore(old map[string][]byte, files []mailconf.File) {
	for _, f := range files {
		if b, ok := old[f.Path]; ok {
			_ = writeFile(f.Path, b, os.FileMode(f.Mode))
		} else {
			_ = os.Remove(f.Path)
		}
	}
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".emailzit-new"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func groupID(name string) int {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(g.Gid)
	return n
}

func firstLine(out []byte, err error) string {
	t := strings.TrimSpace(string(out))
	if t == "" {
		return err.Error()
	}
	if i := strings.IndexByte(t, '\n'); i > 0 {
		t = t[:i]
	}
	if len(t) > 300 {
		t = t[:300]
	}
	return t
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// #nosec G204 -- fixed program names with validated arguments
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// ---- mail directories

// customerDir creates /var/vmail/<customer> owned by the customer's own
// user; an existing directory of another owner is never taken over.
func (s *Server) customerDir(ctx context.Context, r Request) error {
	// the database must agree that this UID belongs to this customer
	var number int
	if err := s.DB.QueryRow(ctx, `SELECT number FROM customers WHERE id=$1`, r.Customer).Scan(&number); err != nil {
		return errors.New("unknown customer")
	}
	if MinUID+number != r.UID {
		return errors.New("the user ID does not belong to the customer")
	}
	dir := filepath.Join(s.VMail, r.Customer)
	st, err := os.Lstat(dir)
	if err == nil {
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || int(sys.Uid) != r.UID {
			return errors.New("the directory exists with another owner")
		}
		return nil
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(dir, r.UID, r.UID); err != nil {
		_ = os.Remove(dir)
		return err
	}
	return nil
}

// trash moves the mail of a deleted domain or mailbox to /var/vmail/.trash
// (kept for 7 days). It refuses while the database still has the object,
// so a compromised panel cannot remove mail of a living mailbox.
func (s *Server) trash(ctx context.Context, r Request) error {
	var n int
	q := `SELECT count(*) FROM mda_users WHERE home LIKE $1`
	pat := "/var/vmail/" + r.Customer + "/" + r.Domain + "/%"
	if r.Local != "" {
		q = `SELECT count(*) FROM mda_users WHERE home = $1`
		pat = "/var/vmail/" + r.Customer + "/" + r.Domain + "/" + r.Local
	}
	if err := s.DB.QueryRow(ctx, q, pat).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("the mailbox still exists")
	}
	src := filepath.Join(s.VMail, r.Customer, r.Domain)
	if r.Local != "" {
		src = filepath.Join(src, r.Local)
	}
	if _, err := os.Lstat(src); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	dst := filepath.Join(s.VMail, ".trash", time.Now().UTC().Format("20060102T150405")+"-"+r.Customer+"-"+r.Domain)
	if r.Local != "" {
		dst += "-" + r.Local
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

// ---- usage

// usageLoop stores the used storage of every mailbox (doveadm) every ten
// minutes, and empties the trash of deleted mail after 7 days.
func (s *Server) usageLoop(ctx context.Context) {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.updateUsage(ctx); err != nil {
			s.Log.Warn("mailbox usage", "err", err)
		}
		s.purgeTrash()
		t.Reset(10 * time.Minute)
	}
}

func (s *Server) updateUsage(ctx context.Context) error {
	out, err := s.Run(ctx, "doveadm", "-f", "tab", "quota", "get", "-A")
	if err != nil {
		return fmt.Errorf("doveadm: %s", firstLine(out, err))
	}
	used := map[string]int64{}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return nil
	}
	head := strings.Split(lines[0], "\t")
	col := func(name string) int {
		for i, h := range head {
			if strings.EqualFold(h, name) {
				return i
			}
		}
		return -1
	}
	cu, ct, cv := col("username"), col("type"), col("value")
	if cu < 0 || ct < 0 || cv < 0 {
		return errors.New("unexpected doveadm output")
	}
	for _, l := range lines[1:] {
		f := strings.Split(l, "\t")
		if len(f) <= max(cu, ct, cv) || !strings.EqualFold(f[ct], "STORAGE") {
			continue
		}
		kb, err := strconv.ParseInt(f[cv], 10, 64)
		if err == nil {
			used[f[cu]] = kb << 10
		}
	}
	for addr, b := range used {
		if _, err := s.DB.Exec(ctx, `UPDATE mailboxes SET used_bytes=$2, used_at=now() WHERE address=$1`, addr, b); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) purgeTrash() {
	dir := filepath.Join(s.VMail, ".trash")
	list, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range list {
		info, err := e.Info()
		if err == nil && time.Since(info.ModTime()) > 7*24*time.Hour {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

// Start applies the configuration once (at the start of the service).
func (s *Server) Start(ctx context.Context, r Request) error {
	if s.Run == nil {
		s.Run = run
	}
	if err := r.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apply(ctx, r)
}

// EnsureCustomerDirs creates missing mail directories of all customers (at
// start: customers created while the helper was not running).
func (s *Server) EnsureCustomerDirs(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT id::text, number FROM customers WHERE status <> 'terminated'`)
	if err != nil {
		return err
	}
	type cust struct {
		id  string
		num int
	}
	var list []cust
	for rows.Next() {
		var c cust
		if err := rows.Scan(&c.id, &c.num); err != nil {
			rows.Close()
			return err
		}
		list = append(list, c)
	}
	rows.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range list {
		if err := s.customerDir(ctx, Request{Action: ActionCustomer, Customer: c.id, UID: MinUID + c.num}); err != nil {
			s.Log.Error("customer mail directory", "customer", c.id, "err", err)
		}
	}
	return nil
}
