//go:build linux

package mailhelper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
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
	case ActionDKIM:
		return s.dkim(ctx, r)
	case ActionBan:
		return s.ban(ctx, r)
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
		CertFile: s.CertFile, KeyFile: s.KeyFile, Relay: s.Relay, PolicySocket: s.policySocket(), Rspamd: rspamdInstalled(),
		AuthPolicyToken: s.authPolicyToken()})
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
	fixOwners()
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
	return s.afterApply(ctx)
}

func (s *Server) restore(old map[string][]byte, files []mailconf.File) {
	defer fixOwners()
	for _, f := range files {
		if b, ok := old[f.Path]; ok {
			_ = writeFile(f.Path, b, os.FileMode(f.Mode))
		} else {
			_ = os.Remove(f.Path)
		}
	}
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	// #nosec G301 -- configuration directories of the mail software
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".emailzit-new"
	// #nosec G703 -- fixed configuration paths; domain and selector names are validated
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
	if r.Local == "" && rspamdInstalled() {
		if err := s.setSelector(r.Domain, ""); err != nil {
			return err
		}
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
	if err := s.preparePolicyDir(); err != nil {
		s.Log.Error("policy directory", "err", err)
	}
	s.prepareFirewall(ctx)
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

// ---- policy service, Rspamd, DKIM

// PolicyDir is where the panel's policy socket lives: inside the Postfix
// queue directory (smtpd runs chrooted there), owned by the panel user,
// readable by the group postfix.
const PolicyDir = "/var/spool/postfix/emailzit"

func (s *Server) policySocket() string {
	if s.Policy != "" {
		return s.Policy
	}
	if _, err := os.Stat(PolicyDir); err == nil {
		return "emailzit/policy"
	}
	return ""
}

// preparePolicyDir creates PolicyDir for the panel user.
func (s *Server) preparePolicyDir() error {
	if err := os.MkdirAll(PolicyDir, 0o750); err != nil {
		return err
	}
	return os.Chown(PolicyDir, s.AllowUID, groupID("postfix"))
}

func rspamdInstalled() bool {
	_, err := os.Stat("/usr/bin/rspamd")
	return err == nil
}

// afterApply checks and reloads Rspamd and compiles the spam filter.
func (s *Server) afterApply(ctx context.Context) error {
	if !rspamdInstalled() {
		return nil
	}
	if err := os.MkdirAll(mailconf.RspamdDKIM, 0o750); err != nil {
		return err
	}
	_ = os.Chown(mailconf.RspamdDKIM, 0, groupID("_rspamd"))
	_ = os.Chown(filepath.Dir(mailconf.RspamdDKIM), 0, groupID("_rspamd"))
	if _, err := os.Stat(mailconf.RspamdDKIMMap); errors.Is(err, os.ErrNotExist) {
		if err := writeFile(mailconf.RspamdDKIMMap, nil, 0o644); err != nil {
			return err
		}
	}
	if out, err := s.Run(ctx, "sievec", mailconf.SpamSieve); err != nil {
		return fmt.Errorf("sievec: %s", firstLine(out, err))
	}
	if out, err := s.Run(ctx, "rspamadm", "configtest"); err != nil {
		return fmt.Errorf("rspamd: %s", firstLine(out, err))
	}
	if out, err := s.Run(ctx, "systemctl", "reload-or-restart", "rspamd"); err != nil {
		return fmt.Errorf("rspamd: %s", firstLine(out, err))
	}
	return nil
}

// dkim installs the signing key of a domain that exists in the database.
func (s *Server) dkim(ctx context.Context, r Request) error {
	if !rspamdInstalled() {
		return errors.New("rspamd is not installed")
	}
	var n int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM domains WHERE name=$1`, r.Domain).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return errors.New("unknown domain")
	}
	if err := os.MkdirAll(mailconf.RspamdDKIM, 0o750); err != nil {
		return err
	}
	_ = os.Chown(mailconf.RspamdDKIM, 0, groupID("_rspamd"))
	_ = os.Chown(filepath.Dir(mailconf.RspamdDKIM), 0, groupID("_rspamd"))
	p := filepath.Join(mailconf.RspamdDKIM, r.Domain+"."+r.Selector+".key")
	if err := writeFile(p, []byte(r.Key), 0o640); err != nil {
		return err
	}
	_ = os.Chown(p, 0, groupID("_rspamd"))
	return s.setSelector(r.Domain, r.Selector)
}

// setSelector writes the domain's line in the selector map ("" removes it
// and the domain's keys).
func (s *Server) setSelector(domain, selector string) error {
	old, _ := os.ReadFile(mailconf.RspamdDKIMMap)
	var lines []string
	for _, l := range strings.Split(string(old), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] != domain {
			lines = append(lines, l)
		}
	}
	if selector != "" {
		lines = append(lines, domain+" "+selector)
	} else {
		keys, _ := filepath.Glob(filepath.Join(mailconf.RspamdDKIM, domain+".*.key"))
		for _, k := range keys {
			_ = os.Remove(k)
		}
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return writeFile(mailconf.RspamdDKIMMap, []byte(content), 0o644)
}

// PeerUID is the user ID of the process on the other end of a Unix socket.
func PeerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a Unix socket")
	}
	return peerUID(uc)
}

// PostfixUID is the user ID of postfix (-1 if unknown).
func PostfixUID() int {
	u, err := user.Lookup("postfix")
	if err != nil {
		return -1
	}
	n, _ := strconv.Atoi(u.Uid)
	return n
}

// fixOwners gives the Postfix maps back to the group postfix (a rewrite or
// a rollback creates new files owned by root).
func fixOwners() {
	maps, _ := filepath.Glob(filepath.Join(mailconf.PostfixMaps, "*.cf"))
	g := groupID("postfix")
	for _, m := range maps {
		_ = os.Chown(m, 0, g)
		_ = os.Chmod(m, 0o640) // #nosec G302 -- the group postfix reads the maps
	}
}

// ---- brute-force guard: token shared with the panel, firewall blocks

// AuthPolicyTokenFile holds the token Dovecot sends to the panel's guard.
const AuthPolicyTokenFile = "/etc/emailzit/auth-policy.token"

// authPolicyToken reads (or creates) the token; the panel user may read it.
func (s *Server) authPolicyToken() string {
	if b, err := os.ReadFile(AuthPolicyTokenFile); err == nil {
		if t := strings.TrimSpace(string(b)); len(t) >= 32 {
			return t
		}
	}
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	t := hex.EncodeToString(raw[:])
	if err := writeFile(AuthPolicyTokenFile, []byte(t+"\n"), 0o640); err != nil {
		s.Log.Error("auth policy token", "err", err)
		return ""
	}
	if u, err := user.LookupId(strconv.Itoa(s.AllowUID)); err == nil {
		if g, err := strconv.Atoi(u.Gid); err == nil {
			_ = os.Chown(AuthPolicyTokenFile, 0, g)
		}
	}
	return t
}

// nftRules is EmailZit's own firewall table: blocked addresses lose the
// mail sign-in ports and the panels (port 25 stays open: other servers).
const nftRules = `table inet emailzit {
	set banned4 { type ipv4_addr; flags timeout; }
	set banned6 { type ipv6_addr; flags timeout; }
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @banned4 tcp dport { 110, 143, 465, 587, 993, 995, 4190, 8444 } drop
		ip6 saddr @banned6 tcp dport { 110, 143, 465, 587, 993, 995, 4190, 8444 } drop
	}
}
`

// prepareFirewall creates the table once (nft must be installed).
func (s *Server) prepareFirewall(ctx context.Context) {
	if _, err := exec.LookPath("nft"); err != nil {
		s.Log.Warn("nft is not installed: failed sign-ins are refused by the panel, but not blocked in the firewall")
		return
	}
	if _, err := s.Run(ctx, "nft", "list", "table", "inet", "emailzit"); err == nil {
		return
	}
	p := "/run/emailzit/nft.rules"
	if err := writeFile(p, []byte(nftRules), 0o600); err != nil {
		s.Log.Error("firewall rules", "err", err)
		return
	}
	if out, err := s.Run(ctx, "nft", "-f", p); err != nil {
		s.Log.Error("firewall rules", "err", firstLine(out, err))
	}
}

// ban adds an address to the blocked set for a while.
func (s *Server) ban(ctx context.Context, r Request) error {
	a, _ := netip.ParseAddr(r.IP)
	set := "banned4"
	if a.Is6() && !a.Is4In6() {
		set = "banned6"
	}
	elem := fmt.Sprintf("{ %s timeout %dm }", a.Unmap().String(), r.Minutes)
	if out, err := s.Run(ctx, "nft", "add", "element", "inet", "emailzit", set, elem); err != nil {
		return fmt.Errorf("nft: %s", firstLine(out, err))
	}
	return nil
}
