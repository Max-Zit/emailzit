package helper

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/update"
)

// update installs a newer signed release: download and verify the package,
// back up the database and the current program, install, and check that
// the console comes back. If it does not, the old program and the
// database backup are put back.
func (h *Helper) update(ctx context.Context, req Request, res Result) Result {
	fail := func(format string, args ...any) Result {
		res.Status, res.Message = "failed", fmt.Sprintf(format, args...)
		return res
	}
	installed := h.installedVersion(ctx)
	if !update.Newer(req.Version, installed) {
		return fail("version %s is not newer than the installed %s", req.Version, installed)
	}
	env := h.env()
	source := env["WATCHZIT_UPDATE_SOURCE"]
	if source == "" {
		source = update.DefaultSource
	}
	hc := &http.Client{Timeout: 10 * time.Minute}
	m, _, _, err := update.Fetch(ctx, hc, source, req.Version)
	if err != nil {
		return fail("%v", err)
	}
	if m.Version != req.Version {
		return fail("the release is %s, not %s", m.Version, req.Version)
	}
	format := "rpm"
	if _, err := os.Stat(h.path("/usr/bin/dpkg")); err == nil {
		format = "deb"
	}
	f := m.Find("server", format, "linux-"+runtime.GOARCH)
	if f == nil {
		return fail("the release has no %s package for linux-%s", format, runtime.GOARCH)
	}
	pkgDir := filepath.Join(h.CacheDir, "packages")
	if err := os.MkdirAll(pkgDir, 0o700); err != nil {
		return fail("%v", err)
	}
	pkg := filepath.Join(pkgDir, f.Name)
	h.logf("downloading %s", f.Name)
	if err := update.Download(ctx, hc, source, req.Version, *f, pkg); err != nil {
		return fail("%v", err)
	}
	// Backups for a rollback.
	bdir := filepath.Join(h.CacheDir, "backups")
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		return fail("%v", err)
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	dump := filepath.Join(bdir, "emailzit-"+installed+"-"+stamp+".dump")
	h.logf("backing up the database to %s", dump)
	dumpFn, restoreFn := h.dumpDB, h.restoreDB
	if h.Dump != nil {
		dumpFn, restoreFn = h.Dump, h.Restore
	}
	if err := dumpFn(ctx, env["WATCHZIT_DB"], dump); err != nil {
		return fail("database backup failed, nothing was changed: %v", err)
	}
	prevBin := filepath.Join(bdir, "emailzit-server-"+installed)
	if err := copyFile(h.path(h.Binary), prevBin, 0o700); err != nil {
		return fail("cannot keep the current program, nothing was changed: %v", err)
	}
	h.prune(bdir)
	h.logf("installing %s", f.Name)
	var ierr error
	if format == "deb" {
		_, ierr = h.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-q", "--allow-downgrades", pkg)
	} else {
		_, ierr = h.Run(ctx, "dnf", "install", "-y", "-q", pkg)
	}
	if ierr == nil {
		_, ierr = h.Run(ctx, "systemctl", "restart", "emailzit-server")
	}
	if ierr == nil {
		ierr = h.healthy(ctx, req.Version)
	}
	if ierr == nil {
		res.Status, res.Message = "done", "EmailZit "+req.Version+" is installed"
		return res
	}
	// Roll back: the previous program and the database as it was.
	h.logf("update failed (%v); rolling back to %s", ierr, installed)
	_, _ = h.Run(ctx, "systemctl", "stop", "emailzit-server")
	rb := []string{}
	if err := copyFile(prevBin, h.path(h.Binary), 0o755); err != nil {
		rb = append(rb, "program: "+err.Error())
	}
	if err := restoreFn(ctx, env["WATCHZIT_DB"], dump); err != nil {
		rb = append(rb, "database: "+err.Error())
	}
	_, _ = h.Run(ctx, "systemctl", "start", "emailzit-server")
	res.Status = "rolled-back"
	res.Message = fmt.Sprintf("the update to %s failed (%v); version %s is running again", req.Version, ierr, installed)
	if len(rb) > 0 {
		res.Status = "failed"
		res.Message += "; the rollback was incomplete: " + strings.Join(rb, "; ")
	}
	return res
}

func (h *Helper) installedVersion(ctx context.Context) string {
	out, err := h.Run(ctx, h.path(h.Binary), "-version")
	if err != nil {
		return "0.0.0"
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return "0.0.0"
	}
	return f[len(f)-1]
}

// env reads the console's configuration file (KEY=value lines).
func (h *Helper) env() map[string]string {
	out := map[string]string{}
	f, err := os.Open(h.path(h.EnvFile)) // #nosec G304 -- the console's configuration
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return out
}

// pgEnv turns a postgres:// URL into libpq variables, so the password is
// not on a command line (other users can read those).
func pgEnv(dbURL string) ([]string, error) {
	u, err := url.Parse(dbURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, errors.New("WATCHZIT_DB is not a postgres:// URL")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host, port = u.Host, "5432"
	}
	pass, _ := u.User.Password()
	env := []string{"PGHOST=" + host, "PGPORT=" + port, "PGUSER=" + u.User.Username(), "PGPASSWORD=" + pass,
		"PGDATABASE=" + strings.TrimPrefix(u.Path, "/"), "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if m := u.Query().Get("sslmode"); m != "" {
		env = append(env, "PGSSLMODE="+m)
	}
	return env, nil
}

func (h *Helper) dumpDB(ctx context.Context, dbURL, path string) error {
	env, err := pgEnv(dbURL)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "pg_dump", "-Fc", "-f", path) // #nosec G204 -- fixed program, our own path
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pg_dump: %v: %s", err, lastLines(string(out), 3))
	}
	return os.Chmod(path, 0o600)
}

func (h *Helper) restoreDB(ctx context.Context, dbURL, path string) error {
	env, err := pgEnv(dbURL)
	if err != nil {
		return err
	}
	var db string
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PGDATABASE="); ok {
			db = v
		}
	}
	cmd := exec.CommandContext(ctx, "pg_restore", "--clean", "--if-exists", "--no-owner", "-d", db, path) // #nosec G204 -- fixed program, our own path
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pg_restore: %v: %s", err, lastLines(string(out), 3))
	}
	return nil
}

// prune keeps the three newest database backups and programs.
func (h *Helper) prune(dir string) {
	for _, prefix := range []string{"emailzit-server-", "emailzit-"} {
		ents, _ := os.ReadDir(dir)
		var names []string
		for _, e := range ents {
			n := e.Name()
			isProg := strings.HasPrefix(n, "emailzit-server-")
			if strings.HasPrefix(n, prefix) && isProg == (prefix == "emailzit-server-") {
				names = append(names, n)
			}
		}
		sort.Slice(names, func(i, j int) bool {
			a, _ := os.Stat(filepath.Join(dir, names[i]))
			b, _ := os.Stat(filepath.Join(dir, names[j]))
			return a != nil && b != nil && a.ModTime().After(b.ModTime())
		})
		for i, n := range names {
			if i >= 3 {
				_ = os.Remove(filepath.Join(dir, n))
			}
		}
	}
}

// healthy waits until the console of the new version answers.
func (h *Helper) healthy(ctx context.Context, version string) error {
	if h.Healthy != nil {
		return h.Healthy(ctx)
	}
	deadline := time.Now().Add(2 * time.Minute)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- the local console, only checked for an answer
	var last error
	for time.Now().Before(deadline) {
		var info ServerInfo
		if b, err := os.ReadFile(filepath.Join(h.dir(), ServerFile)); err == nil && json.Unmarshal(b, &info) == nil && info.Version == version {
			_, port, err := net.SplitHostPort(info.MgmtListen)
			if err == nil {
				resp, err := hc.Get("https://" + net.JoinHostPort("127.0.0.1", port) + "/login")
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						return nil
					}
					last = fmt.Errorf("the console answered HTTP %d", resp.StatusCode)
				} else {
					last = err
				}
			}
		} else {
			last = errors.New("the new version did not start")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the console did not come back: %v", last)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- fixed paths
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) // #nosec G302 G304 -- fixed paths, a program
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
