package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/max-zit/emailzit/internal/update"
)

type fakeSys struct {
	mu   sync.Mutex
	cmds []string
	ver  string
}

func (f *fakeSys) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, line)
	if strings.HasSuffix(name, "emailzit-server") && len(args) == 1 && args[0] == "-version" {
		return []byte("emailzit-server " + f.ver), nil
	}
	return nil, nil
}

func (f *fakeSys) ran(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func newHelper(t *testing.T) (*Helper, *fakeSys) {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "var/lib/emailzit")
	_ = os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/bin/emailzit-server"), []byte("old program"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/bin/dpkg"), nil, 0o755)
	_ = os.MkdirAll(filepath.Join(root, "etc/emailzit"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc/emailzit/server.env"), []byte("# config\nEMAILZIT_DB=postgres://cz:pw@localhost/cz\n"), 0o600)
	fs := &fakeSys{ver: "0.3.0"}
	h := &Helper{DataDir: data, CacheDir: filepath.Join(root, "var/cache/emailzit"), Root: root, EnvFile: "/etc/emailzit/server.env",
		Binary: "/usr/bin/emailzit-server", Run: fs.run,
		Dump: func(_ context.Context, url, path string) error {
			return os.WriteFile(path, []byte("dump of "+url), 0o600)
		},
		Restore: func(context.Context, string, string) error { return nil }}
	return h, fs
}

func (h *Helper) submit(t *testing.T, req Request) *Result {
	t.Helper()
	if err := Submit(h.DataDir, req); err != nil {
		t.Fatal(err)
	}
	if err := h.Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if Pending(h.DataDir) {
		t.Fatal("request not removed")
	}
	r, err := ReadResult(h.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func releaseServer(t *testing.T, version string, pkg []byte) (string, func()) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(pkg)
	name := "emailzit-server_" + version + "_" + runtime.GOARCH + ".deb"
	m := update.Manifest{Product: "emailzit", Version: version, Files: []update.File{{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(pkg)), Kind: "server", Format: "deb", Platform: "linux-" + runtime.GOARCH}}}
	raw, _ := json.Marshal(m)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "manifest.json"):
			_, _ = w.Write(raw)
		case strings.HasSuffix(r.URL.Path, "manifest.json.sig"):
			_, _ = w.Write(update.Sign(raw, priv))
		case strings.HasSuffix(r.URL.Path, name):
			_, _ = w.Write(pkg)
		default:
			http.NotFound(w, r)
		}
	}))
	old := update.TrustedKeys
	update.TrustedKeys = []string{base64.StdEncoding.EncodeToString(pub)}
	return srv.URL, func() { srv.Close(); update.TrustedKeys = old }
}

func TestUpdateInstalls(t *testing.T) {
	h, fs := newHelper(t)
	src, done := releaseServer(t, "0.4.0", []byte("new package"))
	defer done()
	_ = os.WriteFile(filepath.Join(h.Root, "etc/emailzit/server.env"), []byte("EMAILZIT_DB=postgres://cz:pw@localhost/cz\nEMAILZIT_UPDATE_SOURCE="+src+"\n"), 0o600)
	h.Healthy = func(context.Context) error { return nil }
	r := h.submit(t, Request{Action: ActionUpdate, Version: "0.4.0", RequestedBy: "admin"})
	if r.Status != "done" {
		t.Fatalf("result %+v", r)
	}
	if !fs.ran("apt-get install -y -q --allow-downgrades "+filepath.Join(h.CacheDir, "packages")) || !fs.ran("systemctl restart emailzit-server") {
		t.Fatalf("commands %v", fs.cmds)
	}
	backups, _ := os.ReadDir(filepath.Join(h.CacheDir, "backups"))
	if len(backups) != 2 {
		t.Fatalf("backups %v", backups)
	}
}

func TestUpdateRollsBack(t *testing.T) {
	h, fs := newHelper(t)
	src, done := releaseServer(t, "0.4.0", []byte("new package"))
	defer done()
	_ = os.WriteFile(filepath.Join(h.Root, "etc/emailzit/server.env"), []byte("EMAILZIT_DB=postgres://cz:pw@localhost/cz\nEMAILZIT_UPDATE_SOURCE="+src+"\n"), 0o600)
	h.Healthy = func(context.Context) error { return errors.New("no answer") }
	restored := false
	h.Restore = func(context.Context, string, string) error { restored = true; return nil }
	// The package "installs" a new program; the rollback puts the old one back.
	h.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "env" {
			_ = os.WriteFile(filepath.Join(h.Root, "usr/bin/emailzit-server"), []byte("new program"), 0o755)
		}
		return fs.run(ctx, name, args...)
	}
	r := h.submit(t, Request{Action: ActionUpdate, Version: "0.4.0"})
	if r.Status != "rolled-back" || !restored {
		t.Fatalf("result %+v (restored %v)", r, restored)
	}
	if b, _ := os.ReadFile(filepath.Join(h.Root, "usr/bin/emailzit-server")); string(b) != "old program" {
		t.Fatalf("program after the rollback: %q", b)
	}
}

func TestUpdateRefused(t *testing.T) {
	h, fs := newHelper(t)
	if r := h.submit(t, Request{Action: ActionUpdate, Version: "0.2.0"}); r.Status != "failed" || !strings.Contains(r.Message, "not newer") {
		t.Fatalf("downgrade: %+v", r)
	}
	src, done := releaseServer(t, "0.4.0", []byte("pkg"))
	defer done()
	update.TrustedKeys = []string{base64.StdEncoding.EncodeToString(make([]byte, 32))} // another key
	_ = os.WriteFile(filepath.Join(h.Root, "etc/emailzit/server.env"), []byte("EMAILZIT_UPDATE_SOURCE="+src+"\n"), 0o600)
	if r := h.submit(t, Request{Action: ActionUpdate, Version: "0.4.0"}); r.Status != "failed" || !strings.Contains(r.Message, "not signed") {
		t.Fatalf("unsigned: %+v", r)
	}
	if fs.ran("apt-get") {
		t.Fatal("installed something")
	}
}

func TestTimeZoneAndNetwork(t *testing.T) {
	h, fs := newHelper(t)
	if r := h.submit(t, Request{Action: ActionTimeZone, TimeZone: "Europe/Belgrade"}); r.Status != "done" || !fs.ran("timedatectl set-timezone Europe/Belgrade") {
		t.Fatalf("time zone: %+v", r)
	}
	if r := h.submit(t, Request{Action: ActionTimeZone, TimeZone: "Europe/Belgrade; reboot"}); r.Status != "failed" {
		t.Fatalf("bad zone: %+v", r)
	}
	net := &NetworkConfig{Address: "192.168.1.20/24", Gateway: "192.168.1.1", DNS: []string{"1.1.1.1"}}
	if r := h.submit(t, Request{Action: ActionNetwork, Network: net}); r.Status != "failed" || !strings.Contains(r.Message, "appliance") {
		t.Fatalf("network outside the appliance: %+v", r)
	}
	_ = os.WriteFile(filepath.Join(h.Root, ApplianceMarker), nil, 0o644)
	h.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return []byte(`[{"dst":"default","gateway":"192.168.1.1","dev":"ens18"}]`), nil
		}
		return fs.run(ctx, name, args...)
	}
	if r := h.submit(t, Request{Action: ActionNetwork, Network: net}); r.Status != "done" {
		t.Fatalf("network: %+v", r)
	}
	b, _ := os.ReadFile(filepath.Join(h.Root, NetworkFile))
	if !strings.Contains(string(b), "Name=ens18") || !strings.Contains(string(b), "Address=192.168.1.20/24") || !strings.Contains(string(b), "DNS=1.1.1.1") {
		t.Fatalf("network file:\n%s", b)
	}
	if r := h.submit(t, Request{Action: ActionNetwork, Network: &NetworkConfig{Address: "192.168.1.20/24", Gateway: "10.0.0.1", DNS: []string{"1.1.1.1"}}}); r.Status != "failed" {
		t.Fatalf("gateway outside the network: %+v", r)
	}
}
