// Package helper is the root side of the console: the console runs as the
// unprivileged emailzit user and asks for the few things that need root
// (installing a new version, the time zone, the appliance's network) by
// writing request.json into <data-dir>/helper. A systemd path unit then
// starts "emailzit-server --helper", which does the work and writes
// result.json.
//
// The helper trusts nothing in the request beyond the wish itself: a new
// version must be a release signed with a EmailZit release key (checked
// again here, on files only root can write) and newer than the installed
// one; time zones and network settings are validated.
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Actions.
const (
	ActionUpdate    = "update"
	ActionTimeZone  = "timezone"
	ActionNetwork   = "network"
	ActionRestart   = "restart"
	ActionSSH       = "ssh"        // Request.SSH (appliance)
	ActionOSStatus  = "os-status"  // refresh os-status.json
	ActionOSAuto    = "os-auto"    // automatic security updates on/off (Enable)
	ActionOSUpgrade = "os-upgrade" // install all operating system updates
	ActionReboot    = "reboot"     // restart the server
)

// Request is what the console asks for.
type Request struct {
	Action      string         `json:"action"`
	Version     string         `json:"version,omitempty"`
	TimeZone    string         `json:"timezone,omitempty"`
	Network     *NetworkConfig `json:"network,omitempty"`
	SSH         *SSHConfig     `json:"ssh,omitempty"`
	Enable      bool           `json:"enable,omitempty"` // ActionOSAuto
	RequestedBy string         `json:"requested_by"`
	At          time.Time      `json:"at"`
}

// Result is what the helper did.
type Result struct {
	Action   string    `json:"action"`
	Status   string    `json:"status"` // running, done, failed, rolled-back
	Message  string    `json:"message"`
	Version  string    `json:"version,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	restart  bool      // restart the console after writing the result
}

// Files in <data-dir>/helper.
const (
	RequestFile = "request.json"
	ResultFile  = "result.json"
	// ServerFile is written by the console at start: where it listens, so
	// the helper can check that it came back after an update.
	ServerFile = "server.json"
)

// ServerInfo is ServerFile.
type ServerInfo struct {
	Version    string `json:"version"`
	MgmtListen string `json:"mgmt_listen"`
}

// Helper does the work. The fields let tests use a temporary root and a
// fake command runner.
type Helper struct {
	DataDir  string // /var/lib/emailzit
	CacheDir string // /var/cache/emailzit (root only)
	Root     string // "" in production
	EnvFile  string // /etc/emailzit/server.env
	Binary   string // /usr/bin/emailzit-server
	Source   string // release location (default update.DefaultSource)
	Log      func(format string, args ...any)
	Run      func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Healthy checks that the console answers (tests replace it).
	Healthy func(ctx context.Context) error
	// Dump and Restore back up and restore the database (tests replace them).
	Dump, Restore func(ctx context.Context, dbURL, path string) error
}

// RunCommand runs a program (the real Run).
func RunCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed programs with validated arguments
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(lastLines(string(out), 5)))
	}
	return out, nil
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " | ")
}

func (h *Helper) path(p string) string { return filepath.Join(h.Root, p) }

func (h *Helper) dir() string { return filepath.Join(h.DataDir, "helper") }

func (h *Helper) logf(format string, args ...any) {
	if h.Log != nil {
		h.Log(format, args...)
	}
}

// Handle processes a pending request, if any.
func (h *Helper) Handle(ctx context.Context) error {
	reqPath := filepath.Join(h.dir(), RequestFile)
	b, err := os.ReadFile(reqPath) // #nosec G304 -- the console's helper directory
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Remove it first: a request is handled once, even if it fails.
	_ = os.Remove(reqPath)
	if len(b) > 64<<10 {
		return errors.New("request too large")
	}
	var req Request
	if err := json.Unmarshal(b, &req); err != nil {
		return h.finish(Result{Action: "unknown", Status: "failed", Message: "unreadable request", Started: time.Now().UTC()})
	}
	res := Result{Action: req.Action, Status: "running", Started: time.Now().UTC(), Version: req.Version}
	_ = h.write(res)
	h.logf("%s requested by %s", req.Action, req.RequestedBy)
	switch req.Action {
	case ActionUpdate:
		res = h.update(ctx, req, res)
	case ActionTimeZone:
		res = h.timeZone(ctx, req, res)
	case ActionNetwork:
		res = h.network(ctx, req, res)
	case ActionRestart:
		res.Status, res.Message, res.restart = "done", "the console restarts", true
	case ActionSSH:
		res = h.ssh(ctx, req, res)
	case ActionOSStatus, ActionOSAuto, ActionOSUpgrade:
		res = h.osAction(ctx, req, res)
	case ActionReboot:
		res.Status, res.Message = "done", "the server restarts"
	default:
		res.Status, res.Message = "failed", "unknown action"
	}
	err = h.finish(res)
	// The console reads the time zone and its ports when it starts.
	if res.restart {
		_, _ = h.Run(ctx, "systemctl", "restart", "emailzit-server")
	}
	if req.Action == ActionReboot && res.Status == "done" {
		_, _ = h.Run(ctx, "systemctl", "reboot")
	}
	return err
}

func (h *Helper) finish(res Result) error {
	res.Finished = time.Now().UTC()
	h.logf("%s: %s %s", res.Action, res.Status, res.Message)
	return h.write(res)
}

// write publishes the result for the console (world-readable, root-owned:
// the console reads it but cannot fake it for the next run).
func (h *Helper) write(res Result) error {
	b, _ := json.MarshalIndent(res, "", "  ")
	return h.writeFile(ResultFile, b)
}

// writeFile replaces a file of the helper directory (see write).
func (h *Helper) writeFile(name string, b []byte) error {
	p := filepath.Join(h.dir(), name)
	// The directory belongs to the console user: never follow a link it
	// may have planted (O_EXCL also refuses an existing link), and replace
	// result.json by a rename, which replaces a link, not its target.
	tmp := fmt.Sprintf("%s.%d.tmp", p, time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollow, 0o644) // #nosec G302 G304 -- read by the console
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if err := f.Close(); werr == nil {
		werr = err
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	return os.Rename(tmp, p)
}

// ReadResult reads the last result (for the console).
func ReadResult(dataDir string) (*Result, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "helper", ResultFile)) // #nosec G304 -- our data directory
	if err != nil {
		return nil, err
	}
	var r Result
	return &r, json.Unmarshal(b, &r)
}

// Pending reports whether a request waits for the helper.
func Pending(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, "helper", RequestFile))
	return err == nil
}

// Submit writes a request for the helper (the console side).
func Submit(dataDir string, req Request) error {
	d := filepath.Join(dataDir, "helper")
	if err := os.MkdirAll(d, 0o750); err != nil {
		return err
	}
	req.At = time.Now().UTC()
	b, _ := json.Marshal(req)
	tmp := filepath.Join(d, RequestFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d, RequestFile))
}

// Available reports whether this installation has the root helper (the
// Linux packages install its systemd units).
func Available() bool {
	for _, p := range []string{"/usr/lib/systemd/system/emailzit-helper.path", "/lib/systemd/system/emailzit-helper.path", "/etc/systemd/system/emailzit-helper.path"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// WriteServerInfo is called by the console at start.
func WriteServerInfo(dataDir string, info ServerInfo) error {
	d := filepath.Join(dataDir, "helper")
	if err := os.MkdirAll(d, 0o750); err != nil {
		return err
	}
	b, _ := json.Marshal(info)
	return os.WriteFile(filepath.Join(d, ServerFile), b, 0o600)
}
