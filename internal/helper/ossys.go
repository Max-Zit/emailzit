package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- SSH of the appliance

// SSHPortFile holds the SSH port EmailZit set (absent: port 22).
const SSHPortFile = "/etc/ssh/sshd_config.d/60-emailzit-port.conf"

// SSHConfig switches the SSH server on or off and sets its port.
type SSHConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// reservedPorts are used by EmailZit itself.
var reservedPorts = map[int]string{25: "mail from other servers", 80: "automatic setup of mail programs", 443: "automatic setup of mail programs", 465: "sending mail", 587: "sending mail", 993: "IMAP", 995: "POP3", 110: "POP3", 143: "IMAP", 4190: "ManageSieve", 8444: "the panels", 5432: "PostgreSQL", 11332: "Rspamd", 11334: "Rspamd", 6379: "Valkey", 10032: "the sign-in guard"}

// Validate checks c.
func (c *SSHConfig) Validate() error {
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("the SSH port must be between 1 and 65535")
	}
	if what, ok := reservedPorts[c.Port]; ok {
		return fmt.Errorf("port %d is used by %s", c.Port, what)
	}
	return nil
}

// sshUnit is the SSH service: "ssh" on Debian, "sshd" on RHEL systems.
func (h *Helper) sshUnit(ctx context.Context) string {
	if _, err := h.Run(ctx, "systemctl", "cat", "ssh.service"); err == nil {
		return "ssh"
	}
	return "sshd"
}

// ReadSSH reads the SSH port EmailZit set (the console side; whether the
// server runs is in the status the helper writes).
func ReadSSH(root string) SSHConfig {
	c := SSHConfig{Port: 22}
	if b, err := os.ReadFile(filepath.Join(root, SSHPortFile)); err == nil { // #nosec G304 -- fixed path
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "Port" {
				c.Port, _ = strconv.Atoi(f[1])
			}
		}
	}
	return c
}

func (h *Helper) sshRunning(ctx context.Context) bool {
	_, err := h.Run(ctx, "systemctl", "is-active", "--quiet", h.sshUnit(ctx))
	return err == nil
}

// ssh sets the port and starts or stops the SSH server. A port the SSH
// server refuses (sshd -t) leaves the previous setting in place.
func (h *Helper) ssh(ctx context.Context, req Request, res Result) Result {
	fail := func(err error) Result {
		res.Status, res.Message = "failed", err.Error()
		return res
	}
	if !IsAppliance(h.Root) {
		return fail(errors.New("SSH can only be set here on the EmailZit appliance"))
	}
	if req.SSH == nil {
		return fail(errors.New("incomplete request"))
	}
	c := *req.SSH
	if err := c.Validate(); err != nil {
		return fail(err)
	}
	unit := h.sshUnit(ctx)
	path := h.path(SSHPortFile)
	old, oldErr := os.ReadFile(path) // #nosec G304 -- fixed path
	restore := func() {
		if oldErr == nil {
			_ = os.WriteFile(path, old, 0o644) // #nosec G306 G703 -- sshd configuration
		} else {
			_ = os.Remove(path)
		}
	}
	if c.Port == 22 {
		_ = os.Remove(path)
	} else {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)                                                                                                                    // #nosec G301 -- /etc/ssh/sshd_config.d
		if err := os.WriteFile(path, []byte(fmt.Sprintf("# Set by EmailZit (setup menu or Settings → Updates and server).\nPort %d\n", c.Port)), 0o644); err != nil { // #nosec G306 -- sshd configuration
			return fail(err)
		}
	}
	// sshd -t needs its privilege separation directory, which exists only
	// while the SSH server runs.
	_ = os.MkdirAll(h.path("/run/sshd"), 0o755) // #nosec G301 -- sshd's own directory
	if out, err := h.Run(ctx, "sshd", "-t"); err != nil {
		restore()
		return fail(fmt.Errorf("the SSH server refused the setting, nothing was changed: %s", strings.TrimSpace(string(out)+" "+err.Error())))
	}
	// Debian 13 can start SSH through ssh.socket, which listens on the port
	// itself; EmailZit runs the service directly so the port applies.
	_, _ = h.Run(ctx, "systemctl", "disable", "--now", "ssh.socket")
	if !c.Enabled {
		if _, err := h.Run(ctx, "systemctl", "disable", "--now", unit+".service"); err != nil {
			return fail(err)
		}
		res.Status, res.Message = "done", "SSH switched off"
		h.writeOSStatus(ctx, nil)
		return res
	}
	if _, err := h.Run(ctx, "systemctl", "enable", unit+".service"); err != nil {
		return fail(err)
	}
	// After repeated failures systemd refuses restarts for a while.
	_, _ = h.Run(ctx, "systemctl", "reset-failed", unit+".service")
	if _, err := h.Run(ctx, "systemctl", "restart", unit+".service"); err != nil {
		return fail(err)
	}
	res.Status, res.Message = "done", fmt.Sprintf("SSH on port %d", c.Port)
	h.writeOSStatus(ctx, nil)
	return res
}

// ---- operating system updates

// OSStatusFile is written by the helper into <data-dir>/helper.
const OSStatusFile = "os-status.json"

// OSStatus describes the server's operating system updates (and SSH).
type OSStatus struct {
	OS             string    `json:"os"`
	Kernel         string    `json:"kernel"`
	Manager        string    `json:"manager"` // apt or dnf
	Pending        int       `json:"pending"`
	Security       int       `json:"security"`
	Packages       []string  `json:"packages,omitempty"` // first pending packages
	AutoSecurity   bool      `json:"auto_security"`
	LastAutoRun    time.Time `json:"last_auto_run,omitempty"`
	RebootRequired bool      `json:"reboot_required"`
	SSHRunning     bool      `json:"ssh_running"`
	Checked        time.Time `json:"checked"`
	Error          string    `json:"error,omitempty"`
}

// ReadOSStatus reads the last status (for the console).
func ReadOSStatus(dataDir string) (*OSStatus, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "helper", OSStatusFile)) // #nosec G304 -- our data directory
	if err != nil {
		return nil, err
	}
	var st OSStatus
	return &st, json.Unmarshal(b, &st)
}

type osSystem interface {
	status(ctx context.Context, st *OSStatus) error
	setAuto(ctx context.Context, on bool) error
	upgrade(ctx context.Context) (string, error)
}

func (h *Helper) osSystem() (osSystem, error) {
	if exists(h.path("/usr/bin/apt-get")) {
		return &aptSystem{h}, nil
	}
	if exists(h.path("/usr/bin/dnf")) {
		return &dnfSystem{h}, nil
	}
	return nil, errors.New("no supported package manager (apt or dnf) found")
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// osAction runs an OS request; the status is written afterwards.
func (h *Helper) osAction(ctx context.Context, req Request, res Result) Result {
	sys, err := h.osSystem()
	if err == nil {
		switch req.Action {
		case ActionOSStatus:
			res.Message = "status refreshed"
		case ActionOSAuto:
			err = sys.setAuto(ctx, req.Enable)
			res.Message = map[bool]string{true: "automatic security updates switched on", false: "automatic security updates switched off"}[req.Enable]
		case ActionOSUpgrade:
			var out string
			out, err = sys.upgrade(ctx)
			res.Message = "all updates installed"
			if out != "" {
				res.Message += "\n\n" + lastN(out, 25)
			}
		}
	}
	if err != nil {
		res.Status, res.Message = "failed", err.Error()
	} else {
		res.Status = "done"
	}
	h.writeOSStatus(ctx, sys)
	return res
}

// writeOSStatus refreshes os-status.json.
func (h *Helper) writeOSStatus(ctx context.Context, sys osSystem) {
	if sys == nil {
		sys, _ = h.osSystem()
	}
	st := OSStatus{Checked: time.Now().UTC(), SSHRunning: h.sshRunning(ctx)}
	if sys == nil {
		st.Error = "no supported package manager (apt or dnf) found"
	} else if err := sys.status(ctx, &st); err != nil {
		st.Error = err.Error()
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	_ = h.writeFile(OSStatusFile, b)
}

func lastN(s string, n int) string {
	l := strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r", "")), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

func (h *Helper) osRelease() string {
	b, err := os.ReadFile(h.path("/etc/os-release")) // #nosec G304 -- fixed path
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func (h *Helper) kernel(ctx context.Context) string {
	out, err := h.Run(ctx, "uname", "-r")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---- Debian, Ubuntu

type aptSystem struct{ h *Helper }

const autoUpgradesFile = "/etc/apt/apt.conf.d/20auto-upgrades"

// aptInstRe matches "Inst pkg [old] (new suite [arch])" of apt-get -s.
var aptInstRe = regexp.MustCompile(`^Inst (\S+)(?: \[[^\]]*\])? \((\S+) ([^\[)]*)`)

var autoOnRe = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"1"`)

func (s *aptSystem) status(ctx context.Context, st *OSStatus) error {
	h := s.h
	st.Manager, st.OS, st.Kernel = "apt", h.osRelease(), h.kernel(ctx)
	st.RebootRequired = exists(h.path("/var/run/reboot-required"))
	if b, err := os.ReadFile(h.path(autoUpgradesFile)); err == nil { // #nosec G304 -- fixed path
		st.AutoSecurity = autoOnRe.Match(b) && exists(h.path("/usr/bin/unattended-upgrade"))
	}
	if fi, err := os.Stat(h.path("/var/log/unattended-upgrades/unattended-upgrades.log")); err == nil {
		st.LastAutoRun = fi.ModTime().UTC()
	}
	if _, err := h.Run(ctx, "apt-get", "update", "-qq"); err != nil {
		return fmt.Errorf("refresh package lists: %w", err)
	}
	out, err := h.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade", "--with-new-pkgs")
	if err != nil {
		return err
	}
	for _, l := range strings.Split(string(out), "\n") {
		m := aptInstRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		st.Pending++
		if strings.Contains(strings.ToLower(m[3]), "security") {
			st.Security++
		}
		if len(st.Packages) < 50 {
			st.Packages = append(st.Packages, m[1]+" "+m[2])
		}
	}
	return nil
}

func (s *aptSystem) setAuto(ctx context.Context, on bool) error {
	h := s.h
	if on && !exists(h.path("/usr/bin/unattended-upgrade")) {
		if _, err := h.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-q", "unattended-upgrades"); err != nil {
			return err
		}
	}
	v := "0"
	if on {
		v = "1"
	}
	// The package's default configuration installs only security updates.
	conf := fmt.Sprintf("// Managed by EmailZit (Settings → Updates and server)\nAPT::Periodic::Update-Package-Lists \"%s\";\nAPT::Periodic::Unattended-Upgrade \"%s\";\n", v, v)
	return os.WriteFile(h.path(autoUpgradesFile), []byte(conf), 0o644) // #nosec G306 -- apt configuration
}

func (s *aptSystem) upgrade(ctx context.Context) (string, error) {
	h := s.h
	if _, err := h.Run(ctx, "apt-get", "update", "-qq"); err != nil {
		return "", err
	}
	out, err := h.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "-q",
		"-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Options::=--force-confdef", "upgrade", "--with-new-pkgs")
	return string(out), err
}

// ---- AlmaLinux, Rocky Linux, RHEL

type dnfSystem struct{ h *Helper }

const dnfAutoConf = "/etc/dnf/automatic.conf"

var applyYesRe = regexp.MustCompile(`(?m)^apply_updates\s*=\s*yes`)

func (s *dnfSystem) status(ctx context.Context, st *OSStatus) error {
	h := s.h
	st.Manager, st.OS, st.Kernel = "dnf", h.osRelease(), h.kernel(ctx)
	if _, err := h.Run(ctx, "needs-restarting", "-r"); err != nil {
		st.RebootRequired = strings.Contains(err.Error(), "exit status 1")
	}
	if out, err := h.Run(ctx, "systemctl", "is-enabled", "dnf-automatic.timer"); err == nil && strings.TrimSpace(string(out)) == "enabled" {
		b, _ := os.ReadFile(h.path(dnfAutoConf)) // #nosec G304 -- fixed path
		st.AutoSecurity = applyYesRe.Match(b)
	}
	// dnf check-update exits with 100 when updates are available.
	out, err := h.Run(ctx, "dnf", "-q", "--refresh", "check-update")
	if err != nil && !strings.Contains(err.Error(), "exit status 100") {
		return err
	}
	var pkgs []string
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && strings.Contains(f[0], ".") && !strings.HasPrefix(l, " ") {
			st.Pending++
			if len(pkgs) < 50 {
				pkgs = append(pkgs, f[0]+" "+f[1])
			}
		}
	}
	sort.Strings(pkgs)
	st.Packages = pkgs
	if sec, err := h.Run(ctx, "dnf", "-q", "updateinfo", "list", "--security"); err == nil {
		for _, l := range strings.Split(string(sec), "\n") {
			if strings.TrimSpace(l) != "" {
				st.Security++
			}
		}
	}
	return nil
}

func (s *dnfSystem) setAuto(ctx context.Context, on bool) error {
	h := s.h
	if !on {
		_, err := h.Run(ctx, "systemctl", "disable", "--now", "dnf-automatic.timer")
		return err
	}
	if !exists(h.path(dnfAutoConf)) {
		if _, err := h.Run(ctx, "dnf", "install", "-y", "-q", "dnf-automatic"); err != nil {
			return err
		}
	}
	b, err := os.ReadFile(h.path(dnfAutoConf)) // #nosec G304 -- fixed path
	if err != nil {
		return err
	}
	conf := string(b)
	set := func(key, val string) {
		re := regexp.MustCompile(`(?m)^#?\s*` + key + `\s*=.*$`)
		if re.MatchString(conf) {
			conf = re.ReplaceAllString(conf, key+" = "+val)
		} else {
			conf = strings.Replace(conf, "[commands]", "[commands]\n"+key+" = "+val, 1)
		}
	}
	set("upgrade_type", "security")
	set("apply_updates", "yes")
	if err := os.WriteFile(h.path(dnfAutoConf), []byte(conf), 0o644); err != nil { // #nosec G306 G703 -- the fixed dnf configuration file
		return err
	}
	_, err = h.Run(ctx, "systemctl", "enable", "--now", "dnf-automatic.timer")
	return err
}

func (s *dnfSystem) upgrade(ctx context.Context) (string, error) {
	out, err := s.h.Run(ctx, "dnf", "-y", "-q", "upgrade")
	return string(out), err
}
