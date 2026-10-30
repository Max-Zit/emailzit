package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSSH: the appliance's SSH port and on/off; a port sshd refuses or a
// reserved one changes nothing; elsewhere SSH is not touched.
func TestSSH(t *testing.T) {
	h, fs := newHelper(t)
	if r := h.submit(t, Request{Action: ActionSSH, SSH: &SSHConfig{Enabled: true, Port: 2222}}); r.Status != "failed" || !strings.Contains(r.Message, "appliance") {
		t.Fatalf("SSH changed outside the appliance: %+v", r)
	}
	_ = os.WriteFile(filepath.Join(h.Root, ApplianceMarker), nil, 0o644)
	if r := h.submit(t, Request{Action: ActionSSH, SSH: &SSHConfig{Enabled: true, Port: 2222}}); r.Status != "done" || r.Message != "SSH on port 2222" {
		t.Fatalf("port: %+v", r)
	}
	if got := ReadSSH(h.Root); got.Port != 2222 {
		t.Fatalf("port file: %+v", got)
	}
	if !fs.ran("systemctl restart ssh") || !fs.ran("systemctl disable --now ssh.socket") || !fs.ran("sshd -t") {
		t.Fatalf("commands: %v", fs.cmds)
	}
	if r := h.submit(t, Request{Action: ActionSSH, SSH: &SSHConfig{Enabled: true, Port: 8444}}); r.Status != "failed" || !strings.Contains(r.Message, "8444") {
		t.Fatalf("reserved port: %+v", r)
	}
	// sshd refuses: the previous port stays
	h.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "sshd" {
			return []byte("bad"), errors.New("exit status 255")
		}
		return fs.run(ctx, name, args...)
	}
	if r := h.submit(t, Request{Action: ActionSSH, SSH: &SSHConfig{Enabled: true, Port: 2200}}); r.Status != "failed" || ReadSSH(h.Root).Port != 2222 {
		t.Fatalf("refused port: %+v %+v", r, ReadSSH(h.Root))
	}
	h.Run = fs.run
	if r := h.submit(t, Request{Action: ActionSSH, SSH: &SSHConfig{Enabled: false, Port: 22}}); r.Status != "done" || ReadSSH(h.Root).Port != 22 || !fs.ran("systemctl disable --now ssh.service") {
		t.Fatalf("off: %+v", r)
	}
}

// TestOSUpdates: the status from apt, automatic security updates, upgrade
// and reboot.
func TestOSUpdates(t *testing.T) {
	h, fs := newHelper(t)
	_ = os.WriteFile(filepath.Join(h.Root, "usr/bin/apt-get"), nil, 0o755)
	_ = os.MkdirAll(filepath.Join(h.Root, "etc/apt/apt.conf.d"), 0o755)
	_ = os.WriteFile(filepath.Join(h.Root, "usr/bin/unattended-upgrade"), nil, 0o755)
	_ = os.MkdirAll(filepath.Join(h.Root, "var/run"), 0o755)
	_ = os.WriteFile(filepath.Join(h.Root, "var/run/reboot-required"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(h.Root, "etc/os-release"), []byte("NAME=Debian\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n"), 0o644)
	h.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		fs.run(ctx, name, args...)
		switch {
		case name == "apt-get" && len(args) > 0 && args[0] == "-s":
			return []byte("Inst openssl [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])\nInst tzdata [2025a] (2025b Debian:13/stable [all])\nConf openssl\n"), nil
		case name == "uname":
			return []byte("6.12.0-amd64\n"), nil
		}
		return nil, nil
	}
	if r := h.submit(t, Request{Action: ActionOSStatus}); r.Status != "done" {
		t.Fatalf("status: %+v", r)
	}
	st, err := ReadOSStatus(h.DataDir)
	if err != nil || st.Pending != 2 || st.Security != 1 || !st.RebootRequired || st.OS != "Debian GNU/Linux 13 (trixie)" || st.Kernel != "6.12.0-amd64" || st.Manager != "apt" {
		t.Fatalf("status: %+v %v", st, err)
	}
	if r := h.submit(t, Request{Action: ActionOSAuto, Enable: true}); r.Status != "done" {
		t.Fatalf("auto: %+v", r)
	}
	if st, _ := ReadOSStatus(h.DataDir); !st.AutoSecurity {
		t.Fatal("automatic security updates not on")
	}
	if r := h.submit(t, Request{Action: ActionOSUpgrade}); r.Status != "done" || !fs.ran("apt-get -y -q -o Dpkg::Options::=--force-confold") {
		t.Fatalf("upgrade: %+v %v", r, fs.cmds)
	}
	if r := h.submit(t, Request{Action: ActionReboot}); r.Status != "done" || !fs.ran("systemctl reboot") {
		t.Fatalf("reboot: %+v", r)
	}
}
