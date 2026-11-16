//go:build linux

package mailhelper

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/mailconf"
)

func quietServer() *Server {
	return &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// A write of the mail configuration that was INTERRUPTED keeps its files:
// the next start writes the rest. Putting the previous state back would
// take main.cf away from a postfix that is just starting, which ends as a
// failed unit in the log of the first boot of a new server (HostZit's
// finding of 2026-11-16). A write that really failed is still rolled back.
func TestAnInterruptedWriteOfTheMailConfigurationKeepsItsFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.cf")
	files := []mailconf.File{{Path: path, Mode: 0o644, Content: []byte("new")}}
	s := quietServer()
	write := func() {
		t.Helper()
		if err := os.WriteFile(path, []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stopped, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("the first write of a new server is kept", func(t *testing.T) {
		write()
		if s.undo(stopped, map[string][]byte{}, files) {
			t.Fatal("the interrupted write was rolled back")
		}
		if b, err := os.ReadFile(path); err != nil || string(b) != "new" {
			t.Fatalf("the file holds %q (%v)", b, err)
		}
	})
	t.Run("an interrupted change is kept", func(t *testing.T) {
		write()
		if s.undo(stopped, map[string][]byte{path: []byte("old")}, files) {
			t.Fatal("the interrupted change was rolled back")
		}
		if b, _ := os.ReadFile(path); string(b) != "new" {
			t.Fatalf("the file holds %q", b)
		}
	})
	t.Run("a change that failed goes back", func(t *testing.T) {
		write()
		if !s.undo(context.Background(), map[string][]byte{path: []byte("old")}, files) {
			t.Fatal("the failed change was not rolled back")
		}
		if b, _ := os.ReadFile(path); string(b) != "old" {
			t.Fatalf("the file holds %q", b)
		}
	})
	t.Run("a first write that failed leaves nothing behind", func(t *testing.T) {
		write()
		if !s.undo(context.Background(), map[string][]byte{}, files) {
			t.Fatal("the failed write was not rolled back")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the file is still there (%v)", err)
		}
	})
}

// A start that finds every file of the mail configuration unchanged
// reloads nothing, so a service that is down (the files of an interrupted
// write stay in place) has to be started: otherwise no mail would flow
// until the next reboot.
func TestAStartWithNothingToWriteBringsTheMailUp(t *testing.T) {
	var ran []string
	s := quietServer()
	s.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		ran = append(ran, cmd)
		if strings.HasPrefix(cmd, "systemctl is-active") && strings.HasSuffix(cmd, "dovecot") {
			return nil, nil // dovecot runs already
		}
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return nil, errors.New("inactive")
		}
		return nil, nil
	}
	s.keepMail(context.Background())
	if !contains(ran, "systemctl start postfix") {
		t.Fatalf("postfix was not started: %v", ran)
	}
	if contains(ran, "systemctl start dovecot") {
		t.Fatalf("a service that runs was started again: %v", ran)
	}

	// a service that is being stopped is not started again
	ran = nil
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	s.keepMail(stopped)
	if len(ran) > 0 {
		t.Fatalf("a stopping service still asked systemd: %v", ran)
	}
}
