//go:build linux

package mailhelper

import (
	"context"
	"strings"
	"testing"
)

// Setting the rights of a shared folder is only half of it: Dovecot 2.4.1
// tells a client about a shared folder from the list of shared mailboxes,
// and that list is written only by "doveadm acl recalc" (found in the lab
// on 2026-11-18 — the rights were in the folder and the other mailbox saw
// nothing).
func TestSharingAFolderAlsoWritesTheListOfSharedMailboxes(t *testing.T) {
	s := quietServer()
	var cmds []string
	s.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	ctx := context.Background()

	t.Run("sharing sets the rights and writes the list", func(t *testing.T) {
		cmds = nil
		err := s.share(ctx, Request{Action: ActionShare, Owner: "info@example.com", With: "ana@example.com", Folder: "INBOX", Rights: "write"})
		if err != nil {
			t.Fatal(err)
		}
		if len(cmds) != 2 {
			t.Fatalf("commands: %q", cmds)
		}
		if !strings.HasPrefix(cmds[0], "doveadm acl set -u info@example.com INBOX user=ana@example.com ") {
			t.Errorf("the rights were set with %q", cmds[0])
		}
		for _, right := range []string{"lookup", "read", "insert", "expunge"} {
			if !strings.Contains(cmds[0], " "+right) {
				t.Errorf("the write rights lack %q: %s", right, cmds[0])
			}
		}
		if strings.Contains(cmds[0], " admin") {
			t.Errorf("a shared folder must not carry admin rights: %s", cmds[0])
		}
		if cmds[1] != "doveadm acl recalc -u info@example.com" {
			t.Errorf("the list of shared mailboxes was not written: %q", cmds[1])
		}
	})

	t.Run("read only means look and read", func(t *testing.T) {
		cmds = nil
		if err := s.share(ctx, Request{Action: ActionShare, Owner: "info@example.com", With: "ana@example.com", Folder: "INBOX", Rights: "read"}); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(cmds[0], "user=ana@example.com lookup read") {
			t.Errorf("read only is %q", cmds[0])
		}
	})

	t.Run("closing removes the rights and writes the list", func(t *testing.T) {
		cmds = nil
		if err := s.share(ctx, Request{Action: ActionShare, Owner: "info@example.com", With: "ana@example.com", Folder: "INBOX"}); err != nil {
			t.Fatal(err)
		}
		if len(cmds) != 2 || !strings.HasPrefix(cmds[0], "doveadm acl delete ") || cmds[1] != "doveadm acl recalc -u info@example.com" {
			t.Fatalf("commands: %q", cmds)
		}
	})

	t.Run("what is not two mailboxes and a folder is refused", func(t *testing.T) {
		for name, r := range map[string]Request{
			"no reader":     {Owner: "info@example.com", Folder: "INBOX", Rights: "read"},
			"itself":        {Owner: "info@example.com", With: "info@example.com", Folder: "INBOX", Rights: "read"},
			"folder a flag": {Owner: "info@example.com", With: "ana@example.com", Folder: "-u root", Rights: "read"},
			"folder quoted": {Owner: "info@example.com", With: "ana@example.com", Folder: `In"box`, Rights: "read"},
			"unknown right": {Owner: "info@example.com", With: "ana@example.com", Folder: "INBOX", Rights: "admin"},
		} {
			cmds = nil
			if err := s.share(ctx, r); err == nil {
				t.Errorf("%s was accepted", name)
			}
			if len(cmds) != 0 {
				t.Errorf("%s reached doveadm: %q", name, cmds)
			}
		}
	})
}
