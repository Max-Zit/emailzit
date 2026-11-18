//go:build linux

package mailhelper

// Shared folders: the rights of one folder of one mailbox for another
// mailbox of the same customer.
//
// Dovecot keeps them in the dovecot-acl file of the folder and in the
// list of shared mailboxes; doveadm writes both, which is why the rights
// are set with doveadm and never by writing those files by hand.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Share rights as doveadm names them.
var shareRights = map[string][]string{
	"read":  {"lookup", "read"},
	"write": {"lookup", "read", "write", "write-seen", "write-deleted", "insert", "post", "expunge", "create", "delete"},
}

var (
	shareAddrRE   = regexp.MustCompile(`^[^\s"'\\]{1,100}@[a-z0-9.-]{1,180}$`)
	shareFolderRE = regexp.MustCompile(`^[^\s"'\\-][^"'\\]{0,119}$`)
)

// share gives another mailbox the rights of a folder, or takes them away
// when the rights are empty.
func (s *Server) share(ctx context.Context, r Request) error {
	owner, with, folder := strings.ToLower(strings.TrimSpace(r.Owner)), strings.ToLower(strings.TrimSpace(r.With)), strings.TrimSpace(r.Folder)
	if !shareAddrRE.MatchString(owner) || !shareAddrRE.MatchString(with) || owner == with {
		return fmt.Errorf("share: not two mailboxes")
	}
	if !shareFolderRE.MatchString(folder) {
		return fmt.Errorf("share: %q is not a folder name", folder)
	}
	if r.Rights == "" {
		out, err := s.Run(ctx, "doveadm", "acl", "delete", "-u", owner, folder, "user="+with)
		if err != nil {
			return fmt.Errorf("doveadm acl delete: %s", firstLine(out, err))
		}
		s.Log.Info("a shared folder was closed", "owner", owner, "with", with, "folder", folder)
		return nil
	}
	rights, ok := shareRights[r.Rights]
	if !ok {
		return fmt.Errorf("share: unknown rights %q", r.Rights)
	}
	args := append([]string{"acl", "set", "-u", owner, folder, "user=" + with}, rights...)
	if out, err := s.Run(ctx, "doveadm", args...); err != nil {
		return fmt.Errorf("doveadm acl set: %s", firstLine(out, err))
	}
	s.Log.Info("a folder was shared", "owner", owner, "with", with, "folder", folder, "rights", r.Rights)
	return nil
}
