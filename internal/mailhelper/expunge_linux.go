//go:build linux

package mailhelper

// Deleting old mail out of Junk and Trash.
//
// On a hosting server these two folders are where the disk goes: spam
// nobody will ever read and mail the user deleted a year ago. Mail
// programs clean them only for the mailboxes that are opened, so the
// server has to do it, and Dovecot's own doveadm does it right — it keeps
// the index and the quota in step, which deleting files never would.

import (
	"context"
	"fmt"
	"strconv"
)

// expunge deletes mail older than the given days out of a folder of every
// mailbox. Days of 0 means the folder is left alone.
func (s *Server) expunge(ctx context.Context, r Request) error {
	for _, f := range []struct {
		mailbox string
		days    int
	}{{"Junk", r.JunkDays}, {"Trash", r.TrashDays}} {
		if f.days <= 0 {
			continue
		}
		if f.days > 3650 {
			return fmt.Errorf("%s: %d days is not a time span", f.mailbox, f.days)
		}
		// -A: every mailbox of this server. "savedbefore" counts from when
		// the message was saved, not from its Date header, which a spammer
		// writes as they please.
		out, err := s.Run(ctx, "doveadm", "expunge", "-A", "mailbox", f.mailbox,
			"savedbefore", strconv.Itoa(f.days)+"d")
		if err != nil {
			// a mailbox without that folder is not an error of the run
			s.Log.Warn("deleting old mail", "folder", f.mailbox, "days", f.days, "err", firstLine(out, err))
			continue
		}
		s.Log.Info("old mail deleted", "folder", f.mailbox, "older_than_days", f.days)
	}
	return nil
}
