package web

// Deleting old mail out of Junk and Trash.
//
// On a hosting server these two folders are where the disk goes: spam
// nobody will ever read and mail somebody deleted a year ago. Mail
// programs empty them only for the mailboxes that are opened, so the
// server has to, and Dovecot's own doveadm does it in a way that keeps
// the index and the quota right.
//
// It is off until somebody sets a number of days: mail that is deleted
// cannot be brought back, and no server may start throwing mail away
// because it was updated.

import (
	"context"
	"fmt"
	"time"
)

// noticeCleanup remembers when the old mail was last deleted.
const noticeCleanup = "cleanup"

// cleanupHour is when the clean-up runs (server time): after the nightly
// backup, before people start working.
const cleanupHour = 4

// cleanupOldMail deletes the old mail of Junk and Trash once a day.
func (s *Server) cleanupOldMail(ctx context.Context) {
	m := s.MailConfig(ctx)
	if m.JunkDays <= 0 && m.TrashDays <= 0 {
		return
	}
	now := s.now()
	if now.Hour() < cleanupHour {
		return
	}
	at, _, err := s.store.AdminNotice(ctx, noticeCleanup)
	if err != nil || now.Sub(at) < 20*time.Hour {
		return
	}
	if err := s.store.SetAdminNotice(ctx, noticeCleanup, ""); err != nil {
		return
	}
	if s.Mail == nil {
		return
	}
	if err := s.Mail.Expunge(ctx, m.JunkDays, m.TrashDays); err != nil {
		s.log.Error("deleting old mail out of Junk and Trash", "err", err)
		return
	}
	s.log.Info("old mail deleted", "junk_days", m.JunkDays, "trash_days", m.TrashDays)
	_ = s.store.Audit(ctx, "-", "local", "mail.cleanup", "settings",
		fmt.Sprintf("old mail deleted: Junk older than %d days, Trash older than %d days", m.JunkDays, m.TrashDays))
}

// validCleanup checks the two spans (0 = the folder is left alone).
func validCleanup(days int) bool { return days >= 0 && days <= 3650 }
