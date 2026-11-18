package web

// Shared folders on the mailbox page.
//
// The office with one info@ that three people answer had two bad answers
// before: one password three people know, or a forwarder that makes three
// copies and loses every reply. Here the folder stays where it is and the
// others are let into it, which is what Dovecot's ACLs are for.
//
// Only mailboxes of the same customer are offered, and the store refuses
// anything else: every customer runs as its own system user with a 0700
// mail directory, so a share across customers could not work even if it
// were written.

import (
	"context"
	"net/http"

	"github.com/max-zit/emailzit/internal/store"
)

func (s *Server) handleMailboxShare(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	back := "/mailboxes/" + m.ID
	owner, with, err := s.store.AddShare(r.Context(), scopeOf(r), m.ID, r.FormValue("with"), r.FormValue("folder"), r.FormValue("rights"))
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.applyShare(r.Context(), owner, with, r.FormValue("folder"), r.FormValue("rights")); err != nil {
		// the share is in the database; the next start writes it again
		s.log.Error("sharing a folder", "owner", owner.Address, "with", with.Address, "err", err)
		s.redirectErr(w, r, back, "The folder is saved as shared, but the mail server did not take it; try again.")
		return
	}
	s.audit(r, "mailbox.share", "mailbox:"+owner.Address, "folder %q shared with %s (%s)", r.FormValue("folder"), with.Address, r.FormValue("rights"))
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleMailboxShareDelete(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	back := "/mailboxes/" + m.ID
	folder := r.FormValue("folder")
	owner, with, err := s.store.RemoveShare(r.Context(), scopeOf(r), m.ID, r.FormValue("with"), folder)
	if err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.applyShare(r.Context(), owner, with, folder, ""); err != nil {
		s.log.Error("closing a shared folder", "owner", owner.Address, "with", with.Address, "err", err)
		s.redirectErr(w, r, back, "The share is removed here, but the mail server did not take it; try again.")
		return
	}
	s.audit(r, "mailbox.share", "mailbox:"+owner.Address, "folder %q is no longer shared with %s", folder, with.Address)
	s.redirect(w, r, back, "Saved.")
}

// applyShare hands one share to the mail helper (empty rights remove it).
func (s *Server) applyShare(ctx context.Context, owner, with *store.Mailbox, folder, rights string) error {
	if s.Mail == nil {
		return nil
	}
	return s.Mail.Share(ctx, owner.Address, with.Address, folder, rights)
}

// syncShares writes every share again: at a start, after a restore and
// after an import, because the rights live in the mail store and that is
// not what a backup of the panel holds.
func (s *Server) syncShares(ctx context.Context) {
	if s.Mail == nil {
		return
	}
	list, err := s.store.AllShares(ctx)
	if err != nil {
		s.log.Error("the shared folders cannot be read", "err", err)
		return
	}
	var bad int
	for _, x := range list {
		if ctx.Err() != nil {
			return
		}
		if err := s.Mail.Share(ctx, x.OwnerAddress, x.WithAddress, x.Folder, x.Rights); err != nil {
			bad++
			s.log.Warn("a shared folder was not written again", "owner", x.OwnerAddress, "with", x.WithAddress, "folder", x.Folder, "err", err)
		}
	}
	if len(list) > 0 {
		s.log.Info("shared folders written again", "shares", len(list), "failed", bad)
	}
}
