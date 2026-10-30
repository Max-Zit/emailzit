package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/sieve"
	"github.com/max-zit/emailzit/internal/store"
)

// Spam settings: the customer's level (staff), a mailbox's own level and
// allowed / blocked senders (staff, the customer, the mail user). The mail
// helper writes them as each mailbox's Sieve spam script.

// spamForm is what the shared form shows.
type spamForm struct {
	Action string
	S      *store.MailboxSpam
	Levels []string
}

func newSpamForm(action string, sp *store.MailboxSpam) *spamForm {
	return &spamForm{Action: action, S: sp, Levels: sieve.SpamLevels}
}

// syncSpam asks the helper to rewrite the spam scripts of a customer, or of
// one mailbox when address is set.
func (s *Server) syncSpam(ctx context.Context, customerID, address string) {
	if s.Mail == nil {
		return
	}
	if err := s.Mail.Spam(ctx, customerID, address); err != nil {
		s.log.Warn("spam scripts", "customer", customerID, "mailbox", address, "err", err)
	}
}

// Spam rewrites spam scripts through the helper.
func (h *HelperMail) Spam(ctx context.Context, customerID, address string) error {
	req := mailhelper.Request{Action: mailhelper.ActionSpam, Customer: customerID}
	if address != "" {
		req.Local, req.Domain, _ = cutAt(address)
	}
	return h.C.Call(ctx, req)
}

// saveMailboxSpam reads the form and stores a mailbox's settings.
func (s *Server) saveMailboxSpam(r *http.Request, sc store.Scope, m *store.Mailbox) error {
	level := r.FormValue("spam_level")
	if !sieve.ValidSpamLevel(level, true) {
		return errUser("Unknown spam level.")
	}
	allow, err := sieve.CleanSenders(r.FormValue("spam_allow"))
	if err != nil {
		return err
	}
	block, err := sieve.CleanSenders(r.FormValue("spam_block"))
	if err != nil {
		return err
	}
	if err := s.store.SetMailboxSpam(r.Context(), sc, m.ID, level, allow, block); err != nil {
		return err
	}
	s.syncSpam(r.Context(), m.CustomerID, m.Address)
	by := m.Address // the mail user
	if u := userFrom(r); u != nil {
		by = u.Username
	}
	s.auditAs(r, by, "mailbox.spam", "mailbox:"+m.Address, "level %q, %d allowed, %d blocked senders", level, len(allow), len(block))
	return nil
}

// errUser is a message for the user (translated when shown).
type errUser string

func (e errUser) Error() string { return string(e) }

func (s *Server) handleMailboxSpam(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	back := "/mailboxes/" + m.ID + "#spam"
	if err := s.saveMailboxSpam(r, scopeOf(r), m); err != nil {
		s.redirectErr(w, r, back, spamErr(err))
		return
	}
	s.redirect(w, r, back, "Spam settings saved.")
}

func (s *Server) handleMailSpam(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	if err := s.saveMailboxSpam(r, store.Scope{CustomerID: m.CustomerID}, m); err != nil {
		s.redirectErr(w, r, "/mail/filters#spam", spamErr(err))
		return
	}
	s.redirect(w, r, "/mail/filters#spam", "Spam settings saved.")
}

func (s *Server) handleCustomerSpam(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	level := r.FormValue("spam_level")
	if !sieve.ValidSpamLevel(level, false) {
		s.redirectErr(w, r, "/customers/"+c.ID, "Unknown spam level.")
		return
	}
	if err := s.store.SetCustomerSpamLevel(r.Context(), c.ID, level); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.syncSpam(r.Context(), c.ID, "")
	s.audit(r, "customer.spam", "customer:"+c.ID, "spam level %q", level)
	s.redirect(w, r, "/customers/"+c.ID, "Spam settings saved.")
}

// spamErr shows the reason when it is the user's, a general text else.
func spamErr(err error) string {
	switch {
	case errors.Is(err, sieve.ErrTooManySenders):
		return "At most 200 entries per list."
	case errors.Is(err, sieve.ErrBadSender):
		return "Each entry must be an address (ana@example.com) or a whole domain (example.com)."
	}
	if e, ok := err.(errUser); ok {
		return string(e)
	}
	return "The spam settings could not be saved."
}
