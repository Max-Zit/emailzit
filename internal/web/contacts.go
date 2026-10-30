package web

import (
	"net/http"
	"net/mail"
	"strconv"
	"strings"

	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/webmail"
)

// The address book and the signature of webmail (/mail/contacts).

type contactsData struct {
	Contacts  []store.Contact
	Signature string
	Max       int
}

func (s *Server) contactRoutes(m func(string, http.HandlerFunc)) {
	m("GET /mail/contacts", s.handleContacts)
	m("POST /mail/contacts", s.handleContactSave)
	m("POST /mail/contacts/{id}/delete", s.handleContactDelete)
	m("POST /mail/signature", s.handleSignature)
}

func (s *Server) handleContacts(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	d := &contactsData{Max: store.MaxSignature}
	var err error
	if d.Contacts, err = s.store.Contacts(r.Context(), m.ID); err == nil {
		d.Signature, err = s.store.Signature(r.Context(), m.ID)
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p := s.mailPage(r, "Contacts", d)
	p.Nav = "contacts"
	s.render(w, r, http.StatusOK, "mailcontacts", p)
}

func (s *Server) handleContactSave(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	if err := s.store.SaveContact(r.Context(), m.ID, r.FormValue("name"), r.FormValue("email"), false); err != nil {
		s.redirectErr(w, r, "/mail/contacts", err.Error())
		return
	}
	s.redirect(w, r, "/mail/contacts", "The contact was saved.")
}

func (s *Server) handleContactDelete(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.store.DeleteContact(r.Context(), m.ID, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.redirect(w, r, "/mail/contacts", "The contact was removed.")
}

func (s *Server) handleSignature(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	if err := s.store.SetSignature(r.Context(), m.ID, r.FormValue("signature")); err != nil {
		s.redirectErr(w, r, "/mail/contacts#signature", err.Error())
		return
	}
	s.redirect(w, r, "/mail/contacts#signature", "The signature was saved.")
}

// rememberRecipients adds the addresses a message went to to the sender's
// address book (with the names written in the message).
func (s *Server) rememberRecipients(r *http.Request, mailboxID string, d *webmail.Draft) {
	for _, list := range []string{d.To, d.Cc, d.Bcc} {
		if strings.TrimSpace(list) == "" {
			continue
		}
		as, err := mail.ParseAddressList(list)
		if err != nil {
			continue
		}
		for _, a := range as {
			if err := s.store.SaveContact(r.Context(), mailboxID, a.Name, a.Address, true); err != nil {
				s.log.Debug("contact not remembered", "err", err)
			}
		}
	}
}

// withSignature puts the signature under the text the user writes (above a
// quoted or forwarded message).
func withSignature(text, sig string) string {
	if sig == "" {
		return text
	}
	return "\n\n-- \n" + sig + text
}

// label marks a text the templates translate later (for the catalog check).
func label(s string) string { return s }

// folderLabel is the name of a folder as webmail shows it (untranslated).
func folderLabel(f webmail.Folder) string {
	switch {
	case f.Name == "INBOX":
		return label("Inbox")
	case f.Special == `\Sent`:
		return label("Sent")
	case f.Special == `\Drafts`:
		return label("Drafts")
	case f.Special == `\Junk`:
		return label("Spam")
	case f.Special == `\Trash`:
		return label("Trash")
	case f.Special == `\Archive`:
		return label("Archive")
	}
	return f.Name
}

func init() {
	funcs["folderLabel"] = folderLabel
}
