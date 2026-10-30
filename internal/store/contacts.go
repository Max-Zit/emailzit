package store

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"unicode/utf8"
)

// Limits of the address book.
const (
	MaxContacts  = 2000
	MaxSignature = 2000
)

// Contact is an entry of a mailbox's address book.
type Contact struct {
	ID    int64
	Name  string
	Email string
	Auto  bool
}

// Contacts lists a mailbox's address book, most recently used first.
func (s *Store) Contacts(ctx context.Context, mailboxID string) ([]Contact, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name, email, auto FROM contacts WHERE mailbox_id=$1 ORDER BY used_at DESC, email LIMIT $2`, mailboxID, MaxContacts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Contact
	for rows.Next() {
		var c Contact
		if err := rows.Scan(&c.ID, &c.Name, &c.Email, &c.Auto); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// cleanContact checks a name and an address of the address book.
func cleanContact(name, email string) (string, string, error) {
	name = strings.TrimSpace(name)
	email = strings.ToLower(strings.TrimSpace(email))
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || len(email) > 254 {
		return "", "", errors.New("this is not a valid email address")
	}
	if utf8.RuneCountInString(name) > 100 || strings.ContainsAny(name, "\r\n\x00<>\"") {
		return "", "", errors.New("the name is too long or contains characters that are not allowed")
	}
	return name, email, nil
}

// SaveContact adds a contact or renames it (same address); auto marks
// addresses added by sending (they never overwrite a name the user gave).
func (s *Store) SaveContact(ctx context.Context, mailboxID, name, email string, auto bool) error {
	name, email, err := cleanContact(name, email)
	if err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM contacts WHERE mailbox_id=$1`, mailboxID).Scan(&n); err != nil {
		return err
	}
	if auto {
		if n >= MaxContacts {
			// the address book is full: the oldest automatic entry makes room
			_, _ = s.db.Exec(ctx, `DELETE FROM contacts WHERE id = (SELECT id FROM contacts WHERE mailbox_id=$1 AND auto ORDER BY used_at LIMIT 1)`, mailboxID)
		}
		_, err = s.db.Exec(ctx, `INSERT INTO contacts (mailbox_id, name, email, auto) VALUES ($1, $2, $3, true)
			ON CONFLICT (mailbox_id, email) DO UPDATE SET used_at = now(),
			name = CASE WHEN contacts.name = '' THEN EXCLUDED.name ELSE contacts.name END`, mailboxID, name, email)
		return err
	}
	if n >= MaxContacts {
		var exists bool
		_ = s.db.QueryRow(ctx, `SELECT true FROM contacts WHERE mailbox_id=$1 AND email=$2`, mailboxID, email).Scan(&exists)
		if !exists {
			return errors.New("the address book is full")
		}
	}
	_, err = s.db.Exec(ctx, `INSERT INTO contacts (mailbox_id, name, email) VALUES ($1, $2, $3)
		ON CONFLICT (mailbox_id, email) DO UPDATE SET name = EXCLUDED.name, auto = false`, mailboxID, name, email)
	return err
}

// DeleteContact removes an entry of the mailbox's address book.
func (s *Store) DeleteContact(ctx context.Context, mailboxID string, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM contacts WHERE mailbox_id=$1 AND id=$2`, mailboxID, id)
	return err
}

// Signature is the text webmail puts under new messages.
func (s *Store) Signature(ctx context.Context, mailboxID string) (string, error) {
	var sig string
	err := s.db.QueryRow(ctx, `SELECT signature FROM mailboxes WHERE id=$1`, mailboxID).Scan(&sig)
	return sig, notFound(err)
}

// SetSignature stores the webmail signature of a mailbox.
func (s *Store) SetSignature(ctx context.Context, mailboxID, sig string) error {
	sig = strings.TrimRight(strings.ReplaceAll(sig, "\r\n", "\n"), " \n")
	if utf8.RuneCountInString(sig) > MaxSignature || strings.ContainsRune(sig, 0) {
		return errors.New("the signature is too long")
	}
	_, err := s.db.Exec(ctx, `UPDATE mailboxes SET signature=$2 WHERE id=$1`, mailboxID, sig)
	return err
}
