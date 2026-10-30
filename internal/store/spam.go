package store

import (
	"context"
	"errors"
)

// MailboxSpam are the spam settings of a mailbox.
type MailboxSpam struct {
	Level         string // "" = the customer's level
	CustomerLevel string
	Allow, Block  []string
}

// Effective is the level that applies.
func (m *MailboxSpam) Effective() string {
	if m.Level != "" {
		return m.Level
	}
	return m.CustomerLevel
}

// MailboxSpamSettings loads a mailbox's spam settings.
func (s *Store) MailboxSpamSettings(ctx context.Context, sc Scope, mailboxID string) (*MailboxSpam, error) {
	m := &MailboxSpam{}
	err := s.db.QueryRow(ctx, `SELECT m.spam_level, c.spam_level, m.spam_allow, m.spam_block
		FROM mailboxes m JOIN customers c ON c.id = m.customer_id
		WHERE m.id = $1 AND ($2 = '' OR m.customer_id::text = $2)`, mailboxID, sc.CustomerID).
		Scan(&m.Level, &m.CustomerLevel, &m.Allow, &m.Block)
	if err != nil {
		return nil, notFound(err)
	}
	return m, nil
}

// SetMailboxSpam stores a mailbox's spam settings (lists already cleaned).
func (s *Store) SetMailboxSpam(ctx context.Context, sc Scope, mailboxID, level string, allow, block []string) error {
	if allow == nil {
		allow = []string{}
	}
	if block == nil {
		block = []string{}
	}
	if len(allow) > 200 || len(block) > 200 {
		return errors.New("at most 200 entries per list")
	}
	tag, err := s.db.Exec(ctx, `UPDATE mailboxes SET spam_level=$3, spam_allow=$4, spam_block=$5
		WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`, mailboxID, sc.CustomerID, level, allow, block)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CustomerSpamLevel is the customer's spam level.
func (s *Store) CustomerSpamLevel(ctx context.Context, customerID string) (string, error) {
	var l string
	err := s.db.QueryRow(ctx, `SELECT spam_level FROM customers WHERE id=$1`, customerID).Scan(&l)
	return l, notFound(err)
}

// SetCustomerSpamLevel sets the level of all mailboxes that have none of
// their own.
func (s *Store) SetCustomerSpamLevel(ctx context.Context, customerID, level string) error {
	tag, err := s.db.Exec(ctx, `UPDATE customers SET spam_level=$2 WHERE id=$1`, customerID, level)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
