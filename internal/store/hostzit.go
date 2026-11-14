package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

// The links to HostZit servers (INTEGRATION.md E7–E13). EmailZit keeps a
// list: pairing with a new HostZit adds a link, pairing again with the
// same URL replaces only that one, and nothing of one link ever touches
// another. A link serves all customers of this server or only the
// customers assigned to it (E13) — a HostZit of one client linked to a
// shared EmailZit must not see the other customers.

// HostZitLink is one linked HostZit server.
type HostZitLink struct {
	ID         int64
	URL        string
	ServerName string
	Token      string // sealed hzt_ token of that HostZit (dns:mail)
	Insecure   bool   // the administrator allows a self-signed certificate
	Pin        string // SHA-256 of its public key (from the pairing code)
	Addresses  []string
	TokenID    string // the ezt_ token EmailZit gave that HostZit
	ScopeAll   bool   // false: only the customers assigned to this link
	CreatedAt  time.Time
	LastCall   *time.Time
	// filled by HostZitLinks, for the page
	Customers  int // assigned customers (when ScopeAll is false)
	RelayUser  string
	RelayUsed  *time.Time
	TokenUsed  *time.Time
	TokenMaker string // who made the link
}

// Paired reports whether the link was made with a pairing code.
func (l *HostZitLink) Paired() bool { return l != nil && l.TokenID != "" }

const hostzitCols = `l.id, l.url, l.server_name, l.token, l.insecure, l.pin, l.addresses, l.token_id, l.scope_all, l.created_at, l.last_call`

func scanHostZitLink(row interface{ Scan(...any) error }, extra ...any) (*HostZitLink, error) {
	l := &HostZitLink{}
	dst := []any{&l.ID, &l.URL, &l.ServerName, &l.Token, &l.Insecure, &l.Pin, &l.Addresses, &l.TokenID, &l.ScopeAll, &l.CreatedAt, &l.LastCall}
	return l, row.Scan(append(dst, extra...)...)
}

// HostZitLinks lists the links, oldest first, with what the page shows.
func (s *Store) HostZitLinks(ctx context.Context) ([]*HostZitLink, error) {
	rows, err := s.db.Query(ctx, `SELECT `+hostzitCols+`,
			(SELECT count(*) FROM hostzit_link_customers c WHERE c.link_id = l.id),
			COALESCE((SELECT r.username FROM relay_logins r WHERE r.link_id = l.id ORDER BY r.created_at DESC LIMIT 1), ''),
			(SELECT r.last_used FROM relay_logins r WHERE r.link_id = l.id ORDER BY r.created_at DESC LIMIT 1),
			(SELECT t.last_used_at FROM api_tokens t WHERE t.id::text = l.token_id)
		FROM hostzit_links l ORDER BY l.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*HostZitLink
	for rows.Next() {
		var customers int
		var relayUser string
		var relayUsed, tokenUsed *time.Time
		l, err := scanHostZitLink(rows, &customers, &relayUser, &relayUsed, &tokenUsed)
		if err != nil {
			return nil, err
		}
		l.Customers, l.RelayUser, l.RelayUsed, l.TokenUsed = customers, relayUser, relayUsed, tokenUsed
		out = append(out, l)
	}
	return out, rows.Err()
}

// HostZitLinkByID loads one link.
func (s *Store) HostZitLinkByID(ctx context.Context, id int64) (*HostZitLink, error) {
	l, err := scanHostZitLink(s.db.QueryRow(ctx, `SELECT `+hostzitCols+` FROM hostzit_links l WHERE l.id=$1`, id))
	return l, notFound(err)
}

// HostZitLinkByURL finds the link of a HostZit address (a second pairing
// with the same server replaces that link).
func (s *Store) HostZitLinkByURL(ctx context.Context, url string) (*HostZitLink, error) {
	l, err := scanHostZitLink(s.db.QueryRow(ctx, `SELECT `+hostzitCols+` FROM hostzit_links l WHERE l.url=$1`, strings.TrimRight(url, "/")))
	return l, notFound(err)
}

// HostZitLinkByToken finds the link an API token belongs to (the token
// EmailZit gave that HostZit). ErrNotFound for every other token, for
// example the billing system's.
func (s *Store) HostZitLinkByToken(ctx context.Context, tokenID string) (*HostZitLink, error) {
	if tokenID == "" {
		return nil, ErrNotFound
	}
	l, err := scanHostZitLink(s.db.QueryRow(ctx, `SELECT `+hostzitCols+` FROM hostzit_links l WHERE l.token_id=$1`, tokenID))
	return l, notFound(err)
}

// SaveHostZitLink adds a link or changes it (by ID, or by URL when the ID
// is 0: pairing again with the same server replaces that link).
func (s *Store) SaveHostZitLink(ctx context.Context, l *HostZitLink) error {
	l.URL = strings.TrimRight(strings.TrimSpace(l.URL), "/")
	if l.URL == "" {
		return errors.New("the address of the HostZit server is required")
	}
	if l.Addresses == nil {
		l.Addresses = []string{}
	}
	if l.ID != 0 {
		tag, err := s.db.Exec(ctx, `UPDATE hostzit_links SET url=$2, server_name=$3, token=$4, insecure=$5, pin=$6, addresses=$7,
			token_id=$8, scope_all=$9 WHERE id=$1`, l.ID, l.URL, l.ServerName, l.Token, l.Insecure, l.Pin, l.Addresses, l.TokenID, l.ScopeAll)
		if isUnique(err) {
			return ErrConflict
		}
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	}
	err := s.db.QueryRow(ctx, `INSERT INTO hostzit_links(url, server_name, token, insecure, pin, addresses, token_id, scope_all)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (url) DO UPDATE SET server_name=EXCLUDED.server_name, token=EXCLUDED.token, insecure=EXCLUDED.insecure,
			pin=EXCLUDED.pin, addresses=EXCLUDED.addresses, token_id=EXCLUDED.token_id
		RETURNING id`, l.URL, l.ServerName, l.Token, l.Insecure, l.Pin, l.Addresses, l.TokenID, l.ScopeAll).Scan(&l.ID)
	return err
}

// DeleteHostZitLink ends one link (its relay login and assigned customers
// go with it).
func (s *Store) DeleteHostZitLink(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM hostzit_links WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TouchHostZitLink records that EmailZit reached that HostZit (at most
// once a minute).
func (s *Store) TouchHostZitLink(ctx context.Context, id int64) {
	_, _ = s.db.Exec(ctx, `UPDATE hostzit_links SET last_call=now() WHERE id=$1 AND (last_call IS NULL OR last_call < now() - interval '1 minute')`, id)
}

// SetLinkScope sets whether the link serves all customers or only the
// ones listed (E13). The list is replaced; unknown customers are refused.
func (s *Store) SetLinkScope(ctx context.Context, id int64, all bool, customers []string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE hostzit_links SET scope_all=$2 WHERE id=$1`, id, all)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM hostzit_link_customers WHERE link_id=$1`, id); err != nil {
		return err
	}
	for _, c := range customers {
		if !ValidID(c) {
			return errors.New("a customer ID is not a UUID")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO hostzit_link_customers(link_id, customer_id) VALUES($1,$2)
			ON CONFLICT DO NOTHING`, id, c); err != nil {
			if isFK(err) {
				return errors.New("unknown customer")
			}
			return err
		}
	}
	return tx.Commit(ctx)
}

// AssignCustomerToLink adds one customer to an assigned link (a customer
// the link's HostZit created itself belongs to it).
func (s *Store) AssignCustomerToLink(ctx context.Context, id int64, customerID string) error {
	if !ValidID(customerID) {
		return ErrNotFound
	}
	_, err := s.db.Exec(ctx, `INSERT INTO hostzit_link_customers(link_id, customer_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, customerID)
	return err
}

// LinkCustomerIDs lists the customers assigned to a link.
func (s *Store) LinkCustomerIDs(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT customer_id::text FROM hostzit_link_customers WHERE link_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LinkServes reports whether the link may see a customer: every customer
// for a link that serves all, only the assigned ones otherwise.
func (s *Store) LinkServes(ctx context.Context, l *HostZitLink, customerID string) bool {
	if l == nil {
		return true // not a HostZit token (the billing system)
	}
	if l.ScopeAll {
		return true
	}
	if !ValidID(customerID) {
		return false
	}
	var ok bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM hostzit_link_customers WHERE link_id=$1 AND customer_id=$2)`,
		l.ID, customerID).Scan(&ok); err != nil {
		return false
	}
	return ok
}
