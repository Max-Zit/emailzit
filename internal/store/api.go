package store

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/auth"
)

// API scopes.
const (
	ScopeCustomersRead  = "customers:read"
	ScopeCustomersWrite = "customers:write"
	ScopeSSO            = "sso:create"
	ScopeUsage          = "usage:read"
)

// Scopes lists all API scopes.
var Scopes = []string{ScopeCustomersRead, ScopeCustomersWrite, ScopeUsage, ScopeSSO}

// usernameAPI is the customer username shared with HostZit.
var usernameAPI = regexp.MustCompile(`^[a-z][a-z0-9]{2,15}$`)

// APIToken is a token of the REST API.
type APIToken struct {
	ID         string
	Name       string
	Scopes     []string
	AllowedIPs []string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	LastIP     string
}

// Has reports a scope.
func (t *APIToken) Has(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AllowsIP checks the address list of the token (empty = any address).
func (t *APIToken) AllowsIP(ip string) bool {
	if len(t.AllowedIPs) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range t.AllowedIPs {
		if p, err := netip.ParsePrefix(n); err == nil && p.Contains(a) {
			return true
		}
		if b, err := netip.ParseAddr(n); err == nil && b == a {
			return true
		}
	}
	return false
}

// CreateAPIToken makes a token and returns it (shown once).
func (s *Store) CreateAPIToken(ctx context.Context, name string, scopes, ips []string, days int, by string) (string, *APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return "", nil, errors.New("give the token a name (up to 100 characters)")
	}
	known := map[string]bool{}
	for _, sc := range Scopes {
		known[sc] = true
	}
	var sc []string
	for _, x := range scopes {
		if known[x] {
			sc = append(sc, x)
		}
	}
	if len(sc) == 0 {
		return "", nil, errors.New("choose at least one permission")
	}
	list := []string{}
	for _, n := range ips {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, err := netip.ParsePrefix(n); err != nil {
			if _, err := netip.ParseAddr(n); err != nil {
				return "", nil, errors.New("an address of the list is not valid")
			}
		}
		list = append(list, n)
	}
	tok := "ezt_" + auth.RandomToken(32)
	t := &APIToken{ID: NewID(), Name: name, Scopes: sc, AllowedIPs: list, CreatedBy: by, CreatedAt: s.now()}
	var exp any
	if days > 0 {
		e := s.now().Add(time.Duration(days) * 24 * time.Hour)
		t.ExpiresAt, exp = &e, e
	}
	_, err := s.db.Exec(ctx, `INSERT INTO api_tokens(id, name, hash, scopes, allowed_ips, created_by, created_at, expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		t.ID, name, auth.HashToken("api", tok), sc, list, by, t.CreatedAt, exp)
	if err != nil {
		return "", nil, err
	}
	return tok, t, nil
}

// #nosec G101 -- column names, not a credential
const apiTokenCols = `id, name, scopes, allowed_ips, created_by, created_at, expires_at, last_used_at, last_ip`

func scanAPIToken(row interface{ Scan(...any) error }) (*APIToken, error) {
	t := &APIToken{}
	err := row.Scan(&t.ID, &t.Name, &t.Scopes, &t.AllowedIPs, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.LastIP)
	return t, err
}

// APITokens lists the tokens.
func (s *Store) APITokens(ctx context.Context) ([]*APIToken, error) {
	rows, err := s.db.Query(ctx, `SELECT `+apiTokenCols+` FROM api_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// APITokenBySecret finds a valid token and records its use.
func (s *Store) APITokenBySecret(ctx context.Context, tok, ip string) (*APIToken, error) {
	if !strings.HasPrefix(tok, "ezt_") || len(tok) > 100 {
		return nil, ErrNotFound
	}
	t, err := scanAPIToken(s.db.QueryRow(ctx, `SELECT `+apiTokenCols+` FROM api_tokens WHERE hash=$1`, auth.HashToken("api", tok)))
	if err != nil {
		return nil, notFound(err)
	}
	if t.ExpiresAt != nil && s.now().After(*t.ExpiresAt) {
		return nil, ErrNotFound
	}
	if t.LastUsedAt == nil || s.now().Sub(*t.LastUsedAt) > time.Minute || t.LastIP != ip {
		_, _ = s.db.Exec(ctx, `UPDATE api_tokens SET last_used_at=$2, last_ip=$3 WHERE id=$1`, t.ID, s.now(), ip)
	}
	return t, nil
}

// DeleteAPIToken revokes a token.
func (s *Store) DeleteAPIToken(ctx context.Context, id string) error {
	return s.execScoped(ctx, `DELETE FROM api_tokens WHERE id=$1 AND $2 = ''`, id, "")
}

// IdempotentAnswer returns a stored answer of a create call.
func (s *Store) IdempotentAnswer(ctx context.Context, tokenID, key string) (int, string, bool) {
	var st int
	var body string
	err := s.db.QueryRow(ctx, `SELECT status, body FROM api_idempotency WHERE token_id=$1 AND key=$2 AND created_at > now() - interval '24 hours'`,
		tokenID, key).Scan(&st, &body)
	return st, body, err == nil
}

// SaveIdempotentAnswer stores the answer of a create call.
func (s *Store) SaveIdempotentAnswer(ctx context.Context, tokenID, key string, status int, body string) {
	_, _ = s.db.Exec(ctx, `INSERT INTO api_idempotency(token_id, key, status, body) VALUES($1,$2,$3,$4)
		ON CONFLICT (token_id, key) DO UPDATE SET status=$3, body=$4, created_at=now()`, tokenID, key, status, body)
	_, _ = s.db.Exec(ctx, `DELETE FROM api_idempotency WHERE created_at < now() - interval '24 hours'`)
}

// SetCustomerUsername sets the optional username of a customer (the same as
// in HostZit).
func (s *Store) SetCustomerUsername(ctx context.Context, id, username string) error {
	var v any
	if username = strings.TrimSpace(username); username != "" {
		if !usernameAPI.MatchString(username) {
			return errors.New("the username must be 3–16 lower-case letters and digits, starting with a letter")
		}
		v = username
	}
	tag, err := s.db.Exec(ctx, `UPDATE customers SET username=$2 WHERE id=$1`, id, v)
	if isUnique(err) {
		return ErrConflict
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- single sign-on links

// CreateSSOTicket makes a one-time sign-in secret for a customer login
// (valid 60 seconds).
func (s *Store) CreateSSOTicket(ctx context.Context, userID int64) (string, time.Time, error) {
	tok := auth.RandomToken(32)
	exp := s.now().Add(60 * time.Second)
	_, err := s.db.Exec(ctx, `INSERT INTO sso_tickets(hash, user_id, expires_at) VALUES($1,$2,$3)`, auth.HashToken("sso", tok), userID, exp)
	_, _ = s.db.Exec(ctx, `DELETE FROM sso_tickets WHERE expires_at < now()`)
	return tok, exp, err
}

// UseSSOTicket consumes a ticket and returns its user.
func (s *Store) UseSSOTicket(ctx context.Context, tok string) (int64, error) {
	var id int64
	var exp time.Time
	err := s.db.QueryRow(ctx, `DELETE FROM sso_tickets WHERE hash=$1 RETURNING user_id, expires_at`, auth.HashToken("sso", tok)).Scan(&id, &exp)
	if err != nil {
		return 0, notFound(err)
	}
	if s.now().After(exp) {
		return 0, ErrNotFound
	}
	return id, nil
}

// SetWebUIDs replaces the hosting account user IDs of a customer.
func (s *Store) SetWebUIDs(ctx context.Context, customerID string, uids []int) error {
	if len(uids) > 1000 {
		return errors.New("too many user IDs")
	}
	for _, u := range uids {
		if u < 1000000 || u > 1999999 {
			return errors.New("user IDs of hosting accounts are 1000000–1999999")
		}
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM customer_web_uids WHERE customer_id=$1`, customerID); err != nil {
		return err
	}
	for _, u := range uids {
		if _, err := tx.Exec(ctx, `INSERT INTO customer_web_uids(uid, customer_id) VALUES($1,$2)`, u, customerID); err != nil {
			if isUnique(err) {
				return errors.New("a user ID belongs to another customer")
			}
			return err
		}
	}
	return tx.Commit(ctx)
}

// WebUIDs lists the hosting account user IDs of a customer.
func (s *Store) WebUIDs(ctx context.Context, customerID string) ([]int, error) {
	rows, err := s.db.Query(ctx, `SELECT uid FROM customer_web_uids WHERE customer_id=$1 ORDER BY uid`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int{}
	for rows.Next() {
		var u int
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetDomainDNS stores the result of writing the domain's records into
// HostZit's DNS.
func (s *Store) SetDomainDNS(ctx context.Context, id string, managed bool, note string) error {
	if len(note) > 300 {
		note = note[:300]
	}
	_, err := s.db.Exec(ctx, `UPDATE domains SET dns_managed=$2, dns_note=$3, dns_at=now() WHERE id=$1`, id, managed, note)
	return err
}
