package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"
)

// The relay login of the HostZit link (INTEGRATION.md E3). There is at most
// one: it belongs to the link, not to a customer, and the pairing hands it
// to HostZit. Only EmailZit itself checks it (the relay submission server),
// so the password is kept as its SHA-256 like an app password.

// RelayLogin is the login of the linked HostZit.
type RelayLogin struct {
	ID       string
	Username string
	Created  time.Time
	LastUsed time.Time // zero: never used
	Disabled bool
}

func passHash(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// SetRelayLogin replaces the relay login with this one.
func (s *Store) SetRelayLogin(ctx context.Context, username, password string) (*RelayLogin, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM relay_logins`); err != nil {
		return nil, err
	}
	l := &RelayLogin{Username: strings.ToLower(strings.TrimSpace(username))}
	if err := tx.QueryRow(ctx, `INSERT INTO relay_logins(username, hash) VALUES($1,$2) RETURNING id, created_at`,
		l.Username, passHash(password)).Scan(&l.ID, &l.Created); err != nil {
		return nil, err
	}
	return l, tx.Commit(ctx)
}

// RelayLoginOf returns the relay login, or ErrNotFound when there is none.
func (s *Store) RelayLoginOf(ctx context.Context) (*RelayLogin, error) {
	l := &RelayLogin{}
	var used *time.Time
	err := s.db.QueryRow(ctx, `SELECT id, username, created_at, last_used, disabled FROM relay_logins ORDER BY created_at DESC LIMIT 1`).
		Scan(&l.ID, &l.Username, &l.Created, &used, &l.Disabled)
	if err != nil {
		return nil, notFound(err)
	}
	if used != nil {
		l.LastUsed = *used
	}
	return l, nil
}

// DeleteRelayLogins removes the relay login (the link ended).
func (s *Store) DeleteRelayLogins(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM relay_logins`)
	return err
}

// CheckRelayLogin returns the ID of the relay login when the password is
// right, and ErrNotFound otherwise.
func (s *Store) CheckRelayLogin(ctx context.Context, username, password string) (string, error) {
	var id, hash string
	err := s.db.QueryRow(ctx, `SELECT id, hash FROM relay_logins WHERE username=$1 AND NOT disabled`,
		strings.ToLower(strings.TrimSpace(username))).Scan(&id, &hash)
	if err != nil {
		return "", notFound(err)
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(passHash(password))) != 1 {
		return "", ErrNotFound
	}
	return id, nil
}

// TouchRelayLogin records that the relay login was used.
func (s *Store) TouchRelayLogin(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `UPDATE relay_logins SET last_used=now() WHERE id=$1`, id)
	return err
}

// DomainCustomer is the customer of a mail domain that may send here
// (verified, not disabled, customer active); ErrNotFound otherwise.
func (s *Store) DomainCustomer(ctx context.Context, domain string) (string, error) {
	var id string
	err := s.db.QueryRow(ctx, `SELECT d.customer_id FROM domains d JOIN customers c ON c.id = d.customer_id
		WHERE d.name=$1 AND d.verified AND NOT d.disabled AND c.status='active'`, strings.ToLower(domain)).Scan(&id)
	if err != nil {
		return "", notFound(err)
	}
	return id, nil
}

// RelayLimits are the limits for relayed mail of a customer: the package's
// customer limit and recipients per message, with the recipients of the
// last hour (mailboxes, hosting accounts and the relay together).
func (s *Store) RelayLimits(ctx context.Context, customerID string) (*SendLimits, error) {
	l := &SendLimits{CustomerID: customerID, PerHour: -1, PerDay: -1}
	err := s.db.QueryRow(ctx, `SELECT c.status <> 'active', p.customer_per_hour, p.rcpt_per_msg,
			(SELECT COALESCE(sum(rcpts), 0) FROM send_log s WHERE s.customer_id = c.id AND s.at > now() - interval '1 hour')
		FROM customers c JOIN packages p ON p.id = c.package_id WHERE c.id = $1`, customerID).
		Scan(&l.Blocked, &l.CustomerPerHour, &l.RcptPerMsg, &l.CustomerHour)
	if err != nil {
		return nil, notFound(err)
	}
	return l, nil
}

// RelayDomainHour counts the recipients the relay accepted for a sender
// domain in the last hour (the limit for a domain whose customer is not in
// EmailZit).
func (s *Store) RelayDomainHour(ctx context.Context, domain string) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT COALESCE(sum(rcpts), 0) FROM relay_log
		WHERE status='sent' AND split_part(sender, '@', 2) = $1 AND at > now() - interval '1 hour'`,
		strings.ToLower(domain)).Scan(&n)
	return n, err
}

// LogRelaySent counts relayed mail towards the customer's limit.
func (s *Store) LogRelaySent(ctx context.Context, customerID string, rcpts int) error {
	if customerID == "" {
		return nil
	}
	_, err := s.db.Exec(ctx, `INSERT INTO send_log(relay, customer_id, rcpts) VALUES(true,$1,$2)`, customerID, rcpts)
	return err
}

// RelayMail is one message the relay took or refused.
type RelayMail struct {
	CustomerID string // empty: the domain's customer is not in EmailZit
	Sender     string
	Rcpts      int
	QueueID    string
	Status     string // sent, refused
	Reason     string
	ClientIP   string
}

// LogRelay records a message of the relay (the customer's view of the mail
// of their websites, and the weekly report).
func (s *Store) LogRelay(ctx context.Context, m RelayMail) error {
	var cust any
	if m.CustomerID != "" {
		cust = m.CustomerID
	}
	if len(m.Reason) > 500 {
		m.Reason = m.Reason[:500]
	}
	_, err := s.db.Exec(ctx, `INSERT INTO relay_log(customer_id, sender, rcpts, queue_id, status, reason, client_ip)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, cust, strings.ToLower(m.Sender), m.Rcpts, m.QueueID, m.Status, m.Reason, m.ClientIP)
	return err
}

// RelayEntry is a line of the relay log with what became of the message.
type RelayEntry struct {
	At       time.Time
	Sender   string
	Rcpts    int
	QueueID  string
	Status   string
	Reason   string
	ClientIP string
	// Delivery is what the delivery log says about the queue ID
	// ("sent", "bounced", "deferred", ""), for mail the relay took.
	Delivery string
}

// RelayLog lists the newest messages of the relay. With a customer scope
// only that customer's mail is shown.
func (s *Store) RelayLog(ctx context.Context, sc Scope, limit int) ([]RelayEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(ctx, `SELECT r.at, r.sender, r.rcpts, r.queue_id, r.status, r.reason, r.client_ip,
			COALESCE((SELECT l.status FROM mail_log l WHERE l.queue_id = r.queue_id AND r.queue_id <> ''
				ORDER BY CASE l.status WHEN 'bounced' THEN 0 WHEN 'deferred' THEN 1 ELSE 2 END, l.at DESC LIMIT 1), '')
		FROM relay_log r
		WHERE ($1 = '' OR r.customer_id::text = $1)
		ORDER BY r.at DESC LIMIT $2`, sc.CustomerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RelayEntry
	for rows.Next() {
		var e RelayEntry
		if err := rows.Scan(&e.At, &e.Sender, &e.Rcpts, &e.QueueID, &e.Status, &e.Reason, &e.ClientIP, &e.Delivery); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RelayCounts counts the mail of the relay since a time (weekly report).
func (s *Store) RelayCounts(ctx context.Context, since time.Time) (sent, refused int, err error) {
	err = s.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='sent'), count(*) FILTER (WHERE status='refused')
		FROM relay_log WHERE at > $1`, since).Scan(&sent, &refused)
	return sent, refused, err
}

// CleanRelayLog drops relay entries older than the retention of the
// delivery log (30 days).
func (s *Store) CleanRelayLog(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM relay_log WHERE at < now() - interval '30 days'`)
	return err
}
