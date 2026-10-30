package store

import (
	"context"
	"strings"
)

// Mail from websites (emailzit-sendmail): a hosting account of HostZit is
// known by its Linux user ID, which HostZit registers for the customer.

// WebSendLimits loads the limits and counts of a hosting account. The
// package's per-mailbox limits apply to each hosting account, the customer
// limit to all of them together with the mailboxes.
func (s *Store) WebSendLimits(ctx context.Context, uid int) (*SendLimits, error) {
	l := &SendLimits{WebUID: uid}
	err := s.db.QueryRow(ctx, `SELECT w.customer_id, w.send_blocked OR c.status <> 'active',
			p.send_per_hour, p.send_per_day, p.customer_per_hour, p.rcpt_per_msg,
			(SELECT COALESCE(sum(rcpts), 0) FROM send_log l WHERE l.web_uid = w.uid AND l.at > now() - interval '1 hour'),
			(SELECT COALESCE(sum(rcpts), 0) FROM send_log l WHERE l.web_uid = w.uid AND l.at > now() - interval '1 day'),
			(SELECT COALESCE(sum(rcpts), 0) FROM send_log l WHERE l.customer_id = w.customer_id AND l.at > now() - interval '1 hour')
		FROM customer_web_uids w JOIN customers c ON c.id = w.customer_id JOIN packages p ON p.id = c.package_id
		WHERE w.uid = $1`, uid).
		Scan(&l.CustomerID, &l.Blocked, &l.PerHour, &l.PerDay, &l.CustomerPerHour, &l.RcptPerMsg, &l.SentHour, &l.SentDay, &l.CustomerHour)
	if err != nil {
		return nil, notFound(err)
	}
	return l, nil
}

// LogWebRefused records an attempt of a hosting account refused by a limit
// and returns how many were refused for it in the last hour.
func (s *Store) LogWebRefused(ctx context.Context, uid int, reason string) (int, error) {
	if _, err := s.db.Exec(ctx, `INSERT INTO send_refused(web_uid, reason) VALUES($1,$2)`, uid, reason); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM send_refused WHERE web_uid=$1 AND at > now() - interval '1 hour'`, uid).Scan(&n)
	return n, err
}

// SetWebSendBlocked blocks or allows mail from a hosting account.
func (s *Store) SetWebSendBlocked(ctx context.Context, sc Scope, uid int, blocked bool) error {
	tag, err := s.db.Exec(ctx, `UPDATE customer_web_uids SET send_blocked=$2 WHERE uid=$1 AND ($3 = '' OR customer_id::text = $3)`, uid, blocked, sc.CustomerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// WebSender is a hosting account with its sending counts.
type WebSender struct {
	UID         int
	Blocked     bool
	Hour, Day   int
	RefusedHour int
}

// WebSenders lists the hosting accounts of a customer.
func (s *Store) WebSenders(ctx context.Context, customerID string) ([]WebSender, error) {
	rows, err := s.db.Query(ctx, `SELECT w.uid, w.send_blocked,
			(SELECT COALESCE(sum(rcpts),0) FROM send_log WHERE web_uid=w.uid AND at > now() - interval '1 hour'),
			(SELECT COALESCE(sum(rcpts),0) FROM send_log WHERE web_uid=w.uid AND at > now() - interval '1 day'),
			(SELECT count(*) FROM send_refused WHERE web_uid=w.uid AND at > now() - interval '1 hour')
		FROM customer_web_uids w WHERE w.customer_id=$1 ORDER BY w.uid`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebSender
	for rows.Next() {
		var w WebSender
		if err := rows.Scan(&w.UID, &w.Blocked, &w.Hour, &w.Day, &w.RefusedHour); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// CustomerSendDomain tells whether a website of the customer may send as
// an address of the domain: the domain is the customer's, verified and on.
func (s *Store) CustomerSendDomain(ctx context.Context, customerID, domain string) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM domains WHERE customer_id=$1 AND name=$2 AND verified AND NOT disabled)`,
		customerID, strings.ToLower(domain)).Scan(&ok)
	return ok, err
}
