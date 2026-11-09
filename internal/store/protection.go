package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// SetCustomerOutboundIP assigns one of the server's extra sending
// addresses to a customer (empty: the server's address).
func (s *Store) SetCustomerOutboundIP(ctx context.Context, customerID, ip string) error {
	if ip != "" {
		if a, err := netip.ParseAddr(ip); err != nil || a.String() != ip {
			return errors.New("the address is not valid")
		}
	}
	tag, err := s.db.Exec(ctx, `UPDATE customers SET outbound_ip=$2 WHERE id=$1`, customerID, ip)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ClearOutboundIPs takes addresses that are no longer configured away from
// the customers (Postfix would otherwise look for a transport that is gone).
func (s *Store) ClearOutboundIPs(ctx context.Context, keep []string) (int64, error) {
	if keep == nil {
		keep = []string{}
	}
	tag, err := s.db.Exec(ctx, `UPDATE customers SET outbound_ip='' WHERE outbound_ip <> '' AND NOT (outbound_ip = ANY($1))`, keep)
	return tag.RowsAffected(), err
}

// OutboundIPCounts counts the customers per assigned address.
func (s *Store) OutboundIPCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.Query(ctx, `SELECT outbound_ip, count(*) FROM customers WHERE outbound_ip <> '' GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var ip string
		var n int
		if err := rows.Scan(&ip, &n); err != nil {
			return nil, err
		}
		out[ip] = n
	}
	return out, rows.Err()
}

// SpamSender is a mailbox whose outgoing mail Rspamd refused as spam or
// virus within the window.
type SpamSender struct {
	MailboxID, Address, Lang string
	Messages                 int
}

// OutboundSpamSenders lists mailboxes (still allowed to send) with at
// least min refused messages since the time. The sender address leads to
// the login through the same view Postfix uses (own address or a
// send-as alias).
func (s *Store) OutboundSpamSenders(ctx context.Context, since time.Time, min int) ([]SpamSender, error) {
	rows, err := s.db.Query(ctx, `SELECT m.id::text, m.address, m.lang, count(DISTINCT CASE WHEN l.queue_id <> '' THEN l.queue_id ELSE l.id::text END)
		FROM mail_log l JOIN mta_sender_logins sl ON sl.sender = l.sender JOIN mailboxes m ON m.address = sl.login
		WHERE l.outbound AND l.status = 'rejected' AND l.at > $1 AND NOT m.send_blocked
		  AND (l.info ILIKE '%spam message rejected%' OR l.info ILIKE '%virus found%' OR l.info ILIKE '%gtube pattern%')
		GROUP BY m.id, m.address, m.lang HAVING count(DISTINCT CASE WHEN l.queue_id <> '' THEN l.queue_id ELSE l.id::text END) >= $2`, since, min)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SpamSender
	for rows.Next() {
		var x SpamSender
		if err := rows.Scan(&x.MailboxID, &x.Address, &x.Lang, &x.Messages); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// MailStats are the numbers of the weekly report.
type MailStats struct {
	Received, Sent, Deferred, Bounced int
	RefusedIn, RefusedOut             int // all refusals of incoming / outgoing mail
	Spam, Viruses, Attachments        int // refusals by Rspamd (both directions)
	TopSenders                        []TopSender
}

// TopSender is a mailbox with its count of delivered outgoing recipients.
type TopSender struct {
	Address string
	Count   int
}

// MailStatsSince counts the delivery log since the time.
func (s *Store) MailStatsSince(ctx context.Context, since time.Time) (*MailStats, error) {
	st := &MailStats{}
	err := s.db.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE status='sent' AND NOT outbound),
		count(*) FILTER (WHERE status='sent' AND outbound),
		count(DISTINCT queue_id) FILTER (WHERE status='deferred'),
		count(*) FILTER (WHERE status='bounced'),
		count(*) FILTER (WHERE status='rejected' AND NOT outbound),
		count(*) FILTER (WHERE status='rejected' AND outbound),
		count(*) FILTER (WHERE status='rejected' AND (info ILIKE '%spam message rejected%' OR info ILIKE '%gtube pattern%')),
		count(*) FILTER (WHERE status='rejected' AND info ILIKE '%virus found%'),
		count(*) FILTER (WHERE status='rejected' AND info ILIKE '%as attachments%')
		FROM mail_log WHERE at > $1`, since).Scan(&st.Received, &st.Sent, &st.Deferred, &st.Bounced, &st.RefusedIn, &st.RefusedOut, &st.Spam, &st.Viruses, &st.Attachments)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT sender, count(*) FROM mail_log WHERE at > $1 AND outbound AND status='sent' AND sender <> ''
		GROUP BY sender ORDER BY 2 DESC, 1 LIMIT 10`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t TopSender
		if err := rows.Scan(&t.Address, &t.Count); err != nil {
			return nil, err
		}
		st.TopSenders = append(st.TopSenders, t)
	}
	return st, rows.Err()
}

// AdminNotice reads when a notice kind was last sent and its state.
func (s *Store) AdminNotice(ctx context.Context, kind string) (time.Time, string, error) {
	var at time.Time
	var state string
	err := s.db.QueryRow(ctx, `SELECT sent_at, state FROM admin_notices WHERE kind=$1`, kind).Scan(&at, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, "", nil
	}
	return at, state, err
}

// SetAdminNotice records a sent notice.
func (s *Store) SetAdminNotice(ctx context.Context, kind, state string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO admin_notices(kind, sent_at, state) VALUES($1, now(), $2)
		ON CONFLICT (kind) DO UPDATE SET sent_at=now(), state=$2`, kind, state)
	return err
}
