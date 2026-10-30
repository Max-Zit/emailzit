package store

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// SendLimits are the limits that apply to one mailbox right now.
type SendLimits struct {
	MailboxID       string
	WebUID          int // mail from a website (emailzit-sendmail) instead of a mailbox
	CustomerID      string
	Blocked         bool
	PerHour         int // recipients per hour (mailbox)
	PerDay          int
	CustomerPerHour int
	RcptPerMsg      int
	SentHour        int // recipients in the last hour (mailbox)
	SentDay         int
	CustomerHour    int
}

// SendLimitsFor loads the limits and the current counts of a signed-in
// mailbox (the SASL user name is its address).
func (s *Store) SendLimitsFor(ctx context.Context, address string) (*SendLimits, error) {
	l := &SendLimits{}
	err := s.db.QueryRow(ctx, `SELECT m.id, m.customer_id, m.send_blocked OR c.status <> 'active' OR m.disabled,
			COALESCE(m.send_per_hour, p.send_per_hour), COALESCE(m.send_per_day, p.send_per_day), p.customer_per_hour, p.rcpt_per_msg,
			(SELECT COALESCE(sum(rcpts), 0) FROM send_log l WHERE l.mailbox_id = m.id AND l.at > now() - interval '1 hour'),
			(SELECT COALESCE(sum(rcpts), 0) FROM send_log l WHERE l.mailbox_id = m.id AND l.at > now() - interval '1 day'),
			(SELECT COALESCE(sum(rcpts), 0) FROM send_log l WHERE l.customer_id = m.customer_id AND l.at > now() - interval '1 hour')
		FROM mailboxes m JOIN customers c ON c.id = m.customer_id JOIN packages p ON p.id = c.package_id
		WHERE m.address = $1`, strings.ToLower(address)).
		Scan(&l.MailboxID, &l.CustomerID, &l.Blocked, &l.PerHour, &l.PerDay, &l.CustomerPerHour, &l.RcptPerMsg, &l.SentHour, &l.SentDay, &l.CustomerHour)
	if err != nil {
		return nil, notFound(err)
	}
	return l, nil
}

// LogSent records an accepted message.
func (s *Store) LogSent(ctx context.Context, l *SendLimits, rcpts int, ip string) error {
	if l.WebUID > 0 {
		_, err := s.db.Exec(ctx, `INSERT INTO send_log(web_uid, customer_id, rcpts, client_ip) VALUES($1,$2,$3,$4)`, l.WebUID, l.CustomerID, rcpts, ip)
		return err
	}
	_, err := s.db.Exec(ctx, `INSERT INTO send_log(mailbox_id, customer_id, rcpts, client_ip) VALUES($1,$2,$3,$4)`, l.MailboxID, l.CustomerID, rcpts, ip)
	return err
}

// LogRefused records an attempt refused by a limit and returns how many
// were refused for the mailbox in the last hour.
func (s *Store) LogRefused(ctx context.Context, mailboxID, reason string) (int, error) {
	if _, err := s.db.Exec(ctx, `INSERT INTO send_refused(mailbox_id, reason) VALUES($1,$2)`, mailboxID, reason); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM send_refused WHERE mailbox_id=$1 AND at > now() - interval '1 hour'`, mailboxID).Scan(&n)
	return n, err
}

// BlockSending stops a mailbox from sending (abuse); staff lift it.
func (s *Store) BlockSending(ctx context.Context, mailboxID string) error {
	_, err := s.db.Exec(ctx, `UPDATE mailboxes SET send_blocked=true WHERE id=$1`, mailboxID)
	return err
}

// PurgeSendLog drops counts older than two days.
func (s *Store) PurgeSendLog(ctx context.Context) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM send_log WHERE at < now() - interval '2 days'`); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM send_refused WHERE at < now() - interval '2 days'`)
	return err
}

// SentStats are the sending counts of a mailbox for the panels.
type SentStats struct{ Hour, Day, RefusedHour int }

// MailboxSentStats counts what a mailbox sent.
func (s *Store) MailboxSentStats(ctx context.Context, mailboxID string) (SentStats, error) {
	var st SentStats
	err := s.db.QueryRow(ctx, `SELECT
		(SELECT COALESCE(sum(rcpts),0) FROM send_log WHERE mailbox_id=$1 AND at > now() - interval '1 hour'),
		(SELECT COALESCE(sum(rcpts),0) FROM send_log WHERE mailbox_id=$1 AND at > now() - interval '1 day'),
		(SELECT count(*) FROM send_refused WHERE mailbox_id=$1 AND at > now() - interval '1 hour')`, mailboxID).Scan(&st.Hour, &st.Day, &st.RefusedHour)
	return st, err
}

// ---- DKIM

// DKIMKey is the signing key of a domain.
type DKIMKey struct {
	Domain   string
	Selector string
	Private  string // PEM (PKCS#8), only for the root helper
	Public   string // base64 DER, the p= of the DNS record
	Created  time.Time
}

// Record is the TXT value of the key's DNS record.
func (k *DKIMKey) Record() string { return "v=DKIM1; k=rsa; p=" + k.Public }

// RecordName is where the TXT record goes.
func (k *DKIMKey) RecordName() string { return k.Selector + "._domainkey." + k.Domain }

// EnsureDKIM creates the DKIM key of a domain if it has none yet and returns
// it (with the private key, for the root helper).
func (s *Store) EnsureDKIM(ctx context.Context, domainID string) (*DKIMKey, error) {
	k, err := s.DKIM(ctx, domainID)
	if err == nil && k.Selector != "" {
		return k, nil
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return s.NewDKIM(ctx, domainID)
}

// NewDKIM makes a new key for a domain (replacing the old one: the DNS
// record must be updated; with HostZit this happens by itself).
func (s *Store) NewDKIM(ctx context.Context, domainID string) (*DKIMKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	priv := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	sel := "ez" + s.now().UTC().Format("200601")
	// a second key in the same month gets a suffix
	var cur string
	_ = s.db.QueryRow(ctx, `SELECT dkim_selector FROM domains WHERE id=$1`, domainID).Scan(&cur)
	if strings.HasPrefix(cur, sel) {
		i := (len(cur) - len(sel)) % 26
		sel += "abcdefghijklmnopqrstuvwxyz"[i : i+1]
	}
	tag, err := s.db.Exec(ctx, `UPDATE domains SET dkim_selector=$2, dkim_private=$3, dkim_public=$4, dkim_created=$5 WHERE id=$1`,
		domainID, sel, s.box.seal("domains.dkim_private", priv), base64.StdEncoding.EncodeToString(pub), s.now())
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.DKIM(ctx, domainID)
}

// DKIM loads the key of a domain (Selector "" = none yet).
func (s *Store) DKIM(ctx context.Context, domainID string) (*DKIMKey, error) {
	if !ValidID(domainID) {
		return nil, ErrNotFound
	}
	k := &DKIMKey{}
	var sealed string
	var created *time.Time
	err := s.db.QueryRow(ctx, `SELECT name, dkim_selector, dkim_private, dkim_public, dkim_created FROM domains WHERE id=$1`, domainID).
		Scan(&k.Domain, &k.Selector, &sealed, &k.Public, &created)
	if err != nil {
		return nil, notFound(err)
	}
	if created != nil {
		k.Created = *created
	}
	if sealed != "" {
		if k.Private, err = s.box.open("domains.dkim_private", sealed); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// AllDKIM lists the keys of all domains that have one (the helper writes
// them all at start).
func (s *Store) AllDKIM(ctx context.Context) ([]*DKIMKey, error) {
	rows, err := s.db.Query(ctx, `SELECT id FROM domains WHERE dkim_selector <> '' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	var out []*DKIMKey
	for _, id := range ids {
		k, err := s.DKIM(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// LogEntry is a line of the delivery log.
type LogEntry struct {
	At        time.Time
	QueueID   string
	Sender    string
	Recipient string
	Status    string
	Relay     string
	DSN       string
	Info      string
}

// LogFilter narrows the delivery log.
type LogFilter struct {
	Query  string // address or part of it
	Status string
	Limit  int
}

// DeliveryLog lists the newest entries in the scope: a customer sees what
// was sent from or to its own domains.
func (s *Store) DeliveryLog(ctx context.Context, sc Scope, f LogFilter) ([]LogEntry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	rows, err := s.db.Query(ctx, `SELECT at, queue_id, sender, recipient, status, relay, dsn, info FROM mail_log l
		WHERE ($1 = '' OR split_part(l.recipient, '@', 2) IN (SELECT name FROM domains WHERE customer_id::text = $1)
		           OR split_part(l.sender, '@', 2) IN (SELECT name FROM domains WHERE customer_id::text = $1))
		  AND ($2 = '' OR l.recipient LIKE $2 OR l.sender LIKE $2)
		  AND ($3 = '' OR l.status = $3)
		ORDER BY l.at DESC, l.id DESC LIMIT $4`, sc.CustomerID, likeQuery(f.Query), f.Status, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.At, &e.QueueID, &e.Sender, &e.Recipient, &e.Status, &e.Relay, &e.DSN, &e.Info); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
