package store

import "context"

// QuotaCheck is a mailbox whose usage crossed a warning level.
type QuotaCheck struct {
	ID, Address, CustomerID, Lang string
	UsedBytes                     int64
	QuotaMB, Warned               int
}

// QuotaChecks lists mailboxes of active customers with a quota whose
// warning level must change (now at least 80 % and not warned at that level
// yet, or below 70 % after a warning).
func (s *Store) QuotaChecks(ctx context.Context) ([]QuotaCheck, error) {
	rows, err := s.db.Query(ctx, `SELECT m.id, m.address, m.customer_id, m.lang, m.used_bytes, m.quota_mb, m.quota_warned
		FROM mailboxes m JOIN customers c ON c.id = m.customer_id
		WHERE c.status = 'active' AND NOT m.disabled AND m.quota_mb > 0 AND (
			(m.used_bytes * 100 >= m.quota_mb::bigint * 1048576 * 80 AND m.quota_warned < 80) OR
			(m.used_bytes * 100 >= m.quota_mb::bigint * 1048576 * 95 AND m.quota_warned < 95) OR
			(m.used_bytes * 100 < m.quota_mb::bigint * 1048576 * 70 AND m.quota_warned > 0))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QuotaCheck
	for rows.Next() {
		var q QuotaCheck
		if err := rows.Scan(&q.ID, &q.Address, &q.CustomerID, &q.Lang, &q.UsedBytes, &q.QuotaMB, &q.Warned); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// SetQuotaWarned stores the warning level of a mailbox.
func (s *Store) SetQuotaWarned(ctx context.Context, id string, level int) error {
	_, err := s.db.Exec(ctx, `UPDATE mailboxes SET quota_warned=$2 WHERE id=$1`, id, level)
	return err
}
