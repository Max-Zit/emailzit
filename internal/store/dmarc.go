package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/max-zit/emailzit/internal/dmarc"
)

// DMARCAddress is the local part that receives a domain's DMARC reports;
// no mailbox or alias may use it.
const DMARCAddress = "dmarc-reports"

// keepDMARC is how long reports are kept.
const keepDMARC = 180 * 24 * time.Hour

// SaveDMARCReport stores a report that arrived at dmarc-reports@<domain>.
// Only reports about that domain (or its subdomains) are kept; a report
// that arrives twice is stored once. False: the report was not stored.
func (s *Store) SaveDMARCReport(ctx context.Context, recipientDomain string, r *dmarc.Report) (bool, error) {
	recipientDomain = strings.ToLower(recipientDomain)
	if r.Domain != recipientDomain && !strings.HasSuffix(r.Domain, "."+recipientDomain) {
		return false, nil
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var domainID string
	if err := tx.QueryRow(ctx, `SELECT id FROM domains WHERE name=$1`, recipientDomain).Scan(&domainID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO dmarc_reports (domain_id, org, email, report_id, policy, begin_at, end_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (domain_id, org, report_id) DO NOTHING RETURNING id`,
		domainID, r.Org, r.Email, r.ID, r.Policy, r.Begin, r.End).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // already stored
	}
	if err != nil {
		return false, err
	}
	rows := make([][]any, 0, len(r.Records))
	for _, x := range r.Records {
		rows = append(rows, []any{id, x.SourceIP, x.Count, x.Disposition, x.DKIM, x.SPF, x.HeaderFrom})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"dmarc_records"},
		[]string{"report_id", "source_ip", "count", "disposition", "dkim", "spf", "header_from"}, pgx.CopyFromRows(rows)); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM dmarc_reports WHERE domain_id=$1 AND end_at < $2`, domainID, time.Now().Add(-keepDMARC)); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// DMARCSource is the mail from one address in the reports of a period.
type DMARCSource struct {
	IP        netip.Addr
	Messages  int
	Passed    int
	DKIM, SPF int // messages with aligned DKIM, SPF
	Rejected  int // quarantined or refused by receivers
	Reporters string
}

// DMARCSummary is what the reports of a domain say about the last days.
type DMARCSummary struct {
	Reports  int
	Messages int
	Passed   int
	Last     *time.Time
	Sources  []DMARCSource
}

// DMARCSummary sums up a domain's reports since a time, per sending
// address (most mail first, at most 50).
func (s *Store) DMARCSummary(ctx context.Context, domainID string, since time.Time) (*DMARCSummary, error) {
	sum := &DMARCSummary{}
	if err := s.db.QueryRow(ctx, `SELECT count(DISTINCT r.id), max(r.received_at), COALESCE(sum(x.count), 0), COALESCE(sum(x.count) FILTER (WHERE x.dkim OR x.spf), 0)
		FROM dmarc_reports r LEFT JOIN dmarc_records x ON x.report_id = r.id WHERE r.domain_id=$1 AND r.end_at >= $2`, domainID, since).
		Scan(&sum.Reports, &sum.Last, &sum.Messages, &sum.Passed); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT x.source_ip, sum(x.count), sum(x.count) FILTER (WHERE x.dkim OR x.spf),
		COALESCE(sum(x.count) FILTER (WHERE x.dkim), 0), COALESCE(sum(x.count) FILTER (WHERE x.spf), 0),
		COALESCE(sum(x.count) FILTER (WHERE x.disposition IN ('quarantine', 'reject')), 0),
		string_agg(DISTINCT r.org, ', ')
		FROM dmarc_records x JOIN dmarc_reports r ON r.id = x.report_id
		WHERE r.domain_id=$1 AND r.end_at >= $2
		GROUP BY x.source_ip ORDER BY 2 DESC, 1 LIMIT 50`, domainID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var x DMARCSource
		var passed *int
		if err := rows.Scan(&x.IP, &x.Messages, &passed, &x.DKIM, &x.SPF, &x.Rejected, &x.Reporters); err != nil {
			return nil, err
		}
		if passed != nil {
			x.Passed = *passed
		}
		sum.Sources = append(sum.Sources, x)
	}
	return sum, rows.Err()
}
