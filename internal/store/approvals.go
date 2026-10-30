package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ApprovalTimeout is how long a request waits for the second person.
const ApprovalTimeout = 24 * time.Hour

// Approval is a risky change waiting for a second administrator.
type Approval struct {
	ID          int64
	Action      string
	Path        string
	PathValues  map[string]string
	Form        string // sealed JSON of the form values
	Summary     string
	RequestedBy int64
	Requester   string
	RequestedAt time.Time
	Status      string
	DecidedBy   string
	DecidedAt   *time.Time
}

// CreateApproval stores a request.
func (s *Store) CreateApproval(ctx context.Context, a *Approval) error {
	pv, _ := json.Marshal(a.PathValues)
	return s.db.QueryRow(ctx, `INSERT INTO approvals(action, path, path_values, form, summary, requested_by)
		VALUES($1,$2,$3,$4,$5,$6) RETURNING id, requested_at`, a.Action, a.Path, pv, a.Form, a.Summary, a.RequestedBy).Scan(&a.ID, &a.RequestedAt)
}

const approvalCols = `a.id, a.action, a.path, a.path_values, a.form, a.summary, a.requested_by, COALESCE(r.username, ''), a.requested_at,
	CASE WHEN a.status = 'pending' AND a.requested_at < now() - interval '24 hours' THEN 'expired' ELSE a.status END,
	COALESCE(d.username, ''), a.decided_at`

func scanApproval(row interface{ Scan(...any) error }) (*Approval, error) {
	a := &Approval{}
	var pv []byte
	if err := row.Scan(&a.ID, &a.Action, &a.Path, &pv, &a.Form, &a.Summary, &a.RequestedBy, &a.Requester, &a.RequestedAt, &a.Status, &a.DecidedBy, &a.DecidedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(pv, &a.PathValues)
	return a, nil
}

// Approvals lists the pending requests and the ones decided in the last
// week, newest first.
func (s *Store) Approvals(ctx context.Context) ([]*Approval, error) {
	rows, err := s.db.Query(ctx, `SELECT `+approvalCols+` FROM approvals a
		LEFT JOIN users r ON r.id = a.requested_by LEFT JOIN users d ON d.id = a.decided_by
		WHERE a.status = 'pending' OR a.requested_at > now() - interval '7 days'
		ORDER BY a.id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PendingApprovals counts the requests waiting.
func (s *Store) PendingApprovals(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE status = 'pending' AND requested_at > now() - interval '24 hours'`).Scan(&n)
	return n, err
}

// ErrSelfApproval: the requester cannot decide their own request (only
// withdraw it).
var ErrSelfApproval = errors.New("a request needs another administrator")

// DecideApproval approves or rejects a pending request once. Approving
// needs a different user than the requester; the requester may reject
// (withdraw) their own request.
func (s *Store) DecideApproval(ctx context.Context, id, by int64, approve bool) (*Approval, error) {
	status := "rejected"
	if approve {
		status = "approved"
	}
	tag, err := s.db.Exec(ctx, `UPDATE approvals SET status=$3, decided_by=$2, decided_at=now()
		WHERE id=$1 AND status='pending' AND requested_at > now() - interval '24 hours' AND (NOT $4 OR requested_by <> $2)`, id, by, status, approve)
	if err != nil {
		return nil, err
	}
	a, err := scanApproval(s.db.QueryRow(ctx, `SELECT `+approvalCols+` FROM approvals a
		LEFT JOIN users r ON r.id = a.requested_by LEFT JOIN users d ON d.id = a.decided_by WHERE a.id=$1`, id))
	if err != nil {
		return nil, notFound(err)
	}
	if tag.RowsAffected() == 0 {
		if approve && a.Status == "pending" && a.RequestedBy == by {
			return nil, ErrSelfApproval
		}
		return nil, ErrConflict
	}
	return a, nil
}

// ActiveAdmins counts administrators who can sign in (four-eyes needs two).
func (s *Store) ActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled`).Scan(&n)
	return n, err
}
