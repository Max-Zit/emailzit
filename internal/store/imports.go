package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Import is a move of mail from another server into a mailbox.
type Import struct {
	ID         string
	MailboxID  string
	CustomerID string
	Host       string
	Port       int
	Insecure   bool
	Username   string
	Status     string
	Folders    int
	Copied     int
	Skipped    int
	Error      string
	CreatedBy  string
	CreatedAt  time.Time
	FinishedAt *time.Time
}

const importCols = `id, mailbox_id, customer_id, host, port, insecure, username, status, folders, copied, skipped, error, created_by, created_at, finished_at`

func scanImport(row interface{ Scan(...any) error }) (*Import, error) {
	i := &Import{}
	err := row.Scan(&i.ID, &i.MailboxID, &i.CustomerID, &i.Host, &i.Port, &i.Insecure, &i.Username, &i.Status, &i.Folders, &i.Copied,
		&i.Skipped, &i.Error, &i.CreatedBy, &i.CreatedAt, &i.FinishedAt)
	return i, err
}

// CreateImport queues an import for a mailbox of the scope.
func (s *Store) CreateImport(ctx context.Context, sc Scope, mailboxID, host string, port int, insecure bool, user, password, by string) (*Import, error) {
	m, err := s.MailboxByID(ctx, sc, mailboxID)
	if err != nil {
		return nil, err
	}
	host, user = strings.TrimSpace(strings.ToLower(host)), strings.TrimSpace(user)
	if _, err := NormalizeDomain(host); err != nil {
		return nil, errors.New("give the name of the old mail server, for example imap.example.com")
	}
	if port != 993 && port != 143 {
		return nil, errors.New("the port must be 993 (IMAP over TLS) or 143 (IMAP with STARTTLS)")
	}
	if user == "" || len(user) > 200 || password == "" || len(password) > 500 {
		return nil, errors.New("give the user name and password of the old mailbox")
	}
	var running int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM imap_imports WHERE mailbox_id=$1 AND status IN ('queued','running')`, m.ID).Scan(&running); err != nil {
		return nil, err
	}
	if running > 0 {
		return nil, errors.New("an import of this mailbox is already running")
	}
	id := NewID()
	_, err = s.db.Exec(ctx, `INSERT INTO imap_imports(id, mailbox_id, customer_id, host, port, insecure, username, password, created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		id, m.ID, m.CustomerID, host, port, insecure, user, s.box.seal("imap_imports.password", password), by)
	if err != nil {
		return nil, err
	}
	return s.ImportByID(ctx, id)
}

// ImportByID loads an import.
func (s *Store) ImportByID(ctx context.Context, id string) (*Import, error) {
	i, err := scanImport(s.db.QueryRow(ctx, `SELECT `+importCols+` FROM imap_imports WHERE id=$1`, id))
	return i, notFound(err)
}

// Imports lists the imports of a mailbox, newest first.
func (s *Store) Imports(ctx context.Context, mailboxID string) ([]*Import, error) {
	rows, err := s.db.Query(ctx, `SELECT `+importCols+` FROM imap_imports WHERE mailbox_id=$1 ORDER BY created_at DESC LIMIT 20`, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Import
	for rows.Next() {
		i, err := scanImport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// NextImport takes the oldest queued import (running from now on) with
// its password; nil when there is none.
func (s *Store) NextImport(ctx context.Context) (*Import, string, error) {
	var id, sealed string
	err := s.db.QueryRow(ctx, `UPDATE imap_imports SET status='running' WHERE id = (SELECT id FROM imap_imports WHERE status='queued'
		ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id, password`).Scan(&id, &sealed)
	if err != nil {
		if errors.Is(notFound(err), ErrNotFound) {
			return nil, "", nil
		}
		return nil, "", err
	}
	pw, err := s.box.open("imap_imports.password", sealed)
	if err != nil {
		return nil, "", err
	}
	i, err := s.ImportByID(ctx, id)
	return i, pw, err
}

// ImportProgress stores the counts of a running import.
func (s *Store) ImportProgress(ctx context.Context, id string, folders, copied, skipped int) error {
	_, err := s.db.Exec(ctx, `UPDATE imap_imports SET folders=$2, copied=$3, skipped=$4 WHERE id=$1`, id, folders, copied, skipped)
	return err
}

// FinishImport ends an import and forgets the password.
func (s *Store) FinishImport(ctx context.Context, id, errMsg string) error {
	st := "done"
	if errMsg != "" {
		st = "failed"
	}
	if len(errMsg) > 500 {
		errMsg = errMsg[:500]
	}
	_, err := s.db.Exec(ctx, `UPDATE imap_imports SET status=$2, error=$3, password='', finished_at=now() WHERE id=$1`, id, st, errMsg)
	return err
}

// ResetRunningImports puts imports that were running when the server
// stopped back in the queue (at start).
func (s *Store) ResetRunningImports(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `UPDATE imap_imports SET status='queued' WHERE status='running' AND password <> ''`)
	return err
}
