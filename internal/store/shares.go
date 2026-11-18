package store

// Shared folders between the mailboxes of one customer.
//
// The office with one info@ that three people answer has two bad
// answers today: one password three people know, or a forwarder that
// makes three copies and loses every reply. The third answer is the one
// mail servers were built for — the folder stays where it is and the
// others are let in — and that is what this is.
//
// Only inside one customer. That is not politeness: every customer has
// its own system user and its mail directory is 0700, so another
// customer's Dovecot process cannot read the files whatever an ACL says.

import (
	"context"
	"errors"
	"strings"
)

// Share rights.
const (
	ShareRead  = "read"  // look and read
	ShareWrite = "write" // read, mark, move, delete, file mail
)

// Share is one folder of one mailbox opened for another mailbox.
type Share struct {
	OwnerID      string
	OwnerAddress string
	WithID       string
	WithAddress  string
	Folder       string
	Rights       string
}

// May reports whether the rights name a share that may be written.
func ValidShareRights(r string) bool { return r == ShareRead || r == ShareWrite }

// ValidFolder checks a folder name of a shared folder: a name a mail
// program shows, without the characters that would break the ACL file or
// the command line of doveadm.
func ValidFolder(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 || strings.HasPrefix(name, "-") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`"'\`, r) {
			return false
		}
	}
	return true
}

// AddShare opens a folder of a mailbox for another mailbox of the same
// customer and returns both mailboxes.
func (s *Store) AddShare(ctx context.Context, sc Scope, ownerID, withID, folder, rights string) (*Mailbox, *Mailbox, error) {
	folder = strings.TrimSpace(folder)
	if !ValidShareRights(rights) || !ValidFolder(folder) {
		return nil, nil, errors.New("the folder or the rights are not valid")
	}
	owner, err := s.MailboxByID(ctx, sc, ownerID)
	if err != nil {
		return nil, nil, err
	}
	with, err := s.MailboxByID(ctx, sc, withID)
	if err != nil {
		return nil, nil, err
	}
	if owner.ID == with.ID {
		return nil, nil, errors.New("a mailbox cannot be shared with itself")
	}
	if owner.CustomerID != with.CustomerID {
		// the panel never offers it; a hand-written request must not do it
		// either, because the two live under different system users
		return nil, nil, errors.New("both mailboxes must belong to the same customer")
	}
	_, err = s.db.Exec(ctx, `INSERT INTO mailbox_shares(owner_id, with_id, folder, rights) VALUES($1,$2,$3,$4)
		ON CONFLICT (owner_id, with_id, folder) DO UPDATE SET rights=$4`, owner.ID, with.ID, folder, rights)
	if err != nil {
		return nil, nil, err
	}
	return owner, with, nil
}

// RemoveShare closes a shared folder again.
func (s *Store) RemoveShare(ctx context.Context, sc Scope, ownerID, withID, folder string) (*Mailbox, *Mailbox, error) {
	owner, err := s.MailboxByID(ctx, sc, ownerID)
	if err != nil {
		return nil, nil, err
	}
	with, err := s.MailboxByID(ctx, sc, withID)
	if err != nil {
		return nil, nil, err
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM mailbox_shares WHERE owner_id=$1 AND with_id=$2 AND folder=$3`, owner.ID, with.ID, folder)
	if err != nil {
		return nil, nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, nil, ErrNotFound
	}
	return owner, with, nil
}

const shareCols = `o.id, o.address, w.id, w.address, s.folder, s.rights
	FROM mailbox_shares s JOIN mailboxes o ON o.id = s.owner_id JOIN mailboxes w ON w.id = s.with_id`

// SharesOf lists what a mailbox shares and what is shared with it.
func (s *Store) SharesOf(ctx context.Context, sc Scope, mailboxID string) (shared, received []Share, err error) {
	if !ValidID(mailboxID) {
		return nil, nil, ErrNotFound
	}
	rows, err := s.db.Query(ctx, `SELECT `+shareCols+`
		WHERE (s.owner_id=$1 OR s.with_id=$1) AND ($2 = '' OR o.customer_id::text = $2)
		ORDER BY o.address, s.folder, w.address`, mailboxID, sc.CustomerID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var x Share
		if err := rows.Scan(&x.OwnerID, &x.OwnerAddress, &x.WithID, &x.WithAddress, &x.Folder, &x.Rights); err != nil {
			return nil, nil, err
		}
		if x.OwnerID == mailboxID {
			shared = append(shared, x)
		} else {
			received = append(received, x)
		}
	}
	return shared, received, rows.Err()
}

// AllShares lists every share of the server: what the helper writes again
// at a start, after a restore or when a mailbox was imported.
func (s *Store) AllShares(ctx context.Context) ([]Share, error) {
	rows, err := s.db.Query(ctx, `SELECT `+shareCols+` ORDER BY o.address, s.folder, w.address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		var x Share
		if err := rows.Scan(&x.OwnerID, &x.OwnerAddress, &x.WithID, &x.WithAddress, &x.Folder, &x.Rights); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
