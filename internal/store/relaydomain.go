package store

import (
	"context"
	"strings"
	"time"
)

// A website on a linked HostZit may send mail for a domain that has no
// mail here only after the PUBLIC DNS of that domain has shown the record
// EmailZit asked that HostZit to publish (INTEGRATION.md, HostZit's
// security review of the relay). The proof belongs to the link: what is
// remembered per link and domain is the token the record must carry, when
// the record was last seen and when it was first looked for.

// RelayDomain is the proof of one domain at one link.
type RelayDomain struct {
	Domain     string
	LinkID     int64
	Token      string
	HZCustomer string    // the customer of the domain at that HostZit
	ProvenAt   time.Time // zero: the record was never seen
	CheckedAt  time.Time
	FirstSeen  time.Time // when the relay first asked about the domain
}

// RelayDomainProof returns what this link has shown about a domain, or
// ErrNotFound.
func (s *Store) RelayDomainProof(ctx context.Context, domain string, linkID int64) (*RelayDomain, error) {
	d := &RelayDomain{}
	var proven *time.Time
	err := s.db.QueryRow(ctx, `SELECT domain, link_id, token, hz_customer, proven_at, checked_at, created_at
		FROM relay_domains WHERE domain=$1 AND link_id=$2`,
		strings.ToLower(strings.TrimSpace(domain)), linkID).
		Scan(&d.Domain, &d.LinkID, &d.Token, &d.HZCustomer, &proven, &d.CheckedAt, &d.FirstSeen)
	if err != nil {
		return nil, notFound(err)
	}
	if proven != nil {
		d.ProvenAt = *proven
	}
	return d, nil
}

// SaveRelayDomainProof writes the state of one domain at one link. The
// token stays as it is once a record carries it, so the caller reads the
// row first and passes its token back; the time it was first asked about
// is kept by the database.
func (s *Store) SaveRelayDomainProof(ctx context.Context, d *RelayDomain) error {
	var proven any
	if !d.ProvenAt.IsZero() {
		proven = d.ProvenAt
	}
	_, err := s.db.Exec(ctx, `INSERT INTO relay_domains(domain, link_id, token, hz_customer, proven_at, checked_at)
		VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (domain, link_id) DO UPDATE SET token=$3, hz_customer=$4, proven_at=$5, checked_at=$6`,
		strings.ToLower(strings.TrimSpace(d.Domain)), d.LinkID, d.Token, d.HZCustomer, proven, d.CheckedAt)
	return err
}

// PruneRelayDomainProofs forgets the domains nothing has asked about since
// before, so a flood of unknown domains cannot fill the table.
func (s *Store) PruneRelayDomainProofs(ctx context.Context, before time.Time) error {
	_, err := s.db.Exec(ctx, `DELETE FROM relay_domains WHERE checked_at < $1`, before)
	return err
}
