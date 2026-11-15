package store

import (
	"context"
	"strings"
	"time"
)

// A website on a linked HostZit may send mail for a domain that has no
// mail here only after the PUBLIC DNS of that domain has shown the record
// EmailZit asked that HostZit to publish (INTEGRATION.md, HostZit's
// security review of the relay). What is remembered per domain: the link
// that vouched for it, the token its record must carry, when the record
// was last seen and when it was first asked about.

// RelayDomain is the proof of one such domain.
type RelayDomain struct {
	Domain     string
	LinkID     int64
	Token      string
	HZCustomer string    // the customer of the domain at that HostZit
	ProvenAt   time.Time // zero: the record was never seen
	CheckedAt  time.Time
	FirstSeen  time.Time // when the relay first asked about the domain
}

// RelayDomainProof returns what is known about a domain, or ErrNotFound.
func (s *Store) RelayDomainProof(ctx context.Context, domain string) (*RelayDomain, error) {
	d := &RelayDomain{}
	var proven *time.Time
	err := s.db.QueryRow(ctx, `SELECT domain, link_id, token, hz_customer, proven_at, checked_at, created_at
		FROM relay_domains WHERE domain=$1`, strings.ToLower(strings.TrimSpace(domain))).
		Scan(&d.Domain, &d.LinkID, &d.Token, &d.HZCustomer, &proven, &d.CheckedAt, &d.FirstSeen)
	if err != nil {
		return nil, notFound(err)
	}
	if proven != nil {
		d.ProvenAt = *proven
	}
	return d, nil
}

// SaveRelayDomainProof writes the state of one domain. The token of a
// domain stays as it is once a record carries it, so the caller reads the
// row first and passes its token back; the time it was first asked about
// is kept by the database.
func (s *Store) SaveRelayDomainProof(ctx context.Context, d *RelayDomain) error {
	var proven any
	if !d.ProvenAt.IsZero() {
		proven = d.ProvenAt
	}
	_, err := s.db.Exec(ctx, `INSERT INTO relay_domains(domain, link_id, token, hz_customer, proven_at, checked_at)
		VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (domain) DO UPDATE SET link_id=$2, token=$3, hz_customer=$4, proven_at=$5, checked_at=$6`,
		strings.ToLower(strings.TrimSpace(d.Domain)), d.LinkID, d.Token, d.HZCustomer, proven, d.CheckedAt)
	return err
}

// PruneRelayDomainProofs forgets the domains nothing has asked about since
// before, so a flood of unknown domains cannot fill the table.
func (s *Store) PruneRelayDomainProofs(ctx context.Context, before time.Time) error {
	_, err := s.db.Exec(ctx, `DELETE FROM relay_domains WHERE checked_at < $1`, before)
	return err
}
