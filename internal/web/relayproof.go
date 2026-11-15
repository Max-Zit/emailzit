package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/auth"
	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/store"
)

// What the relay of a linked HostZit may send with (INTEGRATION.md E3, E8
// and HostZit's security review of the relay, 2026-11-14):
//
//   - The login of a link works only from the addresses of that link. The
//     relay port is open for the addresses of all links together, so
//     without this check the login of one HostZit would work from another.
//   - A domain that has no mail here is accepted only once the PUBLIC DNS
//     of that domain shows the record EmailZit asked that HostZit to
//     publish. HostZit, like every hosting panel, lets an account create a
//     zone for any name; such a zone does not work in the public DNS, so
//     only the HostZit that really holds the delegated zone can show the
//     record. Without the check a website could send with another
//     customer's domain in From, and SPF and DMARC would pass, because
//     that domain's SPF names this relay.
//
// A mail domain of this server needs no record of its own: it is verified
// in the public DNS already, and the relay then asks whether the HostZit
// of the link holds that very domain for that very customer.

const (
	// relayProofLife is how long a proof counts before it is looked up again.
	relayProofLife = 7 * 24 * time.Hour
	// relayProofRetry is how often one unproven domain is looked up.
	relayProofRetry = 5 * time.Minute
	// relayProofGrace is how long the sender is asked to try again while
	// the record is not visible yet; after that the mail is refused.
	relayProofGrace = 15 * time.Minute
	// relayProofForget is when a domain nothing asked about is dropped.
	relayProofForget = 30 * 24 * time.Hour
	// relayProofPrefix is what the value of the record starts with.
	relayProofPrefix = "emailzit-relay="
)

// relayProofRecord is the name of the record in the zone of the domain.
func relayProofRecord(domain string) string { return "_emailzit." + domain }

// relayProven reports whether the public DNS of a domain shows that the
// HostZit of this link holds its zone. temp: nothing is decided yet, so
// the sender is asked to try again later.
func (s *Server) relayProven(ctx context.Context, l *store.HostZitLink, domain, hzCustomer string) (ok, temp bool) {
	now := s.now()
	// The proof belongs to this link and carries a value of its own, so a
	// second HostZit can neither pass with the record of the first nor
	// take its proof away.
	p, err := s.store.RelayDomainProof(ctx, domain, l.ID)
	if err != nil {
		p = &store.RelayDomain{Domain: domain, LinkID: l.ID, Token: auth.RandomToken(16), FirstSeen: now}
	}
	switch {
	case !p.ProvenAt.IsZero() && now.Sub(p.ProvenAt) < relayProofLife:
		return true, false
	case now.Sub(p.CheckedAt) < relayProofRetry:
		// looked up a moment ago; there is nothing new to learn yet
		return false, now.Sub(p.FirstSeen) < relayProofGrace
	}
	if p.FirstSeen.IsZero() {
		p.FirstSeen = now
	}
	p.HZCustomer, p.CheckedAt = hzCustomer, now
	value := relayProofPrefix + p.Token
	body := map[string]any{"records": []hzRecord{{Name: "_emailzit", Type: "TXT", TTL: 300, Content: value}}}
	if hzCustomer != "" {
		body["customer_id"] = hzCustomer
	}
	path := "/api/v1/dns/zones/" + url.PathEscape(domain) + "/owned/emailzit"
	st, resp, err := s.hostzitCall(ctx, l, http.MethodPut, path, body)
	switch {
	case err != nil || st == 0:
		s.log.Warn("the proof of a relay domain cannot be published", "hostzit", l.URL, "domain", domain, "err", err)
		s.saveProof(ctx, p)
		return false, true
	case st == http.StatusNotFound:
		s.saveProof(ctx, p) // that HostZit does not hold the zone
		return false, false
	case st >= 300:
		s.log.Warn("HostZit refused the proof of a relay domain", "hostzit", l.URL, "domain", domain,
			"status", st, "message", apiMessage(resp))
		s.saveProof(ctx, p)
		return false, now.Sub(p.FirstSeen) < relayProofGrace
	}
	txt, lookupErr := s.lookupTXT(ctx, domain, relayProofRecord(domain))
	for _, t := range txt {
		if strings.TrimSpace(t) != value {
			continue
		}
		p.ProvenAt = now
		s.saveProof(ctx, p)
		s.log.Info("the domain of a website is proven in the public DNS", "domain", domain, "hostzit", l.URL)
		return true, false
	}
	s.saveProof(ctx, p)
	switch {
	case lookupErr != nil && !notFound(lookupErr):
		return false, true // the DNS said nothing at all: ask again later
	case now.Sub(p.FirstSeen) < relayProofGrace:
		return false, true // the record may still be on its way
	}
	s.log.Warn("the domain of a website is not in the public DNS of that HostZit: its mail is refused",
		"domain", domain, "hostzit", l.URL, "record", relayProofRecord(domain))
	return false, false
}

func (s *Server) saveProof(ctx context.Context, p *store.RelayDomain) {
	if err := s.store.SaveRelayDomainProof(ctx, p); err != nil {
		s.log.Error("the proof of a relay domain cannot be written", "domain", p.Domain, "err", err)
	}
}

// RelayAssigned reports whether an administrator here assigned this
// customer to the link (scope "only these customers"). Such a link carries
// that customer's mail without asking HostZit: the assignment is the
// administrator's own word.
func (s *Server) RelayAssigned(ctx context.Context, linkID int64, customerID string) bool {
	l, err := s.store.HostZitLinkByID(ctx, linkID)
	if err != nil || l.ScopeAll {
		return false
	}
	return s.store.LinkServes(ctx, l, customerID)
}

// RelayLoginAllows reports whether the relay login of a link may be used
// from this address: the addresses the pairing wrote into the link (E8).
// A link added by hand may have none; then the allow-list of the port is
// all there is.
func (s *Server) RelayLoginAllows(ctx context.Context, linkID int64, ip string) bool {
	l, err := s.store.HostZitLinkByID(ctx, linkID)
	if err != nil {
		return false
	}
	if len(l.Addresses) == 0 {
		return true
	}
	a, ok := netacl.AddrOf(ip)
	if !ok {
		return false
	}
	if a.IsLoopback() {
		return true // a test on the server itself
	}
	nets, err := netacl.Parse(l.Addresses)
	if err != nil {
		return false
	}
	return netacl.Contains(nets, a)
}
