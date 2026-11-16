package web

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// EmailZit keeps its mail domains in step with what the PUBLIC DNS really
// says. Three things follow the DNS and not a promise of another server:
//
//   - A domain counts as verified only while its _emailzit record is in
//     the public DNS. A zone inside HostZit proves nothing: every hosting
//     account may create a zone for someone else's name, and EmailZit
//     would then take the mail of a stranger's domain (HostZit's security
//     review of 2026-11-14).
//   - A domain is signed only while its DKIM record is in the DNS. A key
//     that was never published makes every signature fail at the receiver,
//     and a failing signature next to a passing one is noise at best.
//   - The records of a domain that no HostZit holds are offered again from
//     time to time: the zone may have been created later, or a write may
//     have been refused while something else was in the way.
//
// The check runs at every start and then every hour; a resolver that
// cannot answer changes nothing.

const (
	// dnsCheckEvery is how often the records are looked up.
	dnsCheckEvery = time.Hour
	// dnsPublishEvery is after how many rounds the records of the domains
	// HostZit does not hold are offered again.
	dnsPublishEvery = 6
)

// RunDNSCheck keeps the verification, the signing and HostZit's DNS in
// step with the public DNS until ctx ends.
func (s *Server) RunDNSCheck(ctx context.Context) {
	t := time.NewTicker(dnsCheckEvery)
	defer t.Stop()
	for round := 0; ; round++ {
		s.CheckDNS(ctx)
		if round > 0 && round%dnsPublishEvery == 0 {
			s.publishUnmanagedDNS(ctx)
		}
		if err := s.store.PruneRelayDomainProofs(ctx, s.now().Add(-relayProofForget)); err != nil {
			s.log.Error("the proofs of the relay domains cannot be cleaned up", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// CheckDNS follows the public DNS for every mail domain: a domain whose
// record is there is verified, and the signing is switched on or off.
func (s *Server) CheckDNS(ctx context.Context) {
	doms, err := s.store.Domains(ctx, store.Staff, "")
	if err != nil {
		s.log.Error("DNS check: the domains cannot be read", "err", err)
		return
	}
	for _, d := range doms {
		if ctx.Err() != nil {
			return
		}
		s.verifyInDNS(ctx, d)
		s.checkDKIM(ctx, d)
	}
}

// verifyInDNS verifies a domain when its _emailzit record is in the public
// DNS. A domain that is verified stays verified: the record is no longer
// asked for once mail flows.
func (s *Server) verifyInDNS(ctx context.Context, d *store.Domain) {
	if d.Verified {
		return
	}
	txt, err := s.lookupTXT(ctx, d.Name, d.VerifyName())
	if err != nil {
		return
	}
	for _, t := range txt {
		if strings.TrimSpace(t) != d.VerifyValue() {
			continue
		}
		if err := s.store.SetDomainVerified(ctx, store.Staff, d.ID, true); err != nil {
			s.log.Error("DNS check: the domain cannot be verified", "domain", d.Name, "err", err)
			return
		}
		d.Verified = true
		s.log.Info("the domain is verified: its record is in the public DNS", "domain", d.Name, "record", d.VerifyName())
		_ = s.store.Audit(ctx, "-", "local", "domain.verify", "domain:"+d.Name, "verified: the record "+d.VerifyName()+" is in the public DNS")
		return
	}
}

// checkDKIM switches the signing of one domain on or off, following its
// DKIM record in the DNS.
func (s *Server) checkDKIM(ctx context.Context, d *store.Domain) {
	k, err := s.store.DKIM(ctx, d.ID)
	if err != nil || k.Selector == "" || k.Public == "" {
		return
	}
	found, decided := s.dkimInDNS(ctx, k)
	if !decided || found == d.DKIMPublished {
		return
	}
	if err := s.store.SetDKIMPublished(ctx, d.ID, found); err != nil {
		s.log.Error("DKIM check", "domain", d.Name, "err", err)
		return
	}
	if found {
		s.log.Info("the DKIM record is in the DNS: the domain is signed again", "domain", d.Name, "selector", k.Selector)
		s.installDKIM(ctx, d.ID)
		return
	}
	s.log.Warn("the DKIM record is not in the DNS: the domain is not signed until it is", "domain", d.Name, "record", k.RecordName())
	s.stopSigning(ctx, d.Name)
}

// stopSigning tells the mail helper to stop signing a domain.
func (s *Server) stopSigning(ctx context.Context, domain string) {
	if s.Mail == nil {
		return
	}
	if err := s.Mail.DKIMOff(ctx, domain); err != nil {
		s.log.Error("switching the signing off", "domain", domain, "err", err)
	}
}

// publishUnmanagedDNS offers the records of the domains no HostZit holds
// once more. A zone may have been created after the domain, and a write
// that was refused once (a conflict with records of the customer) can work
// the next time.
func (s *Server) publishUnmanagedDNS(ctx context.Context) {
	if !s.linked(ctx) {
		return
	}
	doms, err := s.store.Domains(ctx, store.Staff, "")
	if err != nil {
		return
	}
	for _, d := range doms {
		if ctx.Err() != nil {
			return
		}
		if !d.DNSManaged {
			s.publishDNS(ctx, d.ID, false, d)
		}
	}
}

const (
	// txtLookupLife is the whole time one TXT question may take.
	txtLookupLife = 20 * time.Second
	// txtZoneLife is what the name servers of the zone get of it, so a
	// name server that stalls leaves time for the system resolver.
	txtZoneLife = 8 * time.Second
)

// lookupTXT reads a TXT record of a domain from the public DNS (tests
// replace it through the server).
func (s *Server) lookupTXT(ctx context.Context, domain, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, txtLookupLife)
	defer cancel()
	if s.PublicTXT != nil {
		return s.PublicTXT(ctx, domain, name)
	}
	return publicTXT(ctx, domain, name)
}

// publicTXT asks the name servers of the zone the name belongs to, so a
// record that was just published is seen at once, and falls back to the
// system resolver only when they cannot be asked at all: a name server of
// a domain may answer the test question and still refuse the record, and
// the check would then never decide anything (found on e1).
//
// The question carries the ABSOLUTE name. Without the final dot the
// resolver asks the name with the search domain of this server appended as
// well (_emailzit.dnstest.maxzit.com.maxzit.com), an authoritative server
// refuses that, and the refusal is not a "no such name" — so the check
// used to fall through to the system resolver, whose negative answer is
// remembered for up to an hour. In the joint test J3 the record was in the
// public DNS for five minutes while the relay still answered 451, and the
// message was nearly refused (HostZit's finding, 2026-11-16). A name
// server that says "no such name" is believed now, cache and all.
func publicTXT(ctx context.Context, domain, name string) ([]string, error) {
	abs := absoluteName(name)
	zoneCtx, cancel := context.WithTimeout(ctx, txtZoneLife)
	defer cancel()
	txt, err := checkResolver(zoneCtx, domain).LookupTXT(zoneCtx, abs)
	if zoneAnswered(err) {
		return txt, err
	}
	return net.DefaultResolver.LookupTXT(ctx, abs)
}

// zoneAnswered reports whether the name servers of the zone gave an answer
// to believe: records, or "there is no such name". Anything else (no
// reply, a refusal, a server that misbehaves) is no answer, and the
// question goes to the system resolver — whose negative answers are
// remembered, so it must not be asked while the zone itself has spoken.
func zoneAnswered(err error) bool { return err == nil || notFound(err) }

// absoluteName is the name as a question for the DNS: with the final dot,
// so no search domain is ever added to it.
func absoluteName(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(name), ".") + "."
}

// notFound reports a DNS answer that says the name does not exist.
func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// dkimInDNS looks the key up at the name servers of the domain. decided
// is false when the DNS said nothing at all (then nothing is changed).
func (s *Server) dkimInDNS(ctx context.Context, k *store.DKIMKey) (found, decided bool) {
	txt, err := s.lookupTXT(ctx, k.Domain, k.RecordName())
	if err != nil {
		if notFound(err) {
			return false, true // there is no such record
		}
		return false, false
	}
	for _, t := range txt {
		if strings.Contains(strings.ReplaceAll(t, " ", ""), "p="+k.Public) {
			return true, true
		}
	}
	return false, true
}
