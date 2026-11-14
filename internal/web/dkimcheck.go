package web

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// EmailZit signs a domain only while its DKIM record really is in the
// DNS. A key that was never published makes every signature fail at the
// receiver (HostZit found this on a test domain of ours, where the DNS
// API refused to publish the key), and a failing signature next to a
// passing one is noise at best. The check runs at every start and then
// every hour; a resolver that cannot answer changes nothing.

// dkimCheckEvery is how often the DKIM records are looked up.
const dkimCheckEvery = time.Hour

// RunDKIMCheck keeps the signing in step with the DNS until ctx ends.
func (s *Server) RunDKIMCheck(ctx context.Context) {
	t := time.NewTicker(dkimCheckEvery)
	defer t.Stop()
	s.CheckDKIMPublished(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.CheckDKIMPublished(ctx)
		}
	}
}

// CheckDKIMPublished looks up the DKIM record of every domain that has a
// key and switches the signing on or off.
func (s *Server) CheckDKIMPublished(ctx context.Context) {
	doms, err := s.store.Domains(ctx, store.Staff, "")
	if err != nil {
		s.log.Error("DKIM check: the domains cannot be read", "err", err)
		return
	}
	for _, d := range doms {
		if ctx.Err() != nil {
			return
		}
		k, err := s.store.DKIM(ctx, d.ID)
		if err != nil || k.Selector == "" || k.Public == "" {
			continue
		}
		found, decided := s.dkimInDNS(ctx, k)
		if !decided || found == d.DKIMPublished {
			continue
		}
		if err := s.store.SetDKIMPublished(ctx, d.ID, found); err != nil {
			s.log.Error("DKIM check", "domain", d.Name, "err", err)
			continue
		}
		if found {
			s.log.Info("the DKIM record is in the DNS: the domain is signed again", "domain", d.Name, "selector", k.Selector)
			s.installDKIM(ctx, d.ID)
			continue
		}
		s.log.Warn("the DKIM record is not in the DNS: the domain is not signed until it is", "domain", d.Name, "record", k.RecordName())
		s.stopSigning(ctx, d.Name)
	}
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

// dkimTXT asks the name servers of the domain itself, so a record that
// was just published is seen at once, and falls back to the system
// resolver when one of them answers nothing useful (tests replace it).
// A name server of a domain may answer the test question and still refuse
// the record, and the check would then never decide anything.
func dkimTXT(ctx context.Context, domain, name string) ([]string, error) {
	txt, err := checkResolver(ctx, domain).LookupTXT(ctx, name)
	if err == nil || notFound(err) {
		return txt, err
	}
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// notFound reports a DNS answer that says the name does not exist.
func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// dkimInDNS looks the key up at the name servers of the domain. decided
// is false when the DNS said nothing at all (then nothing is changed).
func (s *Server) dkimInDNS(ctx context.Context, k *store.DKIMKey) (found, decided bool) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	lookup := s.DKIMTXT
	if lookup == nil {
		lookup = dkimTXT
	}
	txt, err := lookup(ctx, k.Domain, k.RecordName())
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
