package web

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Steps of the guided set-up of a domain.
const (
	StepVerify  = 1 // prove that the domain is ours
	StepMailbox = 2 // somewhere for the mail to land
	StepHosts   = 3 // autoconfig, autodiscover, mta-sts and the certificate
	StepRecords = 4 // MX, SPF, DKIM and the rest
	StepDone    = 5
	Steps       = 4
)

// hostNames are the names of a domain that must point to this server and be
// in its certificate: mail programs and other mail servers reach them over
// HTTPS.
var hostNames = []string{"autoconfig", "autodiscover", "mta-sts"}

// DomainSetup is what the domain page shows above the records: which step
// the domain is on, and what stands in the way.
type DomainSetup struct {
	Step       int
	Steps      int
	Mailboxes  int
	RequiredOK int // required records found in the DNS
	Required   int
	// CertMissing are host names of the domain the server's certificate
	// does not cover yet; without them Outlook and Thunderbird cannot set
	// themselves up and other servers cannot read the MTA-STS policy.
	CertMissing []string
	// NotHere are host names that do not point to this server (a proxy in
	// front of the DNS, such as Cloudflare's orange cloud, does that).
	NotHere []string
	// ForeignMX is the mail server the domain still points to; its mail
	// should be imported before the MX is moved.
	ForeignMX string
}

// Done reports whether the domain needs nothing more.
func (x *DomainSetup) Done() bool { return x != nil && x.Step >= StepDone }

// certNames reads the names of the certificate the panel serves on 443
// (public.crt, the mail certificate the root helper copies).
func certNames(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, "tls", "public.crt")) // #nosec G304 -- our own data directory
	if err != nil {
		return nil
	}
	var out []string
	for len(b) > 0 {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		out = append(out, c.DNSNames...)
		if c.Subject.CommonName != "" {
			out = append(out, c.Subject.CommonName)
		}
		break // the first certificate is the server's own
	}
	return out
}

// covers reports whether one of the certificate's names is name (a
// wildcard covers one label).
func covers(names []string, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if n == name {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if _, after, found := strings.Cut(name, "."); found && after == rest {
				return true
			}
		}
	}
	return false
}

// domainSetup works out where a domain stands. It only asks the DNS when
// the earlier steps are done, so the page stays quick.
func (s *Server) domainSetup(ctx context.Context, d *domainData, domain string) *DomainSetup {
	x := &DomainSetup{Steps: Steps, Mailboxes: len(d.Mailboxes)}
	for _, r := range d.Records {
		if r.Required {
			x.Required++
			if d.Checked[indexOf(d.Records, r)] == CheckOK {
				x.RequiredOK++
			}
		}
	}
	switch {
	case d.D != nil && !d.D.Verified:
		x.Step = StepVerify
		return x
	case len(d.Mailboxes) == 0 && len(d.Aliases) == 0:
		x.Step = StepMailbox
		return x
	}
	if d.Mail.Hostname == "" {
		x.Step = StepHosts
		return x
	}
	names := certNames(s.DataDir)
	for _, h := range hostNames {
		if !covers(names, h+"."+domain) {
			x.CertMissing = append(x.CertMissing, h+"."+domain)
		}
	}
	// the two warnings need the DNS, so they are only looked up where they
	// help: after "Check DNS", and while the certificate is not ready
	if d.Checked != nil || len(x.CertMissing) > 0 {
		x.NotHere, x.ForeignMX = s.dnsWarnings(ctx, domain, d.Mail.Hostname)
	}
	switch {
	case len(x.CertMissing) > 0 || len(x.NotHere) > 0:
		x.Step = StepHosts
	case x.Required > 0 && x.RequiredOK < x.Required:
		x.Step = StepRecords
	default:
		x.Step = StepDone
	}
	return x
}

func indexOf(list []DNSRecord, r DNSRecord) int {
	for i, x := range list {
		if x.Name == r.Name && x.Type == r.Type && x.Value == r.Value {
			return i
		}
	}
	return -1
}

// dnsWarnings looks for the two mistakes that cost the most time: a host
// name of the domain that does not point to this server, and an MX that
// still points at the old provider.
func (s *Server) dnsWarnings(ctx context.Context, domain, hostname string) (notHere []string, foreignMX string) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res := checkResolver(ctx, domain)
	mine := map[string]bool{}
	for _, ip := range lookupIPs(ctx, res, hostname) {
		mine[ip] = true
	}
	if len(mine) > 0 {
		for _, h := range hostNames {
			name := h + "." + domain
			ips := lookupIPs(ctx, res, name)
			if len(ips) == 0 {
				continue // not set yet: that is the step itself, not a warning
			}
			here := false
			for _, ip := range ips {
				if mine[ip] {
					here = true
				}
			}
			if !here {
				notHere = append(notHere, name)
			}
		}
	}
	if mx, err := res.LookupMX(ctx, domain); err == nil {
		for _, m := range mx {
			host := strings.ToLower(strings.TrimSuffix(m.Host, "."))
			if host != strings.ToLower(hostname) && foreignMX == "" {
				foreignMX = host
			}
		}
	}
	return notHere, foreignMX
}

func lookupIPs(ctx context.Context, res *net.Resolver, name string) []string {
	ips, err := res.LookupIP(ctx, "ip", name)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
