package web

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// DNSRecord is a record a mail domain needs. On its own EmailZit shows them
// for the customer to set at the DNS provider; with HostZit they are
// written into HostZit's DNS (later).
type DNSRecord struct {
	Name  string // full name, e.g. example.com or _dmarc.example.com
	Type  string
	Value string
	Note  string // what it is for (English, translated in the template)
	// Required records are needed for mail to work; the others improve
	// deliverability or set-up of mail programs.
	Required bool
}

// mailRecords lists the records of a domain. Without a host name of the
// server nothing pointing to it can be shown yet.
func mailRecords(d *store.Domain, m MailSettings) []DNSRecord {
	var out []DNSRecord
	if !d.Verified {
		out = append(out, DNSRecord{Name: d.VerifyName(), Type: "TXT", Value: d.VerifyValue(), Required: true,
			Note: "Proves that the domain is yours; mail for it is accepted only after this check."})
	}
	h := m.Hostname
	if h == "" {
		return out
	}
	out = append(out,
		DNSRecord{Name: d.Name, Type: "MX", Value: "10 " + h + ".", Required: true, Note: "Mail for the domain is delivered to this server."},
		DNSRecord{Name: d.Name, Type: "TXT", Value: "v=spf1 mx ~all", Required: true, Note: "SPF: only this server sends mail for the domain."},
		DNSRecord{Name: "_dmarc." + d.Name, Type: "TXT", Value: "v=DMARC1; p=none; adkim=s; aspf=s", Note: "DMARC: how receivers treat mail that fails SPF and DKIM (start with p=none, later quarantine or reject)."},
		DNSRecord{Name: "autoconfig." + d.Name, Type: "CNAME", Value: h + ".", Note: "Thunderbird and other programs find the settings by themselves."},
		DNSRecord{Name: "autodiscover." + d.Name, Type: "CNAME", Value: h + ".", Note: "Outlook finds the settings by itself."},
		DNSRecord{Name: "_imaps._tcp." + d.Name, Type: "SRV", Value: "0 1 993 " + h + ".", Note: "IMAP over TLS (RFC 6186)."},
		DNSRecord{Name: "_submissions._tcp." + d.Name, Type: "SRV", Value: "0 1 465 " + h + ".", Note: "Sending over TLS (RFC 8314)."},
		DNSRecord{Name: "_submission._tcp." + d.Name, Type: "SRV", Value: "10 1 587 " + h + ".", Note: "Sending with STARTTLS."},
		DNSRecord{Name: "_pop3s._tcp." + d.Name, Type: "SRV", Value: "10 1 995 " + h + ".", Note: "POP3 over TLS."},
	)
	return out
}

// Resolver looks names up (tests replace it).
var Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
} = net.DefaultResolver

// checkTXT reports whether name has a TXT record with exactly value.
func (s *Server) checkTXT(ctx context.Context, name, value string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	list, err := Resolver.LookupTXT(ctx, name)
	if err != nil {
		return false, err
	}
	for _, t := range list {
		if strings.TrimSpace(t) == value {
			return true, nil
		}
	}
	return false, nil
}
