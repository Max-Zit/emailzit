package web

import (
	"context"
	"net"
	"strconv"
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
func mailRecords(d *store.Domain, m MailSettings, k *store.DKIMKey) []DNSRecord {
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
		// DKIM after SPF (filled below when the domain has a key)
		DNSRecord{Name: "_dmarc." + d.Name, Type: "TXT", Value: "v=DMARC1; p=none; adkim=s; aspf=s", Note: "DMARC: how receivers treat mail that fails SPF and DKIM (start with p=none, later quarantine or reject)."},
		DNSRecord{Name: "autoconfig." + d.Name, Type: "CNAME", Value: h + ".", Note: "Thunderbird and other programs find the settings by themselves."},
		DNSRecord{Name: "autodiscover." + d.Name, Type: "CNAME", Value: h + ".", Note: "Outlook finds the settings by itself."},
		DNSRecord{Name: "_imaps._tcp." + d.Name, Type: "SRV", Value: "0 1 993 " + h + ".", Note: "IMAP over TLS (RFC 6186)."},
		DNSRecord{Name: "_submissions._tcp." + d.Name, Type: "SRV", Value: "0 1 465 " + h + ".", Note: "Sending over TLS (RFC 8314)."},
		DNSRecord{Name: "_submission._tcp." + d.Name, Type: "SRV", Value: "10 1 587 " + h + ".", Note: "Sending with STARTTLS."},
		DNSRecord{Name: "_pop3s._tcp." + d.Name, Type: "SRV", Value: "10 1 995 " + h + ".", Note: "POP3 over TLS."},
	)
	return withDKIM(out, k)
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

func init() {
	// the DKIM record goes right after SPF
	dkimRecord = func(k *store.DKIMKey) DNSRecord {
		return DNSRecord{Name: k.RecordName(), Type: "TXT", Value: k.Record(), Required: true,
			Note: "DKIM: receivers check the signature of your mail with this key."}
	}
}

var dkimRecord func(k *store.DKIMKey) DNSRecord

// withDKIM inserts the DKIM record after SPF.
func withDKIM(list []DNSRecord, k *store.DKIMKey) []DNSRecord {
	if k == nil || k.Selector == "" {
		return list
	}
	for i, r := range list {
		if r.Type == "TXT" && strings.HasPrefix(r.Value, "v=spf1") {
			out := append([]DNSRecord{}, list[:i+1]...)
			out = append(out, dkimRecord(k))
			return append(out, list[i+1:]...)
		}
	}
	return list
}

// Record checks after "Check DNS".
const (
	CheckOK        = "ok"
	CheckMissing   = "missing"
	CheckDifferent = "different"
)

// checkRecords looks the records up in the public DNS.
func (s *Server) checkRecords(ctx context.Context, list []DNSRecord) map[int]string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res := net.DefaultResolver
	out := map[int]string{}
	norm := func(v string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".") }
	for i, rec := range list {
		st := CheckMissing
		switch rec.Type {
		case "MX":
			want := norm(strings.Fields(rec.Value)[1])
			if mx, err := res.LookupMX(ctx, rec.Name); err == nil && len(mx) > 0 {
				st = CheckDifferent
				for _, m := range mx {
					if norm(m.Host) == want {
						st = CheckOK
					}
				}
			}
		case "TXT":
			if txt, err := res.LookupTXT(ctx, rec.Name); err == nil && len(txt) > 0 {
				st = CheckDifferent
				prefix := strings.SplitN(rec.Value, ";", 2)[0]
				prefix = strings.Fields(prefix)[0]
				for _, t := range txt {
					switch {
					case strings.ReplaceAll(t, " ", "") == strings.ReplaceAll(rec.Value, " ", ""):
						st = CheckOK
					case strings.HasPrefix(rec.Value, "v=spf1") && strings.HasPrefix(t, "v=spf1") && (strings.Contains(t, " mx") || strings.Contains(t, "a:")):
						st = CheckOK // an own SPF record that includes this server
					case strings.HasPrefix(rec.Value, "v=DMARC1") && strings.HasPrefix(t, prefix):
						st = CheckOK // any DMARC policy
					}
				}
			}
		case "CNAME":
			if c, err := res.LookupCNAME(ctx, rec.Name); err == nil {
				st = CheckDifferent
				if norm(c) == norm(rec.Value) {
					st = CheckOK
				}
			}
		case "SRV":
			f := strings.Fields(rec.Value)
			labels := strings.SplitN(rec.Name, ".", 3)
			if len(f) == 4 && len(labels) == 3 {
				if _, srv, err := res.LookupSRV(ctx, strings.TrimPrefix(labels[0], "_"), strings.TrimPrefix(labels[1], "_"), labels[2]); err == nil && len(srv) > 0 {
					st = CheckDifferent
					for _, x := range srv {
						if norm(x.Target) == norm(f[3]) && strconv.Itoa(int(x.Port)) == f[2] {
							st = CheckOK
						}
					}
				}
			}
		}
		out[i] = st
	}
	return out
}
