package mtasts

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// TLSAType is the DNS type of TLSA records (RFC 6698).
const TLSAType dnsmessage.Type = 52

// TLSAChecker asks a validating resolver (the local Unbound) whether a
// host has TLSA records for port 25 whose answer is DNSSEC-validated (AD
// bit set).
func TLSAChecker(resolver string) func(ctx context.Context, host string) bool {
	return func(ctx context.Context, host string) bool {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if !validDomain(host) {
			return false
		}
		name, err := dnsmessage.NewName("_25._tcp." + host + ".")
		if err != nil {
			return false
		}
		var idb [2]byte
		_, _ = rand.Read(idb[:])
		id := binary.BigEndian.Uint16(idb[:])
		b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{ID: id, RecursionDesired: true, AuthenticData: true})
		b.EnableCompression()
		if b.StartQuestions() != nil || b.Question(dnsmessage.Question{Name: name, Type: TLSAType, Class: dnsmessage.ClassINET}) != nil || b.StartAdditionals() != nil {
			return false
		}
		var opt dnsmessage.ResourceHeader
		if opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, true) != nil || b.OPTResource(opt, dnsmessage.OPTResource{}) != nil {
			return false
		}
		q, err := b.Finish()
		if err != nil {
			return false
		}
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", resolver)
		if err != nil {
			return false
		}
		defer c.Close()
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		msg := make([]byte, 2+len(q))
		binary.BigEndian.PutUint16(msg, uint16(len(q))) // #nosec G115 -- a query of a few hundred bytes
		copy(msg[2:], q)
		if _, err := c.Write(msg); err != nil {
			return false
		}
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return false
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			return false
		}
		var p dnsmessage.Parser
		h, err := p.Start(resp)
		if err != nil || h.ID != id || !h.Response || h.RCode != dnsmessage.RCodeSuccess || !h.AuthenticData {
			return false
		}
		if err := p.SkipAllQuestions(); err != nil {
			return false
		}
		for {
			ah, err := p.AnswerHeader()
			if err != nil {
				return false
			}
			if ah.Type == TLSAType {
				return true
			}
			if err := p.SkipAnswer(); err != nil {
				return false
			}
		}
	}
}
