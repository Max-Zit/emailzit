// Package submit takes mail from websites (INTEGRATION P7): PHP's mail()
// on a HostZit hosting account runs emailzit-sendmail, which hands the
// message to the EmailZit server over /run/emailzit/submit.sock. The server
// knows the hosting account by the user ID of the connecting process
// (SO_PEERCRED), applies the customer's sending limits, lets the website
// send only as addresses of the customer's own verified domains, and passes
// the message to Postfix (DKIM signing, delivery log) through a service
// only the EmailZit server can reach.
package submit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// Request is the first line emailzit-sendmail sends (JSON), followed by the
// message.
type Request struct {
	Sender  string   `json:"sender,omitempty"`  // -f / -r
	Name    string   `json:"name,omitempty"`    // -F
	Extract bool     `json:"extract,omitempty"` // -t: recipients from the headers
	Rcpts   []string `json:"rcpts,omitempty"`   // command line
}

// Reply is the server's answer (one JSON line).
type Reply struct {
	ID    string `json:"id,omitempty"` // Postfix queue ID
	Error string `json:"error,omitempty"`
	Temp  bool   `json:"temp,omitempty"` // try again later (limit, server busy)
}

// Socket is where the EmailZit server takes mail from websites.
const Socket = "/run/emailzit/submit.sock"

// MaxRcpts caps the recipients of one message before the package limit is
// even looked at.
const MaxRcpts = 1000

// permError is a refusal that will not change by trying again.
type permError struct{ msg string }

func (e *permError) Error() string { return e.msg }

func refuse(format string, a ...any) error { return &permError{fmt.Sprintf(format, a...)} }

// IsPermanent tells a refusal from a temporary problem.
func IsPermanent(err error) bool {
	var p *permError
	return errors.As(err, &p)
}

// field is one header field as written (with its folded lines).
type field struct {
	name string // as written
	raw  string // "Name: value\n" including continuation lines
}

// prepared is a message ready for Postfix.
type prepared struct {
	from  string // address in the From header
	rcpts []string
	data  []byte // LF line ends
}

// prepare checks and completes a message: recipients from the command line
// and (with -t) the headers, Bcc removed, From/Date/Message-ID added when
// missing.
func prepare(req Request, raw []byte, hostname string, now time.Time) (*prepared, error) {
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	head, body, ok := bytes.Cut(raw, []byte("\n\n"))
	if !ok {
		head, body = raw, nil
	}
	var fields []field
	for _, line := range strings.SplitAfter(string(head), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, "\n") {
			line += "\n"
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) == 0 {
				return nil, refuse("the message does not start with a header")
			}
			fields[len(fields)-1].raw += line
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return nil, refuse("the message header is not valid (line %q)", trim(line))
		}
		fields = append(fields, field{name: name, raw: line})
	}
	if len(fields) > 500 {
		return nil, refuse("the message has too many header fields")
	}
	value := func(f field) string {
		_, v, _ := strings.Cut(f.raw, ":")
		v = strings.ReplaceAll(v, "\n", "")
		return strings.TrimSpace(v)
	}
	p := &prepared{}
	seen := map[string]bool{}
	add := func(a string) error {
		a = strings.TrimSpace(a)
		if a == "" {
			return nil
		}
		addr, err := mail.ParseAddress(a)
		if err != nil || !validAddr(addr.Address) {
			return refuse("invalid recipient %q", trim(a))
		}
		k := strings.ToLower(addr.Address)
		if !seen[k] {
			seen[k] = true
			p.rcpts = append(p.rcpts, addr.Address)
		}
		return nil
	}
	for _, r := range req.Rcpts {
		for _, a := range strings.Split(r, ",") {
			if err := add(a); err != nil {
				return nil, err
			}
		}
	}
	var hasDate, hasID bool
	var out []field
	for _, f := range fields {
		switch strings.ToLower(f.name) {
		case "to", "cc", "bcc":
			if req.Extract {
				if v := value(f); v != "" {
					list, err := mail.ParseAddressList(v)
					if err != nil {
						return nil, refuse("the %s header is not valid: %v", f.name, err)
					}
					for _, a := range list {
						if err := add(a.Address); err != nil {
							return nil, err
						}
					}
				}
			}
			if strings.EqualFold(f.name, "bcc") {
				continue // never shown to the recipients
			}
		case "from":
			if p.from != "" {
				return nil, refuse("the message has more than one From header")
			}
			list, err := mail.ParseAddressList(value(f))
			if err != nil || len(list) != 1 || !validAddr(list[0].Address) {
				return nil, refuse("the From header must hold exactly one valid address")
			}
			p.from = list[0].Address
		case "date":
			hasDate = true
		case "message-id":
			hasID = true
		}
		out = append(out, f)
	}
	if len(p.rcpts) == 0 {
		return nil, refuse("the message has no recipients")
	}
	if len(p.rcpts) > MaxRcpts {
		return nil, refuse("too many recipients")
	}
	var b bytes.Buffer
	if p.from == "" {
		if req.Sender == "" || !validAddr(req.Sender) {
			return nil, refuse("the message has no From address")
		}
		p.from = req.Sender
		a := mail.Address{Name: req.Name, Address: req.Sender}
		b.WriteString("From: " + a.String() + "\n")
	}
	if !hasDate {
		b.WriteString("Date: " + now.Format(time.RFC1123Z) + "\n")
	}
	if !hasID {
		r := make([]byte, 12)
		_, _ = rand.Read(r)
		b.WriteString("Message-ID: <" + hex.EncodeToString(r) + "@" + hostname + ">\n")
	}
	for _, f := range out {
		b.WriteString(f.raw)
	}
	b.WriteString("\n")
	b.Write(body)
	p.data = b.Bytes()
	return p, nil
}

// validAddr accepts a plain address for the SMTP envelope.
func validAddr(a string) bool {
	local, domain, ok := strings.Cut(a, "@")
	if !ok || local == "" || domain == "" || len(a) > 254 || strings.Contains(domain, "@") {
		return false
	}
	for _, r := range a {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("<>()[]\\,;\"", r) {
			return false
		}
	}
	return true
}

// domainOf is the domain of an address, lower case.
func domainOf(a string) string {
	_, d, _ := strings.Cut(a, "@")
	return strings.ToLower(d)
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}
