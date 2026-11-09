// Package mtasts is EmailZit's MTA-STS lookup for outgoing mail (RFC
// 8461): Postfix asks it through a socketmap for every domain it sends to
// (smtp_tls_policy_maps). A domain that publishes a policy in "enforce"
// mode gets mail only over TLS, to its listed servers, with a valid
// certificate. Policies are cached for their max_age and refreshed when
// the id of the TXT record changes; when the policy server cannot be
// reached, a cached policy keeps applying.
//
// Where DANE works (the local resolver validates DNSSEC) and the domain's
// servers publish TLSA records, the lookup answers nothing, so Postfix
// uses DANE, which RFC 8461 prefers.
package mtasts

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Policy is a domain's MTA-STS policy.
type Policy struct {
	ID      string
	Mode    string // enforce, testing, none
	MX      []string
	MaxAge  time.Duration
	Fetched time.Time
}

// Service answers Postfix's socketmap requests.
type Service struct {
	Log *slog.Logger
	// AllowUID may connect (postfix); -1 = anybody (tests).
	AllowUID int
	PeerUID  func(c net.Conn) (int, error)
	// LookupTXT and Fetch are replaced in tests.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	Fetch     func(ctx context.Context, domain string) ([]byte, error)
	// HasTLSA tells whether a host has DNSSEC-validated TLSA records (nil:
	// DANE is not available here).
	HasTLSA func(ctx context.Context, host string) bool
	// LookupMX lists a domain's MX hosts (for the DANE check).
	LookupMX func(ctx context.Context, domain string) ([]string, error)
	Now      func() time.Time

	mu    sync.Mutex
	cache map[string]*entry
}

type entry struct {
	pol     *Policy   // nil: the domain has no policy
	checked time.Time // TXT record last looked at
	mu      sync.Mutex
}

// Serve accepts connections until the listener closes.
func (s *Service) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.conn(ctx, c)
	}
}

func (s *Service) conn(ctx context.Context, c net.Conn) {
	defer c.Close()
	if s.AllowUID >= 0 {
		uid, err := s.PeerUID(c)
		if err != nil || (uid != s.AllowUID && uid != 0) {
			return
		}
	}
	r := bufio.NewReader(c)
	for {
		_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
		req, err := readNetstring(r)
		if err != nil {
			return
		}
		name, key, ok := strings.Cut(req, " ")
		reply := "PERM invalid request"
		if ok && name == "mtasts" {
			lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			reply = s.Answer(lctx, key)
			cancel()
		}
		if _, err := fmt.Fprintf(c, "%d:%s,", len(reply), reply); err != nil {
			return
		}
	}
}

// readNetstring reads "<len>:<data>," (at most 10000 bytes).
func readNetstring(r *bufio.Reader) (string, error) {
	n, err := r.ReadString(':')
	if err != nil {
		return "", err
	}
	l, err := strconv.Atoi(strings.TrimSuffix(n, ":"))
	if err != nil || l < 0 || l > 10000 {
		return "", errors.New("invalid netstring")
	}
	b := make([]byte, l+1)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	if b[l] != ',' {
		return "", errors.New("invalid netstring")
	}
	return string(b[:l]), nil
}

// Answer is the socketmap reply for a domain.
func (s *Service) Answer(ctx context.Context, domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDomain(domain) {
		return "NOTFOUND "
	}
	p := s.Policy(ctx, domain)
	if p == nil || p.Mode != "enforce" || len(p.MX) == 0 {
		return "NOTFOUND "
	}
	if s.HasTLSA != nil && s.daneUsable(ctx, domain) {
		return "NOTFOUND "
	}
	match := make([]string, len(p.MX))
	for i, m := range p.MX {
		// Postfix: ".example.net" matches the subdomains
		match[i] = strings.TrimPrefix(m, "*")
	}
	return "OK secure match=" + strings.Join(match, ":")
}

// daneUsable: every MX host of the domain has validated TLSA records.
func (s *Service) daneUsable(ctx context.Context, domain string) bool {
	if s.LookupMX == nil {
		return false
	}
	hosts, err := s.LookupMX(ctx, domain)
	if err != nil || len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if !s.HasTLSA(ctx, h) {
			return false
		}
	}
	return true
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// txtCheck is how often the TXT record is looked at again (a changed id
// means a new policy).
const txtCheck = time.Hour

// Policy returns the domain's current policy (nil: none).
func (s *Service) Policy(ctx context.Context, domain string) *Policy {
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]*entry{}
	}
	e := s.cache[domain]
	if e == nil {
		if len(s.cache) > 50000 {
			s.cache = map[string]*entry{}
		}
		e = &entry{}
		s.cache[domain] = e
	}
	s.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	now := s.now()
	if e.pol != nil && now.Sub(e.pol.Fetched) > e.pol.MaxAge {
		e.pol = nil
	}
	if !e.checked.IsZero() && now.Sub(e.checked) < txtCheck {
		return e.pol
	}
	id, ok, err := s.recordID(ctx, domain)
	if err != nil {
		// DNS trouble: keep what we have, ask again soon
		e.checked = now.Add(-txtCheck + 5*time.Minute)
		return e.pol
	}
	e.checked = now
	if !ok {
		// no record: a cached policy stays until it expires (RFC 8461 5.1)
		return e.pol
	}
	if e.pol != nil && e.pol.ID == id {
		return e.pol
	}
	body, err := s.fetch(ctx, domain)
	if err != nil {
		if s.Log != nil {
			s.Log.Info("MTA-STS policy not fetched", "domain", domain, "err", err)
		}
		return e.pol
	}
	p, err := Parse(body)
	if err != nil {
		if s.Log != nil {
			s.Log.Info("MTA-STS policy invalid", "domain", domain, "err", err)
		}
		return e.pol
	}
	p.ID, p.Fetched = id, now
	e.pol = p
	return p
}

// recordID reads the id of "_mta-sts.<domain>" (ok false: no record).
func (s *Service) recordID(ctx context.Context, domain string) (string, bool, error) {
	look := s.LookupTXT
	if look == nil {
		look = net.DefaultResolver.LookupTXT
	}
	txts, err := look(ctx, "_mta-sts."+domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", false, nil
		}
		return "", false, err
	}
	var ids []string
	for _, t := range txts {
		if !strings.HasPrefix(t, "v=STSv1") {
			continue
		}
		for _, f := range strings.Split(t, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(f), "=")
			if k == "id" && v != "" {
				ids = append(ids, v)
			}
		}
	}
	if len(ids) != 1 {
		return "", false, nil // none or ambiguous: no policy
	}
	return ids[0], true, nil
}

func (s *Service) fetch(ctx context.Context, domain string) ([]byte, error) {
	if s.Fetch != nil {
		return s.Fetch(ctx, domain)
	}
	return FetchHTTPS(ctx, domain)
}

var client = &http.Client{
	Timeout: 15 * time.Second,
	// RFC 8461 3.3: no redirects
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: nil, MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second},
}

// FetchHTTPS downloads https://mta-sts.<domain>/.well-known/mta-sts.txt
// (certificate checked, at most 64 KB).
func FetchHTTPS(ctx context.Context, domain string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://mta-sts."+domain+"/.well-known/mta-sts.txt", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "text/plain") {
		return nil, errors.New("not text/plain")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 64<<10 {
		return nil, errors.New("policy too large")
	}
	return b, nil
}

// maxAge is the longest a policy is kept (one year, RFC 8461 3.2).
const maxAge = 31557600 * time.Second

// Parse reads a policy file.
func Parse(b []byte) (*Policy, error) {
	p := &Policy{}
	var version bool
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(l, "\r"), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "version":
			version = v == "STSv1"
		case "mode":
			p.Mode = v
		case "max_age":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 || len(v) > 10 {
				return nil, errors.New("invalid max_age")
			}
			p.MaxAge = time.Duration(n) * time.Second
		case "mx":
			m := strings.ToLower(strings.TrimSuffix(v, "."))
			host := strings.TrimPrefix(m, "*.")
			if !validDomain(host) || strings.Contains(host, "*") || len(p.MX) >= 100 {
				return nil, errors.New("invalid mx")
			}
			p.MX = append(p.MX, m)
		}
	}
	switch {
	case !version:
		return nil, errors.New("not an STSv1 policy")
	case p.Mode != "enforce" && p.Mode != "testing" && p.Mode != "none":
		return nil, errors.New("invalid mode")
	case p.Mode != "none" && len(p.MX) == 0:
		return nil, errors.New("no mx")
	}
	if p.MaxAge > maxAge {
		p.MaxAge = maxAge
	}
	return p, nil
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
