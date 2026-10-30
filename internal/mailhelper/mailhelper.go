// Package mailhelper is the root side of the mail system: a small service
// that does the few mail tasks needing root (configuration files of
// Postfix and Dovecot, the customers' mail directories, moving deleted mail
// away, reading mailbox usage). The panel (user emailzit) talks to it over
// a Unix socket that only root and the emailzit user may use; the service
// checks the caller's user ID on every connection, accepts only a fixed list
// of typed requests and validates every value again.
package mailhelper

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Socket is where the helper listens.
const Socket = "/run/emailzit/mail-helper.sock"

// Actions.
const (
	ActionApply    = "apply"    // write the server-wide configuration and reload
	ActionCustomer = "customer" // create the mail directory of a customer
	ActionTrash    = "trash"    // move the mail of a deleted domain or mailbox away
	ActionDKIM     = "dkim"     // install the DKIM key of a domain
	ActionPing     = "ping"
)

// Request is one call.
type Request struct {
	Action string `json:"action"`
	// apply
	Hostname     string `json:"hostname,omitempty"`
	MaxMessageMB int    `json:"max_message_mb,omitempty"`
	// customer, trash
	Customer string `json:"customer,omitempty"` // UUID
	UID      int    `json:"uid,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Local    string `json:"local,omitempty"` // empty: the whole domain
	// dkim
	Selector string `json:"selector,omitempty"`
	Key      string `json:"key,omitempty"` // PEM, PKCS#8 RSA
	// who asked (for the helper's log)
	By string `json:"by,omitempty"`
}

// Reply is the answer.
type Reply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

var (
	uuidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	localRE  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_+-]|\.[a-z0-9_+-]){0,63}$`)
	selRE    = regexp.MustCompile(`^[a-z0-9]{1,32}$`)
)

// UID range of the customers' mail users.
const (
	MinUID = 2000000
	MaxUID = 2999999
)

// Validate checks a request before anything is done with it.
func (r *Request) Validate() error {
	switch r.Action {
	case ActionPing:
		return nil
	case ActionApply:
		if r.MaxMessageMB < 1 || r.MaxMessageMB > 200 {
			return errors.New("invalid message size")
		}
		if r.Hostname != "" && (!domainRE.MatchString(r.Hostname) || len(r.Hostname) > 253) {
			return errors.New("invalid host name")
		}
		return nil
	case ActionCustomer:
		if !uuidRE.MatchString(r.Customer) || r.UID < MinUID || r.UID > MaxUID {
			return errors.New("invalid customer")
		}
		return nil
	case ActionDKIM:
		if !domainRE.MatchString(r.Domain) || len(r.Domain) > 253 || !selRE.MatchString(r.Selector) {
			return errors.New("invalid domain or selector")
		}
		blk, rest := pem.Decode([]byte(r.Key))
		if blk == nil || blk.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) > 0 {
			return errors.New("invalid key")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return errors.New("invalid key")
		}
		if rk, ok := k.(*rsa.PrivateKey); !ok || rk.N.BitLen() < 2048 {
			return errors.New("the key must be RSA with at least 2048 bits")
		}
		return nil
	case ActionTrash:
		if !uuidRE.MatchString(r.Customer) || !domainRE.MatchString(r.Domain) || len(r.Domain) > 253 {
			return errors.New("invalid domain")
		}
		if r.Local != "" && (!localRE.MatchString(r.Local) || len(r.Local) > 64) {
			return errors.New("invalid mailbox")
		}
		return nil
	}
	return fmt.Errorf("unknown action %q", r.Action)
}

// Client talks to the helper (used by the panel).
type Client struct {
	Socket string
	By     func(ctx context.Context) string
}

// Call sends one request and waits for the reply.
func (c *Client) Call(ctx context.Context, req Request) error {
	if err := req.Validate(); err != nil {
		return err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return fmt.Errorf("mail helper not reachable: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Minute)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var rep Reply
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&rep); err != nil {
		return fmt.Errorf("mail helper: %w", err)
	}
	if !rep.OK {
		return fmt.Errorf("mail helper: %s", rep.Error)
	}
	return nil
}
