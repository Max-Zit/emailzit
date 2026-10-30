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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	ActionBan      = "ban"      // block an address in the firewall (failed sign-ins)
	ActionQueue    = "queue"    // list the mail queue, or hold / release / delete / flush messages
	ActionCert     = "cert"     // install a certificate for the mail services
	ActionSpam     = "spam"     // write the spam scripts of all mailboxes, a customer's or one mailbox
	ActionExport   = "export"   // pack a customer's mail and settings for BackupZit or a move
	ActionStatus   = "status"   // health of the mail system (WatchZit)
	ActionImport   = "import"   // write the mail of an uploaded archive into the customer's mailboxes
	ActionNotice   = "notice"   // put a message of the server into a mailbox (quota warning)
	ActionPing     = "ping"
)

// Request is one call.
type Request struct {
	Action string `json:"action"`
	// apply
	Hostname     string `json:"hostname,omitempty"`
	MaxMessageMB int    `json:"max_message_mb,omitempty"`
	// apply: smart host for all outgoing mail ("[host]:port") and its login
	Relay         string `json:"relay,omitempty"`
	RelayUser     string `json:"relay_user,omitempty"`
	RelayPassword string `json:"relay_password,omitempty"`
	ClamAV        bool   `json:"clamav,omitempty"` // virus scan on
	// customer, trash
	Customer string `json:"customer,omitempty"` // UUID
	UID      int    `json:"uid,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Local    string `json:"local,omitempty"` // empty: the whole domain
	// dkim
	Selector string `json:"selector,omitempty"`
	Key      string `json:"key,omitempty"` // PEM, PKCS#8 RSA
	// ban
	IP      string `json:"ip,omitempty"`
	Minutes int    `json:"minutes,omitempty"`
	// queue: op list, hold, release, delete, flush; IDs of messages
	Op  string   `json:"op,omitempty"`
	IDs []string `json:"ids,omitempty"`
	// cert: PEM chain and key
	Chain string `json:"chain,omitempty"`
	// notice: subject and text (Domain and Local name the mailbox)
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
	// export: file name (time) and the manifest of the customer's settings
	Name     string `json:"name,omitempty"`
	Format   string `json:"format,omitempty"` // import: emailzit or cpanel
	Manifest string `json:"manifest,omitempty"`
	// who asked (for the helper's log)
	By string `json:"by,omitempty"`
}

// Reply is the answer.
type Reply struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

var (
	uuidRE       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	domainRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	localRE      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_+-]|\.[a-z0-9_+-]){0,63}$`)
	selRE        = regexp.MustCompile(`^[a-z0-9]{1,32}$`)
	queueIDRE    = regexp.MustCompile(`^[0-9A-Za-z]{8,20}$`)
	exportNameRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`)
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
		if len(r.Relay) > 300 || len(r.RelayUser) > 256 || len(r.RelayPassword) > 256 || (r.RelayUser != "" && r.Relay == "") {
			return errors.New("invalid relay")
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
	case ActionQueue:
		switch r.Op {
		case "list", "flush":
		case "hold", "release", "delete":
			if len(r.IDs) == 0 || len(r.IDs) > 1000 {
				return errors.New("no messages chosen")
			}
			for _, id := range r.IDs {
				if !queueIDRE.MatchString(id) {
					return errors.New("invalid queue ID")
				}
			}
		default:
			return errors.New("unknown queue operation")
		}
		return nil
	case ActionStatus:
		return nil
	case ActionNotice:
		if !domainRE.MatchString(r.Domain) || !localRE.MatchString(r.Local) || r.Subject == "" || len(r.Subject) > 200 || strings.ContainsAny(r.Subject, "\r\n\x00") || len(r.Body) > 8000 {
			return errors.New("invalid notice")
		}
		return nil
	case ActionImport:
		if !uuidRE.MatchString(r.Customer) || !exportNameRE.MatchString(r.Name) || (r.Format != "emailzit" && r.Format != "cpanel") {
			return errors.New("invalid import")
		}
		return nil
	case ActionExport:
		if !uuidRE.MatchString(r.Customer) || !exportNameRE.MatchString(r.Name) || len(r.Manifest) > 4<<20 || !json.Valid([]byte(r.Manifest)) {
			return errors.New("invalid export")
		}
		return nil
	case ActionSpam:
		if r.Customer != "" && !uuidRE.MatchString(r.Customer) {
			return errors.New("invalid customer")
		}
		if r.Local != "" && (!domainRE.MatchString(r.Domain) || !localRE.MatchString(r.Local)) {
			return errors.New("invalid mailbox")
		}
		return nil
	case ActionCert:
		return validCert(r.Chain, r.Key)
	case ActionBan:
		a, err := netip.ParseAddr(r.IP)
		if err != nil || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || r.Minutes < 1 || r.Minutes > 10080 {
			return errors.New("invalid address or time")
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

// validCert checks a certificate chain and its private key.
func validCert(chain, key string) error {
	if len(chain) > 64<<10 || len(key) > 16<<10 {
		return errors.New("the certificate is too large")
	}
	pair, err := tls.X509KeyPair([]byte(chain), []byte(key))
	if err != nil {
		return errors.New("the certificate and the key do not fit together or are not PEM")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("the certificate cannot be read")
	}
	if time.Now().After(leaf.NotAfter) {
		return errors.New("the certificate has expired")
	}
	return nil
}

// CallData sends a request and decodes the answer's data into v.
func (c *Client) CallData(ctx context.Context, req Request, v any) error {
	if err := req.Validate(); err != nil {
		return err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return fmt.Errorf("mail helper not reachable: %w", err)
	}
	defer conn.Close()
	wait := 2 * time.Minute
	if req.Action == ActionExport || req.Action == ActionImport {
		wait = ExportTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(wait))
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
	if v != nil && len(rep.Data) > 0 {
		return json.Unmarshal(rep.Data, v)
	}
	return nil
}

// QueueItem is a message waiting in the Postfix queue.
type QueueItem struct {
	ID         string    `json:"queue_id"`
	Queue      string    `json:"queue_name"` // active, deferred, hold, incoming
	Arrival    int64     `json:"arrival_time"`
	Size       int64     `json:"message_size"`
	Sender     string    `json:"sender"`
	Recipients []QueueTo `json:"recipients"`
}

// QueueTo is a recipient of a queued message and why it waits.
type QueueTo struct {
	Address string `json:"address"`
	Reason  string `json:"delay_reason,omitempty"`
}

// ExportDir is where exports are written (in the panel's data directory).
const ExportDir = "/var/lib/emailzit/exports"

// ExportTimeout is how long an export may take.
const ExportTimeout = 6 * time.Hour

// ExportResult describes a finished export.
type ExportResult struct {
	File      string `json:"file"`
	Size      int64  `json:"size"`
	Files     int    `json:"files"`
	MailBytes int64  `json:"mail_bytes"`
}

// Status is the health of the mail system.
type Status struct {
	Services     map[string]string `json:"services"` // systemd state: active, inactive, failed …
	Queue        int               `json:"queue"`
	Deferred     int               `json:"deferred"`
	DiskTotalMB  int64             `json:"disk_total_mb"`
	DiskFreeMB   int64             `json:"disk_free_mb"`
	CertNotAfter *time.Time        `json:"certificate_not_after,omitempty"`
}

// ImportDir is where uploaded archives wait (in the panel's data directory).
const ImportDir = "/var/lib/emailzit/imports"

// ImportResult describes what an import wrote.
type ImportResult struct {
	Files            int      `json:"files"`
	Bytes            int64    `json:"bytes"`
	Existing         int      `json:"existing"` // already there, left alone
	Mailboxes        []string `json:"mailboxes"`
	UnknownMailboxes []string `json:"unknown_mailboxes,omitempty"`
}

// PublicCertDir holds the panel's copy of the mail certificate (for the
// public web listener on port 443).
const PublicCertDir = "/var/lib/emailzit/tls"
