package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/idna"

	"github.com/max-zit/emailzit/internal/auth"
)

// Scope limits what a caller may see and change: a customer login sees only
// its own customer's objects; staff (CustomerID "") see everything. Every
// query on customer objects takes a Scope, so ownership is checked in one
// place and never taken from the request.
type Scope struct{ CustomerID string }

// Staff is the scope of server staff (all customers).
var Staff = Scope{}

// IsCustomer reports a customer's scope.
func (sc Scope) IsCustomer() bool { return sc.CustomerID != "" }

// ErrLimit is returned when a package limit would be exceeded.
var ErrLimit = errors.New("limit of the package reached")

// ErrInactive is returned for changes to a suspended or terminated customer.
var ErrInactive = errors.New("the customer is not active")

// NewID makes a random (version 4) UUID.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidID checks the form of a UUID (lower case).
func ValidID(id string) bool { return uuidRE.MatchString(id) }

// ---- packages

// Package is a set of limits.
type Package struct {
	ID              int64
	Slug, Name      string
	MaxDomains      int
	MaxMailboxes    int
	MaxAliases      int
	StorageMB       int // all mailboxes together; 0 = no limit
	MailboxMB       int // default size of a new mailbox
	MaxMailboxMB    int
	SendPerHour     int // per mailbox
	SendPerDay      int
	CustomerPerHour int // the whole customer
	RcptPerMsg      int
	CreatedAt       time.Time
	Customers       int // number of customers using it (lists)
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate checks a package.
func (p *Package) Validate() error {
	p.Slug, p.Name = strings.TrimSpace(strings.ToLower(p.Slug)), strings.TrimSpace(p.Name)
	switch {
	case !slugRE.MatchString(p.Slug):
		return errors.New("the short name may contain lower-case letters, digits and dashes (up to 63)")
	case p.Name == "" || len(p.Name) > 100:
		return errors.New("the name is required (up to 100 characters)")
	case p.MaxDomains < 0 || p.MaxMailboxes < 0 || p.MaxAliases < 0 || p.StorageMB < 0:
		return errors.New("limits cannot be negative")
	case p.MailboxMB < 1 || p.MaxMailboxMB < 1 || p.MailboxMB > p.MaxMailboxMB:
		return errors.New("the default mailbox size must be at least 1 MB and not larger than the largest mailbox")
	case p.StorageMB > 0 && p.MailboxMB > p.StorageMB:
		return errors.New("the default mailbox size cannot be larger than the storage of the package")
	case p.SendPerHour < 0 || p.SendPerDay < 0 || p.CustomerPerHour < 0:
		return errors.New("sending limits cannot be negative")
	case p.RcptPerMsg < 1 || p.RcptPerMsg > 1000:
		return errors.New("recipients per message must be 1–1000")
	}
	return nil
}

const packageCols = `id, slug, name, max_domains, max_mailboxes, max_aliases, storage_mb, mailbox_mb, max_mailbox_mb,
	send_per_hour, send_per_day, customer_per_hour, rcpt_per_msg, created_at`

func scanPackage(row pgx.Row, extra ...any) (*Package, error) {
	p := &Package{}
	dst := []any{&p.ID, &p.Slug, &p.Name, &p.MaxDomains, &p.MaxMailboxes, &p.MaxAliases, &p.StorageMB, &p.MailboxMB,
		&p.MaxMailboxMB, &p.SendPerHour, &p.SendPerDay, &p.CustomerPerHour, &p.RcptPerMsg, &p.CreatedAt}
	return p, row.Scan(append(dst, extra...)...)
}

// Packages lists the packages with the number of customers on each.
func (s *Store) Packages(ctx context.Context) ([]*Package, error) {
	rows, err := s.db.Query(ctx, `SELECT `+packageCols+`, (SELECT count(*) FROM customers c WHERE c.package_id=p.id AND c.status<>'terminated')
		FROM packages p ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Package
	for rows.Next() {
		p := &Package{}
		p, err := scanPackage(rows, &p.Customers)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PackageByID loads a package.
func (s *Store) PackageByID(ctx context.Context, id int64) (*Package, error) {
	p, err := scanPackage(s.db.QueryRow(ctx, `SELECT `+packageCols+` FROM packages WHERE id=$1`, id))
	return p, notFound(err)
}

// PackageBySlug loads a package by its short name (API).
func (s *Store) PackageBySlug(ctx context.Context, slug string) (*Package, error) {
	p, err := scanPackage(s.db.QueryRow(ctx, `SELECT `+packageCols+` FROM packages WHERE slug=$1`, strings.ToLower(slug)))
	return p, notFound(err)
}

// SavePackage creates (ID 0) or updates a package.
func (s *Store) SavePackage(ctx context.Context, p *Package) error {
	if err := p.Validate(); err != nil {
		return err
	}
	args := []any{p.Slug, p.Name, p.MaxDomains, p.MaxMailboxes, p.MaxAliases, p.StorageMB, p.MailboxMB, p.MaxMailboxMB,
		p.SendPerHour, p.SendPerDay, p.CustomerPerHour, p.RcptPerMsg}
	var err error
	if p.ID == 0 {
		err = s.db.QueryRow(ctx, `INSERT INTO packages(slug, name, max_domains, max_mailboxes, max_aliases, storage_mb, mailbox_mb,
			max_mailbox_mb, send_per_hour, send_per_day, customer_per_hour, rcpt_per_msg) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			RETURNING id`, args...).Scan(&p.ID)
	} else {
		var tag interface{ RowsAffected() int64 }
		tag, err = s.db.Exec(ctx, `UPDATE packages SET slug=$1, name=$2, max_domains=$3, max_mailboxes=$4, max_aliases=$5, storage_mb=$6,
			mailbox_mb=$7, max_mailbox_mb=$8, send_per_hour=$9, send_per_day=$10, customer_per_hour=$11, rcpt_per_msg=$12 WHERE id=$13`,
			append(args, p.ID)...)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
	}
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeletePackage removes a package nobody uses.
func (s *Store) DeletePackage(ctx context.Context, id int64) error {
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM customers WHERE package_id=$1`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("the package is still used by customers")
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM packages WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- customers

// Customer statuses.
const (
	CustomerActive     = "active"
	CustomerSuspended  = "suspended"
	CustomerTerminated = "terminated"
)

// Customer is one hosting customer.
type Customer struct {
	ID           string
	Number       int
	ExternalID   string
	Username     string // shared with HostZit (optional)
	Name, Email  string
	PackageID    int64
	PackageName  string
	Status       string
	StatusReason string
	Lang         string
	CreatedAt    time.Time
	StatusAt     time.Time
	// counts (lists and the overview)
	Domains, Mailboxes, Aliases int
	QuotaMB                     int64 // sum of the mailbox sizes
	UsedBytes                   int64
}

// UID is the system user (and group) the customer's mail belongs to.
func (c *Customer) UID() int { return 2000000 + c.Number }

// Active reports an active customer.
func (c *Customer) Active() bool { return c != nil && c.Status == CustomerActive }

const customerCols = `c.id, c.number, COALESCE(c.external_id, ''), COALESCE(c.username, ''), c.name, c.email, c.package_id, p.name, c.status, c.status_reason,
	c.lang, c.created_at, c.status_at,
	(SELECT count(*) FROM domains d WHERE d.customer_id=c.id),
	(SELECT count(*) FROM mailboxes m WHERE m.customer_id=c.id),
	(SELECT count(*) FROM aliases a WHERE a.customer_id=c.id),
	(SELECT COALESCE(sum(quota_mb), 0) FROM mailboxes m WHERE m.customer_id=c.id),
	(SELECT COALESCE(sum(used_bytes), 0) FROM mailboxes m WHERE m.customer_id=c.id)`

func scanCustomer(row pgx.Row) (*Customer, error) {
	c := &Customer{}
	err := row.Scan(&c.ID, &c.Number, &c.ExternalID, &c.Username, &c.Name, &c.Email, &c.PackageID, &c.PackageName, &c.Status, &c.StatusReason,
		&c.Lang, &c.CreatedAt, &c.StatusAt, &c.Domains, &c.Mailboxes, &c.Aliases, &c.QuotaMB, &c.UsedBytes)
	return c, err
}

// NewCustomer describes a customer to create.
type NewCustomer struct {
	ID         string // optional: the caller's UUID (the same customer in HostZit)
	ExternalID string // optional: the billing system's ID
	Name       string
	Email      string
	PackageID  int64
}

// CreateCustomer adds a customer.
func (s *Store) CreateCustomer(ctx context.Context, n NewCustomer) (*Customer, error) {
	n.Name, n.Email, n.ExternalID = strings.TrimSpace(n.Name), strings.TrimSpace(n.Email), strings.TrimSpace(n.ExternalID)
	n.ID = strings.ToLower(strings.TrimSpace(n.ID))
	if n.ID == "" {
		n.ID = NewID()
	}
	switch {
	case !ValidID(n.ID):
		return nil, errors.New("the customer ID must be a UUID")
	case n.Name == "" || len(n.Name) > 200:
		return nil, errors.New("the name is required (up to 200 characters)")
	case len(n.ExternalID) > 100:
		return nil, errors.New("the external ID is too long")
	}
	if n.Email != "" {
		if _, err := ParseAddress(n.Email); err != nil {
			return nil, errors.New("the contact e-mail address is not valid")
		}
	}
	var ext any
	if n.ExternalID != "" {
		ext = n.ExternalID
	}
	_, err := s.db.Exec(ctx, `INSERT INTO customers(id, external_id, name, email, package_id) VALUES($1,$2,$3,$4,$5)`,
		n.ID, ext, n.Name, n.Email, n.PackageID)
	if isUnique(err) {
		return nil, ErrConflict
	}
	if isFK(err) {
		return nil, errors.New("unknown package")
	}
	if err != nil {
		return nil, err
	}
	return s.CustomerByID(ctx, n.ID)
}

// CustomerByID loads a customer.
func (s *Store) CustomerByID(ctx context.Context, id string) (*Customer, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	c, err := scanCustomer(s.db.QueryRow(ctx, `SELECT `+customerCols+` FROM customers c JOIN packages p ON p.id=c.package_id WHERE c.id=$1`, id))
	return c, notFound(err)
}

// CustomerByExternalID loads a customer by the billing system's ID.
func (s *Store) CustomerByExternalID(ctx context.Context, ext string) (*Customer, error) {
	c, err := scanCustomer(s.db.QueryRow(ctx, `SELECT `+customerCols+` FROM customers c JOIN packages p ON p.id=c.package_id WHERE c.external_id=$1`, ext))
	return c, notFound(err)
}

// CustomerFilter narrows the customer list.
type CustomerFilter struct {
	Query  string // name, e-mail, external ID or domain
	Status string
	Limit  int
	After  string // name|id of the last row of the previous page
}

// Customers lists customers, ordered by name.
func (s *Store) Customers(ctx context.Context, f CustomerFilter) ([]*Customer, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 200
	}
	q := `SELECT ` + customerCols + ` FROM customers c JOIN packages p ON p.id=c.package_id WHERE true`
	var args []any
	if f.Query != "" {
		args = append(args, "%"+likeEscape(strings.ToLower(f.Query))+"%")
		q += fmt.Sprintf(` AND (lower(c.name) LIKE $%[1]d OR lower(c.email) LIKE $%[1]d OR lower(COALESCE(c.external_id,'')) LIKE $%[1]d
			OR EXISTS (SELECT 1 FROM domains d WHERE d.customer_id=c.id AND d.name LIKE $%[1]d))`, len(args))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		q += fmt.Sprintf(` AND c.status=$%d`, len(args))
	}
	if f.After != "" {
		name, id, _ := strings.Cut(f.After, "|")
		args = append(args, name, id)
		q += fmt.Sprintf(` AND (lower(c.name), c.id::text) > ($%d, $%d)`, len(args)-1, len(args))
	}
	args = append(args, f.Limit)
	q += fmt.Sprintf(` ORDER BY lower(c.name), c.id::text LIMIT $%d`, len(args))
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Customer
	for rows.Next() {
		c, err := scanCustomer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// UpdateCustomer changes the name, contact e-mail and external ID.
func (s *Store) UpdateCustomer(ctx context.Context, id, name, email, ext string) error {
	name, email, ext = strings.TrimSpace(name), strings.TrimSpace(email), strings.TrimSpace(ext)
	if name == "" || len(name) > 200 {
		return errors.New("the name is required (up to 200 characters)")
	}
	if email != "" {
		if _, err := ParseAddress(email); err != nil {
			return errors.New("the contact e-mail address is not valid")
		}
	}
	var extv any
	if ext != "" {
		extv = ext
	}
	tag, err := s.db.Exec(ctx, `UPDATE customers SET name=$2, email=$3, external_id=$4 WHERE id=$1`, id, name, email, extv)
	if isUnique(err) {
		return ErrConflict
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetCustomerPackage moves a customer to another package. Usage above the
// new limits is kept (nothing is deleted), but nothing new can be added.
func (s *Store) SetCustomerPackage(ctx context.Context, id string, pkg int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE customers SET package_id=$2 WHERE id=$1`, id, pkg)
	if isFK(err) {
		return errors.New("unknown package")
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetCustomerStatus suspends, re-activates or terminates a customer. A
// suspended customer keeps receiving mail, but nobody of it can sign in or
// send; a terminated customer's mail is refused (the data stays until it
// is deleted). Sessions of the customer's logins and mail users end.
func (s *Store) SetCustomerStatus(ctx context.Context, id, status, reason string) error {
	if status != CustomerActive && status != CustomerSuspended && status != CustomerTerminated {
		return errors.New("unknown status")
	}
	if len(reason) > 300 {
		return errors.New("the reason is too long")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE customers SET status=$2, status_reason=$3, status_at=now() WHERE id=$1`, id, status, strings.TrimSpace(reason))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if status != CustomerActive {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE customer_id=$1)`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mail_sessions WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE customer_id=$1)`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM app_passwords WHERE kind='webmail' AND mailbox_id IN (SELECT id FROM mailboxes WHERE customer_id=$1)`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// lockCustomer locks the customer row for a change that counts against
// the package and returns the customer's package; it fails for customers
// that are not active.
func lockCustomer(ctx context.Context, tx pgx.Tx, id string) (*Package, error) {
	var status string
	var pkg int64
	err := tx.QueryRow(ctx, `SELECT status, package_id FROM customers WHERE id=$1 FOR UPDATE`, id).Scan(&status, &pkg)
	if err != nil {
		return nil, notFound(err)
	}
	if status != CustomerActive {
		return nil, ErrInactive
	}
	return scanPackage(tx.QueryRow(ctx, `SELECT `+packageCols+` FROM packages WHERE id=$1`, pkg))
}

// ---- domains

// Domain is a mail domain of a customer.
type Domain struct {
	ID           string
	CustomerID   string
	CustomerName string
	Name         string // ASCII (Punycode) form
	Verified     bool
	VerifyToken  string
	CatchAll     string
	Disabled     bool
	CreatedAt    time.Time
	Mailboxes    int
	Aliases      int
}

// Unicode is the domain name as people write it.
func (d *Domain) Unicode() string {
	if u, err := idna.Display.ToUnicode(d.Name); err == nil {
		return u
	}
	return d.Name
}

// VerifyName is where the verification TXT record goes.
func (d *Domain) VerifyName() string { return "_emailzit." + d.Name }

// VerifyValue is the content of the verification TXT record.
func (d *Domain) VerifyValue() string { return "emailzit-verify=" + d.VerifyToken }

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain checks a domain name and returns its lower-case ASCII
// form (internationalised names become Punycode).
func NormalizeDomain(name string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	a, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", errors.New("not a valid domain name")
	}
	a = strings.ToLower(a)
	labels := strings.Split(a, ".")
	if len(a) > 253 || len(labels) < 2 {
		return "", errors.New("not a valid domain name")
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return "", errors.New("not a valid domain name")
		}
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(labels[len(labels)-1]) {
		return "", errors.New("not a valid domain name")
	}
	return a, nil
}

const domainCols = `d.id, d.customer_id, c.name, d.name, d.verified, d.verify_token, d.catch_all, d.disabled, d.created_at,
	(SELECT count(*) FROM mailboxes m WHERE m.domain_id=d.id), (SELECT count(*) FROM aliases a WHERE a.domain_id=d.id)`

func scanDomain(row pgx.Row) (*Domain, error) {
	d := &Domain{}
	err := row.Scan(&d.ID, &d.CustomerID, &d.CustomerName, &d.Name, &d.Verified, &d.VerifyToken, &d.CatchAll, &d.Disabled, &d.CreatedAt,
		&d.Mailboxes, &d.Aliases)
	return d, err
}

// CreateDomain adds a domain to a customer. verified marks it as verified
// at once (staff, dedicated servers, or the zone is in HostZit's DNS).
func (s *Store) CreateDomain(ctx context.Context, sc Scope, customerID, name string, verified bool) (*Domain, error) {
	if sc.IsCustomer() {
		customerID = sc.CustomerID
	}
	a, err := NormalizeDomain(name)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	p, err := lockCustomer(ctx, tx, customerID)
	if err != nil {
		return nil, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM domains WHERE customer_id=$1`, customerID).Scan(&n); err != nil {
		return nil, err
	}
	if n >= p.MaxDomains {
		return nil, ErrLimit
	}
	id := NewID()
	_, err = tx.Exec(ctx, `INSERT INTO domains(id, customer_id, name, verified, verify_token) VALUES($1,$2,$3,$4,$5)`,
		id, customerID, a, verified, auth.RandomToken(16))
	if isUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.DomainByID(ctx, sc, id)
}

// DomainByID loads a domain within the scope.
func (s *Store) DomainByID(ctx context.Context, sc Scope, id string) (*Domain, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	d, err := scanDomain(s.db.QueryRow(ctx, `SELECT `+domainCols+` FROM domains d JOIN customers c ON c.id=d.customer_id
		WHERE d.id=$1 AND ($2 = '' OR d.customer_id::text = $2)`, id, sc.CustomerID))
	return d, notFound(err)
}

// DomainByName loads a domain by name within the scope.
func (s *Store) DomainByName(ctx context.Context, sc Scope, name string) (*Domain, error) {
	a, err := NormalizeDomain(name)
	if err != nil {
		return nil, ErrNotFound
	}
	d, err := scanDomain(s.db.QueryRow(ctx, `SELECT `+domainCols+` FROM domains d JOIN customers c ON c.id=d.customer_id
		WHERE d.name=$1 AND ($2 = '' OR d.customer_id::text = $2)`, a, sc.CustomerID))
	return d, notFound(err)
}

// Domains lists the domains in the scope (customerID narrows staff lists).
func (s *Store) Domains(ctx context.Context, sc Scope, customerID string) ([]*Domain, error) {
	if sc.IsCustomer() {
		customerID = sc.CustomerID
	}
	rows, err := s.db.Query(ctx, `SELECT `+domainCols+` FROM domains d JOIN customers c ON c.id=d.customer_id
		WHERE ($1 = '' OR d.customer_id::text = $1) ORDER BY d.name LIMIT 5000`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDomainVerified marks a domain as verified (or not).
func (s *Store) SetDomainVerified(ctx context.Context, sc Scope, id string, v bool) error {
	return s.execScoped(ctx, `UPDATE domains SET verified=$3 WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`, id, sc.CustomerID, v)
}

// SetDomainDisabled switches mail for a domain off (staff only).
func (s *Store) SetDomainDisabled(ctx context.Context, id string, v bool) error {
	return s.execScoped(ctx, `UPDATE domains SET disabled=$3 WHERE id=$1 AND $2 = ''`, id, "", v)
}

// SetCatchAll sets where mail for unknown addresses of the domain goes
// ("" = refuse it, the default). The target must be a mailbox of the same
// customer or an outside address.
func (s *Store) SetCatchAll(ctx context.Context, sc Scope, id, target string) error {
	d, err := s.DomainByID(ctx, sc, id)
	if err != nil {
		return err
	}
	target = strings.TrimSpace(strings.ToLower(target))
	if target != "" {
		dest, err := s.checkDestinations(ctx, d.CustomerID, []string{target})
		if err != nil {
			return err
		}
		target = dest[0]
	}
	return s.execScoped(ctx, `UPDATE domains SET catch_all=$3 WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`, id, sc.CustomerID, target)
}

// DeleteDomain removes a domain with all its mailboxes and aliases (the
// mail files are removed by the helper afterwards).
func (s *Store) DeleteDomain(ctx context.Context, sc Scope, id string) error {
	return s.execScoped(ctx, `DELETE FROM domains WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`, id, sc.CustomerID)
}

func (s *Store) execScoped(ctx context.Context, q string, args ...any) error {
	if id, ok := args[0].(string); ok && !ValidID(id) {
		return ErrNotFound
	}
	tag, err := s.db.Exec(ctx, q, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- addresses

var localRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_+-]|\.[a-z0-9_+-]){0,63}$`)

// ValidLocalPart checks the part of an address before the @ (a strict
// subset of what RFC 5321 allows: what mailbox names are in practice).
func ValidLocalPart(l string) error {
	if !localRE.MatchString(l) || len(l) > 64 {
		return errors.New("the name may contain letters, digits, dots, dashes, underscores and plus (up to 64), not at the start or end")
	}
	return nil
}

// ParseAddress checks an e-mail address and returns it in lower case with
// the domain in ASCII form.
func ParseAddress(a string) (string, error) {
	a = strings.TrimSpace(a)
	if strings.ContainsAny(a, " <>\"(),;:\\[]\r\n\t") {
		return "", errors.New("not a valid e-mail address")
	}
	if _, err := mail.ParseAddress(a); err != nil {
		return "", errors.New("not a valid e-mail address")
	}
	l, d, ok := strings.Cut(a, "@")
	if !ok || l == "" || len(l) > 64 {
		return "", errors.New("not a valid e-mail address")
	}
	dn, err := NormalizeDomain(d)
	if err != nil {
		return "", errors.New("not a valid e-mail address")
	}
	return strings.ToLower(l) + "@" + dn, nil
}

// checkDestinations validates alias destinations: outside addresses, or
// addresses on this server that belong to the same customer (a customer
// cannot route mail into another customer's mailboxes by alias tricks).
func (s *Store) checkDestinations(ctx context.Context, customerID string, list []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range list {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		a, err := ParseAddress(raw)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", raw, err)
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		_, dom, _ := strings.Cut(a, "@")
		var owner string
		err = s.db.QueryRow(ctx, `SELECT customer_id::text FROM domains WHERE name=$1`, dom).Scan(&owner)
		switch {
		case err == nil && owner != customerID:
			return nil, fmt.Errorf("%s: the domain belongs to another customer of this server", a)
		case err == nil:
			var n int
			if err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM mailboxes WHERE address=$1) + (SELECT count(*) FROM aliases WHERE address=$1)`, a).Scan(&n); err != nil {
				return nil, err
			}
			if n == 0 {
				return nil, fmt.Errorf("%s: there is no such mailbox or alias", a)
			}
		case !errors.Is(err, pgx.ErrNoRows):
			return nil, err
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one destination is required")
	}
	if len(out) > 50 {
		return nil, errors.New("at most 50 destinations")
	}
	return out, nil
}

// ---- mailboxes

// Mailbox is one mail account.
type Mailbox struct {
	ID           string
	DomainID     string
	CustomerID   string
	LocalPart    string
	Address      string
	DisplayName  string
	QuotaMB      int
	Disabled     bool
	SendBlocked  bool
	SendPerHour  *int
	SendPerDay   *int
	TOTPEnabled  bool
	HasWebPass   bool
	Lang         string
	UsedBytes    int64
	UsedAt       *time.Time
	CreatedAt    time.Time
	LastLoginAt  *time.Time
	AppPasswords int
}

// UsedPercent is the share of the quota in use.
func (m *Mailbox) UsedPercent() int {
	if m.QuotaMB <= 0 {
		return 0
	}
	p := int(m.UsedBytes * 100 / (int64(m.QuotaMB) << 20))
	return min(p, 100)
}

const mailboxCols = `m.id, m.domain_id, m.customer_id, m.local_part, m.address, m.display_name, m.quota_mb, m.disabled, m.send_blocked,
	m.send_per_hour, m.send_per_day, m.totp_enabled, m.web_password_hash <> '', m.lang, m.used_bytes, m.used_at, m.created_at, m.last_login_at,
	(SELECT count(*) FROM app_passwords p WHERE p.mailbox_id=m.id AND p.kind='app')`

func scanMailbox(row pgx.Row) (*Mailbox, error) {
	m := &Mailbox{}
	err := row.Scan(&m.ID, &m.DomainID, &m.CustomerID, &m.LocalPart, &m.Address, &m.DisplayName, &m.QuotaMB, &m.Disabled, &m.SendBlocked,
		&m.SendPerHour, &m.SendPerDay, &m.TOTPEnabled, &m.HasWebPass, &m.Lang, &m.UsedBytes, &m.UsedAt, &m.CreatedAt, &m.LastLoginAt, &m.AppPasswords)
	return m, err
}

// NewMailbox describes a mailbox to create.
type NewMailbox struct {
	DomainID    string
	LocalPart   string
	DisplayName string
	Password    string // web password (webmail and own settings, with 2FA)
	QuotaMB     int    // 0 = the package default
}

// CreateMailbox adds a mailbox to a domain of the scope.
func (s *Store) CreateMailbox(ctx context.Context, sc Scope, n NewMailbox) (*Mailbox, error) {
	d, err := s.DomainByID(ctx, sc, n.DomainID)
	if err != nil {
		return nil, err
	}
	n.LocalPart = strings.ToLower(strings.TrimSpace(n.LocalPart))
	if err := ValidLocalPart(n.LocalPart); err != nil {
		return nil, err
	}
	if err := auth.CheckPasswordPolicy(n.Password); err != nil {
		return nil, err
	}
	hash, err := auth.HashPassword(n.Password)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	p, err := lockCustomer(ctx, tx, d.CustomerID)
	if err != nil {
		return nil, err
	}
	if n.QuotaMB == 0 {
		n.QuotaMB = p.MailboxMB
	}
	if n.QuotaMB < 1 || n.QuotaMB > p.MaxMailboxMB {
		return nil, fmt.Errorf("the mailbox size must be 1–%d MB", p.MaxMailboxMB)
	}
	var count int
	var sum int64
	if err := tx.QueryRow(ctx, `SELECT count(*), COALESCE(sum(quota_mb), 0) FROM mailboxes WHERE customer_id=$1`, d.CustomerID).Scan(&count, &sum); err != nil {
		return nil, err
	}
	if count >= p.MaxMailboxes {
		return nil, ErrLimit
	}
	if p.StorageMB > 0 && sum+int64(n.QuotaMB) > int64(p.StorageMB) {
		return nil, fmt.Errorf("%w: only %d MB of storage are left", ErrLimit, max(int64(p.StorageMB)-sum, 0))
	}
	addr := n.LocalPart + "@" + d.Name
	var taken int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM aliases WHERE address=$1`, addr).Scan(&taken); err != nil {
		return nil, err
	}
	if taken > 0 {
		return nil, ErrConflict
	}
	id := NewID()
	_, err = tx.Exec(ctx, `INSERT INTO mailboxes(id, domain_id, customer_id, local_part, address, display_name, web_password_hash, quota_mb)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, d.ID, d.CustomerID, n.LocalPart, addr, strings.TrimSpace(n.DisplayName), hash, n.QuotaMB)
	if isUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.MailboxByID(ctx, sc, id)
}

// MailboxByID loads a mailbox within the scope.
func (s *Store) MailboxByID(ctx context.Context, sc Scope, id string) (*Mailbox, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	m, err := scanMailbox(s.db.QueryRow(ctx, `SELECT `+mailboxCols+` FROM mailboxes m WHERE m.id=$1 AND ($2 = '' OR m.customer_id::text = $2)`,
		id, sc.CustomerID))
	return m, notFound(err)
}

// MailboxByAddress loads a mailbox by its address (mail user sign-in).
func (s *Store) MailboxByAddress(ctx context.Context, addr string) (*Mailbox, error) {
	a, err := ParseAddress(addr)
	if err != nil {
		return nil, ErrNotFound
	}
	m, err := scanMailbox(s.db.QueryRow(ctx, `SELECT `+mailboxCols+` FROM mailboxes m WHERE m.address=$1`, a))
	return m, notFound(err)
}

// MailboxFilter narrows mailbox lists.
type MailboxFilter struct {
	CustomerID string // staff only
	DomainID   string
	Query      string
	Limit      int
}

// Mailboxes lists mailboxes in the scope.
func (s *Store) Mailboxes(ctx context.Context, sc Scope, f MailboxFilter) ([]*Mailbox, error) {
	if sc.IsCustomer() {
		f.CustomerID = sc.CustomerID
	}
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 1000
	}
	rows, err := s.db.Query(ctx, `SELECT `+mailboxCols+` FROM mailboxes m
		WHERE ($1 = '' OR m.customer_id::text = $1) AND ($2 = '' OR m.domain_id::text = $2) AND ($3 = '' OR m.address LIKE $3)
		ORDER BY m.address LIMIT $4`, f.CustomerID, f.DomainID, likeQuery(f.Query), f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Mailbox
	for rows.Next() {
		m, err := scanMailbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func likeQuery(q string) string {
	q = strings.TrimSpace(strings.ToLower(q))
	if q == "" {
		return ""
	}
	return "%" + likeEscape(q) + "%"
}

// MailboxUpdate is what the panels change on a mailbox.
type MailboxUpdate struct {
	DisplayName string
	QuotaMB     int
	Disabled    bool
	// staff only:
	SendBlocked bool
	SendPerHour *int
	SendPerDay  *int
}

// UpdateMailbox changes a mailbox. Customers cannot change the sending
// limits or lift a sending block set by staff.
func (s *Store) UpdateMailbox(ctx context.Context, sc Scope, id string, u MailboxUpdate) error {
	m, err := s.MailboxByID(ctx, sc, id)
	if err != nil {
		return err
	}
	if len(u.DisplayName) > 100 {
		return errors.New("the display name is too long")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	p, err := lockCustomer(ctx, tx, m.CustomerID)
	if err != nil {
		return err
	}
	if u.QuotaMB != m.QuotaMB {
		if u.QuotaMB < 1 || u.QuotaMB > p.MaxMailboxMB {
			return fmt.Errorf("the mailbox size must be 1–%d MB", p.MaxMailboxMB)
		}
		var sum int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(quota_mb), 0) FROM mailboxes WHERE customer_id=$1 AND id<>$2`, m.CustomerID, id).Scan(&sum); err != nil {
			return err
		}
		if p.StorageMB > 0 && sum+int64(u.QuotaMB) > int64(p.StorageMB) {
			return fmt.Errorf("%w: only %d MB of storage are left", ErrLimit, max(int64(p.StorageMB)-sum, 0))
		}
	}
	if sc.IsCustomer() {
		u.SendBlocked, u.SendPerHour, u.SendPerDay = m.SendBlocked, m.SendPerHour, m.SendPerDay
	}
	if _, err := tx.Exec(ctx, `UPDATE mailboxes SET display_name=$2, quota_mb=$3, disabled=$4, send_blocked=$5, send_per_hour=$6, send_per_day=$7
		WHERE id=$1`, id, strings.TrimSpace(u.DisplayName), u.QuotaMB, u.Disabled, u.SendBlocked, u.SendPerHour, u.SendPerDay); err != nil {
		return err
	}
	if u.Disabled {
		if _, err := tx.Exec(ctx, `DELETE FROM mail_sessions WHERE mailbox_id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// SetMailboxPassword sets the web password of a mailbox and signs it out
// everywhere (its webmail tokens end too; app passwords stay).
func (s *Store) SetMailboxPassword(ctx context.Context, sc Scope, id, password string) error {
	if err := auth.CheckPasswordPolicy(password); err != nil {
		return err
	}
	h, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := s.execScoped(ctx, `UPDATE mailboxes SET web_password_hash=$3 WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`, id, sc.CustomerID, h); err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM mail_sessions WHERE mailbox_id=$1`, id)
	if err == nil {
		_, err = s.db.Exec(ctx, `DELETE FROM app_passwords WHERE mailbox_id=$1 AND kind='webmail'`, id)
	}
	return err
}

// ResetMailboxTwoFactor removes the second factor of a mail user (set up
// again at the next sign-in).
func (s *Store) ResetMailboxTwoFactor(ctx context.Context, sc Scope, id string) error {
	if err := s.execScoped(ctx, `UPDATE mailboxes SET totp_secret='', totp_enabled=false, totp_last_step=0, recovery_codes='{}'
		WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`, id, sc.CustomerID); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM mail_sessions WHERE mailbox_id=$1`, id)
	return err
}

// DeleteMailbox removes a mailbox (the files are removed by the helper).
// Aliases that pointed only to it are left for the customer to fix.
func (s *Store) DeleteMailbox(ctx context.Context, sc Scope, id string) error {
	return s.execScoped(ctx, `DELETE FROM mailboxes WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`, id, sc.CustomerID)
}

// ---- app passwords

// AppPassword is a password of one mail program or device.
type AppPassword struct {
	ID         string
	MailboxID  string
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	LastIP     string
}

// appPasswordAlphabet has no look-alike characters (0/o, 1/l).
const appPasswordAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

// NewAppPassword makes a random app password: four groups of five
// characters (about 100 bits), easy to type on a phone.
func NewAppPassword() string {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(appPasswordAlphabet[int(c)%len(appPasswordAlphabet)])
	}
	return sb.String()
}

// HashAppPassword is what the database keeps (and Dovecot compares).
func HashAppPassword(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(h[:])
}

// CreateAppPassword adds an app password to a mailbox and returns it (shown
// once).
func (s *Store) CreateAppPassword(ctx context.Context, mailboxID, name string) (string, *AppPassword, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 60 {
		return "", nil, errors.New("give the device or program a name (up to 60 characters)")
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM app_passwords WHERE mailbox_id=$1 AND kind='app'`, mailboxID).Scan(&n); err != nil {
		return "", nil, err
	}
	if n >= 30 {
		return "", nil, errors.New("a mailbox can have at most 30 app passwords; remove old ones first")
	}
	pw := NewAppPassword()
	ap := &AppPassword{ID: NewID(), MailboxID: mailboxID, Name: name, CreatedAt: s.now()}
	_, err := s.db.Exec(ctx, `INSERT INTO app_passwords(id, mailbox_id, kind, name, hash, created_at) VALUES($1,$2,'app',$3,$4,$5)`,
		ap.ID, mailboxID, name, HashAppPassword(pw), ap.CreatedAt)
	if err != nil {
		return "", nil, err
	}
	return pw, ap, nil
}

// AppPasswords lists the app passwords of a mailbox.
func (s *Store) AppPasswords(ctx context.Context, mailboxID string) ([]*AppPassword, error) {
	rows, err := s.db.Query(ctx, `SELECT id, mailbox_id, name, created_at, last_used_at, last_ip FROM app_passwords
		WHERE mailbox_id=$1 AND kind='app' ORDER BY created_at`, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppPassword
	for rows.Next() {
		a := &AppPassword{}
		if err := rows.Scan(&a.ID, &a.MailboxID, &a.Name, &a.CreatedAt, &a.LastUsedAt, &a.LastIP); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAppPassword revokes an app password of a mailbox.
func (s *Store) DeleteAppPassword(ctx context.Context, mailboxID, id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM app_passwords WHERE id=$1 AND mailbox_id=$2 AND kind='app'`, id, mailboxID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- aliases and forwarders

// Alias sends mail for an address to other addresses.
type Alias struct {
	ID           string
	DomainID     string
	CustomerID   string
	Address      string
	Destinations []string
	SendAs       bool
	CreatedAt    time.Time
}

const aliasCols = `a.id, a.domain_id, a.customer_id, a.address, a.destinations, a.send_as, a.created_at`

func scanAlias(row pgx.Row) (*Alias, error) {
	a := &Alias{}
	err := row.Scan(&a.ID, &a.DomainID, &a.CustomerID, &a.Address, &a.Destinations, &a.SendAs, &a.CreatedAt)
	return a, err
}

// CreateAlias adds an alias (or a forwarder, when the address is a
// mailbox: then the mailbox keeps a copy only if it is listed among the
// destinations).
func (s *Store) CreateAlias(ctx context.Context, sc Scope, domainID, local string, dest []string, sendAs bool) (*Alias, error) {
	d, err := s.DomainByID(ctx, sc, domainID)
	if err != nil {
		return nil, err
	}
	local = strings.ToLower(strings.TrimSpace(local))
	if err := ValidLocalPart(local); err != nil {
		return nil, err
	}
	addr := local + "@" + d.Name
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	p, err := lockCustomer(ctx, tx, d.CustomerID)
	if err != nil {
		return nil, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM aliases WHERE customer_id=$1`, d.CustomerID).Scan(&n); err != nil {
		return nil, err
	}
	if n >= p.MaxAliases {
		return nil, ErrLimit
	}
	list, err := s.checkDestinations(ctx, d.CustomerID, dest)
	if err != nil {
		return nil, err
	}
	for _, x := range list {
		if x == addr {
			// a mailbox forwarding with a copy lists itself; an alias of
			// nothing pointing at itself would loop
			var mb int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM mailboxes WHERE address=$1`, addr).Scan(&mb); err != nil {
				return nil, err
			}
			if mb == 0 {
				return nil, errors.New("an alias cannot point to itself")
			}
		}
	}
	id := NewID()
	_, err = tx.Exec(ctx, `INSERT INTO aliases(id, domain_id, customer_id, address, destinations, send_as) VALUES($1,$2,$3,$4,$5,$6)`,
		id, d.ID, d.CustomerID, addr, list, sendAs)
	if isUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.AliasByID(ctx, sc, id)
}

// AliasByID loads an alias within the scope.
func (s *Store) AliasByID(ctx context.Context, sc Scope, id string) (*Alias, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	a, err := scanAlias(s.db.QueryRow(ctx, `SELECT `+aliasCols+` FROM aliases a WHERE a.id=$1 AND ($2 = '' OR a.customer_id::text = $2)`, id, sc.CustomerID))
	return a, notFound(err)
}

// Aliases lists aliases in the scope.
func (s *Store) Aliases(ctx context.Context, sc Scope, customerID, domainID string) ([]*Alias, error) {
	if sc.IsCustomer() {
		customerID = sc.CustomerID
	}
	rows, err := s.db.Query(ctx, `SELECT `+aliasCols+` FROM aliases a WHERE ($1 = '' OR a.customer_id::text = $1) AND ($2 = '' OR a.domain_id::text = $2)
		ORDER BY a.address LIMIT 5000`, customerID, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Alias
	for rows.Next() {
		a, err := scanAlias(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateAlias changes the destinations of an alias.
func (s *Store) UpdateAlias(ctx context.Context, sc Scope, id string, dest []string, sendAs bool) error {
	a, err := s.AliasByID(ctx, sc, id)
	if err != nil {
		return err
	}
	list, err := s.checkDestinations(ctx, a.CustomerID, dest)
	if err != nil {
		return err
	}
	return s.execScoped(ctx, `UPDATE aliases SET destinations=$3, send_as=$4 WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`,
		id, sc.CustomerID, list, sendAs)
}

// DeleteAlias removes an alias.
func (s *Store) DeleteAlias(ctx context.Context, sc Scope, id string) error {
	return s.execScoped(ctx, `DELETE FROM aliases WHERE id=$1 AND ($2 = '' OR customer_id::text = $2)`, id, sc.CustomerID)
}

// ---- overview

// Totals counts the objects of the server (staff overview).
type Totals struct {
	Customers, Suspended, Domains, Unverified, Mailboxes, Aliases int
	QuotaMB, UsedBytes                                            int64
}

// ServerTotals counts customers, domains and mailboxes.
func (s *Store) ServerTotals(ctx context.Context) (Totals, error) {
	var t Totals
	err := s.db.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM customers WHERE status<>'terminated'), (SELECT count(*) FROM customers WHERE status='suspended'),
		(SELECT count(*) FROM domains), (SELECT count(*) FROM domains WHERE NOT verified),
		(SELECT count(*) FROM mailboxes), (SELECT count(*) FROM aliases),
		(SELECT COALESCE(sum(quota_mb),0) FROM mailboxes), (SELECT COALESCE(sum(used_bytes),0) FROM mailboxes)`).
		Scan(&t.Customers, &t.Suspended, &t.Domains, &t.Unverified, &t.Mailboxes, &t.Aliases, &t.QuotaMB, &t.UsedBytes)
	return t, err
}

// GrantMailRoles gives the mail software read access to its views: Postfix
// (role postfix) and Dovecot (role dovecot) read only the views, the root
// helper (role root) reads what it checks and writes only the usage
// columns. Roles that do not exist (development) are skipped. Run at every
// start, so new views get their grants.
func (s *Store) GrantMailRoles(ctx context.Context) error {
	grants := map[string][]string{
		"postfix": {`GRANT SELECT ON mta_domains, mta_mailboxes, mta_aliases, mta_sender_logins TO postfix`},
		"dovecot": {`GRANT SELECT ON mda_users, mda_logins TO dovecot`},
		"root": {`GRANT SELECT ON mda_users, customers TO root`, `GRANT SELECT (id, address) ON mailboxes TO root`,
			`GRANT UPDATE (used_bytes, used_at) ON mailboxes TO root`, `GRANT SELECT ON settings TO root`, `GRANT SELECT (name) ON domains TO root`,
			`GRANT INSERT, DELETE ON mail_log TO root`, `GRANT USAGE ON SEQUENCE mail_log_id_seq TO root`},
	}
	for role, qs := range grants {
		var ok bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			continue
		}
		for _, q := range qs {
			if _, err := s.db.Exec(ctx, q); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
	}
	return nil
}
