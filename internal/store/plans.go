package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// The mail plans of a customer. A package is the plan of ONE mailbox
// (Stefan, 2026-11-14: mail is sold per mailbox, so one customer may hold
// three Mail 10, two Mail 100 and one Mail 25 at the same time).
// customer_packages says how many mailboxes of a plan the customer has;
// the customer's base package (customers.package_id) holds the limits of
// the whole customer and is the plan a new mailbox gets by default.

// maxPlanMailboxes is the largest number of mailboxes one plan can hold
// for a customer (the same ceiling the table checks).
const maxPlanMailboxes = 100000

// CustomerPackage is one plan of a customer.
type CustomerPackage struct {
	Package   *Package
	Mailboxes int // how many mailboxes of the plan the customer has
	Used      int // how many of them exist
}

// Free is how many mailboxes of the plan can still be made.
func (c *CustomerPackage) Free() int { return max(c.Mailboxes-c.Used, 0) }

// CustomerPackages lists the plans of a customer, the smallest mailbox
// first.
func (s *Store) CustomerPackages(ctx context.Context, sc Scope, customerID string) ([]*CustomerPackage, error) {
	if sc.IsCustomer() {
		customerID = sc.CustomerID
	}
	if !ValidID(customerID) {
		return nil, ErrNotFound
	}
	rows, err := s.db.Query(ctx, `SELECT `+packageCols+`, cp.mailboxes,
			(SELECT count(*) FROM mailboxes m WHERE m.customer_id = cp.customer_id AND m.package_id = cp.package_id)
		FROM customer_packages cp JOIN packages p ON p.id = cp.package_id
		WHERE cp.customer_id = $1 ORDER BY p.mailbox_mb, lower(p.name)`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CustomerPackage
	for rows.Next() {
		cp := &CustomerPackage{}
		p, err := scanPackage(rows, &cp.Mailboxes, &cp.Used)
		if err != nil {
			return nil, err
		}
		cp.Package = p
		out = append(out, cp)
	}
	return out, rows.Err()
}

// SetCustomerPackageCount sets how many mailboxes of one plan the customer
// has; 0 removes the plan. Fewer than the mailboxes that already exist on
// the plan is refused.
func (s *Store) SetCustomerPackageCount(ctx context.Context, customerID string, packageID int64, n int) error {
	if n < 0 || n > maxPlanMailboxes {
		return fmt.Errorf("the number of mailboxes must be 0–%d", maxPlanMailboxes)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setPlanCount(ctx, tx, customerID, packageID, n); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReplaceCustomerPackages sets all plans of a customer at once (the
// billing system sends what the customer ordered). A plan that is left
// out is removed, which only works while no mailbox uses it.
func (s *Store) ReplaceCustomerPackages(ctx context.Context, customerID string, counts map[int64]int) error {
	for _, n := range counts {
		if n < 0 || n > maxPlanMailboxes {
			return fmt.Errorf("the number of mailboxes must be 0–%d", maxPlanMailboxes)
		}
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var have []int64
	rows, err := tx.Query(ctx, `SELECT package_id FROM customer_packages WHERE customer_id=$1`, customerID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		have = append(have, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range have {
		if _, ok := counts[id]; !ok {
			counts[id] = 0 // left out: remove the plan
		}
	}
	for id, n := range counts {
		if err := setPlanCount(ctx, tx, customerID, id, n); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// setPlanCount writes one plan count inside a transaction.
func setPlanCount(ctx context.Context, tx pgx.Tx, customerID string, packageID int64, n int) error {
	if !ValidID(customerID) {
		return ErrNotFound
	}
	var name string
	var used int
	err := tx.QueryRow(ctx, `SELECT p.name, (SELECT count(*) FROM mailboxes m WHERE m.customer_id=$2 AND m.package_id=p.id)
		FROM packages p WHERE p.id=$1`, packageID, customerID).Scan(&name, &used)
	if err != nil {
		return notFound(err)
	}
	if n < used {
		return fmt.Errorf("the customer has %d mailboxes of the plan %s; delete some first", used, name)
	}
	if n == 0 {
		_, err = tx.Exec(ctx, `DELETE FROM customer_packages WHERE customer_id=$1 AND package_id=$2`, customerID, packageID)
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO customer_packages(customer_id, package_id, mailboxes) VALUES($1,$2,$3)
		ON CONFLICT (customer_id, package_id) DO UPDATE SET mailboxes=EXCLUDED.mailboxes`, customerID, packageID, n)
	if isFK(err) {
		return ErrNotFound
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// mailboxPlan is the plan a mailbox gets (base when none is chosen) and
// checks that the customer has a free mailbox of it. Called inside the
// transaction that creates or moves the mailbox; skip is a mailbox that
// already uses the plan (moving it keeps its place).
func mailboxPlan(ctx context.Context, tx pgx.Tx, customerID string, base *Package, want int64, skip string) (*Package, error) {
	p := base
	if want != 0 && want != base.ID {
		var err error
		if p, err = scanPackage(tx.QueryRow(ctx, `SELECT `+packageCols+` FROM packages p WHERE p.id=$1`, want)); err != nil {
			return nil, errors.New("unknown plan")
		}
	}
	var paid, used int
	err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT mailboxes FROM customer_packages WHERE customer_id=$1 AND package_id=$2), 0),
		(SELECT count(*) FROM mailboxes WHERE customer_id=$1 AND package_id=$2 AND ($3 = '' OR id::text <> $3))`,
		customerID, p.ID, skip).Scan(&paid, &used)
	if err != nil {
		return nil, err
	}
	if used >= paid {
		return nil, fmt.Errorf("%w: the customer has %d mailboxes of the plan %s", ErrLimit, paid, p.Name)
	}
	return p, nil
}
