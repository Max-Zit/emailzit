package web

import (
	"context"

	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/store"
)

// HelperMail applies mail changes through the root mail helper.
type HelperMail struct{ C *mailhelper.Client }

// Apply writes the server-wide configuration.
func (h *HelperMail) Apply(ctx context.Context, m MailSettings) error {
	return h.C.Call(ctx, mailhelper.Request{Action: mailhelper.ActionApply, Hostname: m.Hostname, MaxMessageMB: m.MaxMessageMB})
}

// CustomerCreated makes the customer's mail directory.
func (h *HelperMail) CustomerCreated(ctx context.Context, c *store.Customer) error {
	return h.C.Call(ctx, mailhelper.Request{Action: mailhelper.ActionCustomer, Customer: c.ID, UID: c.UID()})
}

// DomainDeleted moves the domain's mail to the trash.
func (h *HelperMail) DomainDeleted(ctx context.Context, d *store.Domain) error {
	return h.C.Call(ctx, mailhelper.Request{Action: mailhelper.ActionTrash, Customer: d.CustomerID, Domain: d.Name})
}

// MailboxDeleted moves the mailbox's mail to the trash.
func (h *HelperMail) MailboxDeleted(ctx context.Context, m *store.Mailbox) error {
	_, dom, _ := cutAt(m.Address)
	return h.C.Call(ctx, mailhelper.Request{Action: mailhelper.ActionTrash, Customer: m.CustomerID, Domain: dom, Local: m.LocalPart})
}

func cutAt(a string) (string, string, bool) {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] == '@' {
			return a[:i], a[i+1:], true
		}
	}
	return a, "", false
}
