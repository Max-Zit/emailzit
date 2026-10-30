package web

import (
	"context"
	"time"

	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/store"
)

// HelperMail applies mail changes through the root mail helper.
type HelperMail struct{ C *mailhelper.Client }

// Apply writes the server-wide configuration.
func (h *HelperMail) Apply(ctx context.Context, m MailSettings) error {
	req := mailhelper.Request{Action: mailhelper.ActionApply, Hostname: m.Hostname, MaxMessageMB: m.MaxMessageMB, ClamAV: m.ClamAV, IPv4Only: m.IPv4Only}
	if m.RelayHost != "" {
		relay, err := m.relay()
		if err != nil {
			return err
		}
		req.Relay = relay
		if m.RelayUser != "" && m.relayPassword != "" {
			req.RelayUser, req.RelayPassword = m.RelayUser, m.relayPassword
		}
	}
	return h.C.Call(ctx, req)
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

// DKIM installs the domain's signing key.
func (h *HelperMail) DKIM(ctx context.Context, k *store.DKIMKey) error {
	return h.C.Call(ctx, mailhelper.Request{Action: mailhelper.ActionDKIM, Domain: k.Domain, Selector: k.Selector, Key: k.Private})
}

// SyncMail gives the helper what only the panel has (the DKIM keys, sealed
// with the server key): at every start, for all domains.
func (s *Server) SyncMail(ctx context.Context) {
	defer s.publishAllDNS(ctx)
	if s.Mail == nil {
		return
	}
	// the helper may still be starting (both services start together)
	for i := 0; i < 30; i++ {
		if err := (&mailhelper.Client{Socket: mailhelper.Socket}).Call(ctx, mailhelper.Request{Action: mailhelper.ActionPing}); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	doms, err := s.store.Domains(ctx, store.Staff, "")
	if err != nil {
		s.log.Error("mail sync", "err", err)
		return
	}
	for _, d := range doms {
		s.installDKIM(ctx, d.ID)
	}
}

// installDKIM makes sure the domain has a key and the helper has it.
func (s *Server) installDKIM(ctx context.Context, domainID string) {
	k, err := s.store.EnsureDKIM(ctx, domainID)
	if err != nil {
		s.log.Error("DKIM key", "domain", domainID, "err", err)
		return
	}
	if s.Mail == nil {
		return
	}
	if err := s.Mail.DKIM(ctx, k); err != nil {
		s.log.Error("installing the DKIM key", "domain", k.Domain, "err", err)
	}
}
