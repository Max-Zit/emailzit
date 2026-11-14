package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/mailconf"
	"github.com/max-zit/emailzit/internal/store"
)

// Protection of the server's reputation: outgoing spam blocks the mailbox
// automatically, the administrators get notices (block, block lists) and a
// weekly report, and customers can send from their own addresses.

const (
	// SpamBlockThreshold refused outgoing messages (spam or virus) within
	// SpamBlockWindow block the mailbox's sending.
	SpamBlockThreshold = 3
	SpamBlockWindow    = time.Hour
	noticeReport       = "weekly-report"
	noticeBlocklist    = "blocklists"
)

// validateProtection checks the settings of this file.
func (m *MailSettings) validateProtection() error {
	var list []mailconf.OutboundIP
	for i := range m.OutboundIPs {
		o := &m.OutboundIPs[i]
		o.Address = strings.TrimSpace(o.Address)
		o.HELO = strings.ToLower(strings.TrimSpace(o.HELO))
		if a, err := netip.ParseAddr(o.Address); err == nil {
			o.Address = a.String()
		}
		list = append(list, mailconf.OutboundIP{Address: o.Address, HELO: o.HELO})
	}
	if len(list) > 0 {
		s := mailconf.Settings{Hostname: "mail.example.com", MaxMessageMB: 1, DBName: "x", CertFile: "/a", KeyFile: "/b", OutboundIPs: list}
		if err := s.Validate(); err != nil {
			return errors.New("each outbound address needs a valid IP address and a full host name (one per line: address host name)")
		}
	}
	to, err := noticeAddresses(m.NoticeTo)
	if err != nil {
		return err
	}
	m.NoticeTo = strings.Join(to, ", ")
	return nil
}

// parseOutboundIPs reads the form's lines "address host-name".
func (m *MailSettings) parseOutboundIPs(text string) error {
	m.OutboundIPs = nil
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		switch len(f) {
		case 0:
			continue
		case 2:
			m.OutboundIPs = append(m.OutboundIPs, OutboundAddr{Address: f[0], HELO: f[1]})
		default:
			return errors.New("each outbound address needs a valid IP address and a full host name (one per line: address host name)")
		}
	}
	return nil
}

// OutboundText is the form's text of the addresses.
func (m MailSettings) OutboundText() string {
	var b strings.Builder
	for _, o := range m.OutboundIPs {
		b.WriteString(o.Address + " " + o.HELO + "\n")
	}
	return b.String()
}

// OutboundAddress finds a configured address.
func (m MailSettings) OutboundAddress(ip string) (OutboundAddr, bool) {
	for _, o := range m.OutboundIPs {
		if o.Address == ip {
			return o, true
		}
	}
	return OutboundAddr{}, false
}

func noticeAddresses(s string) ([]string, error) {
	var out []string
	for _, a := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' }) {
		p, err := store.ParseAddress(a)
		if err != nil {
			return nil, errors.New("the address for notices is not valid")
		}
		out = append(out, p)
	}
	if len(out) > 5 {
		return nil, errors.New("at most five addresses for notices")
	}
	return out, nil
}

// SystemMailer sends a notice or a test message of the server (set by
// main; nil = none). With a domain the sender is postmaster of that
// domain, so the receiver sees its SPF, DKIM and DMARC; empty sends as
// the server itself.
type SystemMailer func(ctx context.Context, domain string, to []string, subject, body string) error

// notifyAdmins mails the administrators (Settings -> Mail server); without
// an address the notice is only logged.
func (s *Server) notifyAdmins(ctx context.Context, subject, body string) {
	m := s.MailConfig(ctx)
	to, _ := noticeAddresses(m.NoticeTo)
	if len(to) == 0 || s.SystemMail == nil {
		s.log.Info("notice for the administrators (no address set)", "subject", subject)
		return
	}
	host := m.Hostname
	if host == "" {
		host = "this server"
	}
	if err := s.SystemMail(ctx, "", to, "EmailZit "+host+": "+subject, body); err != nil {
		s.log.Warn("notice for the administrators", "subject", subject, "err", err)
	}
}

// RunProtection checks every five minutes for mailboxes sending spam,
// every six hours the block lists, and sends the weekly report on Monday
// morning.
func (s *Server) RunProtection(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		s.BlockSpamSenders(ctx)
		s.blocklistNotice(ctx)
		s.weeklyReport(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// BlockSpamSenders blocks the sending of mailboxes whose outgoing mail
// Rspamd refused SpamBlockThreshold times within the window: almost
// always a stolen password. The administrators and the mailbox are told.
func (s *Server) BlockSpamSenders(ctx context.Context) {
	list, err := s.store.OutboundSpamSenders(ctx, s.now().Add(-SpamBlockWindow), SpamBlockThreshold)
	if err != nil {
		s.log.Warn("outgoing spam check", "err", err)
		return
	}
	for _, x := range list {
		if err := s.store.BlockSending(ctx, x.MailboxID); err != nil {
			s.log.Warn("blocking a mailbox", "mailbox", x.Address, "err", err)
			continue
		}
		reason := fmt.Sprintf("%d outgoing messages refused as spam or virus within an hour", x.Messages)
		_ = s.store.Audit(ctx, "-", "local", "mailbox.send.blocked", "mailbox:"+x.Address, "sending blocked automatically: "+reason)
		s.log.Warn("sending blocked automatically", "mailbox", x.Address, "reason", reason)
		s.notifyAdmins(ctx, "sending of "+x.Address+" blocked",
			fmt.Sprintf("The mailbox %s sent spam or viruses: %s.\n\nIts sending is blocked; it still receives mail. This is usually a stolen password: set a new password for the mailbox (and its app passwords), check its forwarding rules, then lift the block on the mailbox's page (Sending: blocked).\n", x.Address, reason))
		if s.Mail != nil {
			_ = s.Mail.Notice(ctx, x.Address, translate(x.Lang, "Sending from your mailbox was stopped"),
				translate(x.Lang, "Messages sent from your mailbox were refused as spam or virus several times within an hour, so sending is stopped for now. You still receive mail.")+"\n\n"+
					translate(x.Lang, "This usually means someone else knows your password. Change it (and the passwords of your mail programs), and ask your provider to allow sending again.")+"\n")
		}
	}
}

// blocklistNotice checks the server's sending addresses on the DNS block
// lists every six hours and tells the administrators when a listing
// appears or goes away.
func (s *Server) blocklistNotice(ctx context.Context) {
	at, state, err := s.store.AdminNotice(ctx, noticeBlocklist)
	if err != nil || s.now().Sub(at) < 6*time.Hour {
		return
	}
	ips := s.sendingAddrs(ctx)
	if len(ips) == 0 {
		return
	}
	var listed []string
	for _, r := range checkBlacklists(ctx, ips) {
		if r.Listed {
			listed = append(listed, r.IP+" on "+r.List)
		}
	}
	sort.Strings(listed)
	now := strings.Join(listed, "; ")
	if err := s.store.SetAdminNotice(ctx, noticeBlocklist, now); err != nil {
		return
	}
	switch {
	case now != "" && now != state:
		s.notifyAdmins(ctx, "address on a block list",
			"An address this server sends from is on a DNS block list:\n\n  "+strings.ReplaceAll(now, "; ", "\n  ")+"\n\nMail from it is refused or lands in spam at many receivers. Find out who sent spam (Delivery log, outgoing; mailboxes blocked automatically are in the audit log), stop it, then ask the list to remove the address (each list has a removal page). Check the state under Mail queue -> Blacklists.\n")
	case now == "" && state != "":
		s.notifyAdmins(ctx, "block lists clear again", "No address of this server is on a checked block list any more.\n")
	}
}

// sendingAddrs are the public IPv4 addresses mail leaves from: those of
// the server and the extra outbound addresses.
func (s *Server) sendingAddrs(ctx context.Context) []netip.Addr {
	ips := publicAddrs()
	have := map[netip.Addr]bool{}
	for _, ip := range ips {
		have[ip] = true
	}
	for _, o := range s.MailConfig(ctx).OutboundIPs {
		if a, err := netip.ParseAddr(o.Address); err == nil && a.Is4() && !a.IsPrivate() && !have[a] {
			ips = append(ips, a)
			have[a] = true
		}
	}
	return ips
}

// weeklyReport sends the report once a week, on Monday after 7:00 (server
// time), about the seven days before.
func (s *Server) weeklyReport(ctx context.Context) {
	now := s.now()
	if now.Weekday() != time.Monday || now.Hour() < 7 {
		return
	}
	at, _, err := s.store.AdminNotice(ctx, noticeReport)
	if err != nil || now.Sub(at) < 24*time.Hour {
		return
	}
	if to, _ := noticeAddresses(s.MailConfig(ctx).NoticeTo); len(to) == 0 {
		return
	}
	body, err := s.reportText(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		s.log.Warn("weekly report", "err", err)
		return
	}
	if err := s.store.SetAdminNotice(ctx, noticeReport, ""); err != nil {
		return
	}
	s.notifyAdmins(ctx, "weekly report", body)
}

// reportText is the weekly report.
func (s *Server) reportText(ctx context.Context, since time.Time) (string, error) {
	st, err := s.store.MailStatsSince(ctx, since)
	if err != nil {
		return "", err
	}
	t, err := s.store.ServerTotals(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Mail of the last seven days (since %s):\n\n", since.Format("2006-01-02 15:04"))
	for _, l := range []struct {
		label string
		n     int
	}{{"received", st.Received}, {"sent to other servers", st.Sent}, {"deferred messages", st.Deferred}, {"bounced", st.Bounced},
		{"refused, incoming", st.RefusedIn}, {"refused, outgoing", st.RefusedOut}, {"  of them spam", st.Spam}, {"  viruses", st.Viruses},
		{"  risky attachments", st.Attachments}} {
		fmt.Fprintf(&b, "  %-24s %7d\n", l.label, l.n)
	}
	// mail of the websites of a linked HostZit on another server
	if sent, refused, err := s.store.RelayCounts(ctx, since); err == nil && sent+refused > 0 {
		fmt.Fprintf(&b, "  %-24s %7d\n", "from websites, taken", sent)
		fmt.Fprintf(&b, "  %-24s %7d\n", "from websites, refused", refused)
	}
	b.WriteString("\n")
	if len(st.TopSenders) > 0 {
		b.WriteString("Mailboxes that sent the most (recipients):\n\n")
		for _, x := range st.TopSenders {
			fmt.Fprintf(&b, "  %6d  %s\n", x.Count, x.Address)
		}
		b.WriteString("\n")
	}
	entries, err := s.store.AuditEntries(ctx, store.AuditFilter{Query: "sending blocked automatically", Limit: 200})
	var blocked []store.AuditEntry
	for _, e := range entries {
		if e.Action == "mailbox.send.blocked" && e.At.After(since) {
			blocked = append(blocked, e)
		}
	}
	if err == nil && len(blocked) > 0 {
		b.WriteString("Sending blocked automatically:\n\n")
		for _, e := range blocked {
			fmt.Fprintf(&b, "  %s  %s\n", e.At.Format("2006-01-02 15:04"), strings.TrimPrefix(e.Target, "mailbox:"))
		}
		b.WriteString("\n")
	}
	if ips := s.sendingAddrs(ctx); len(ips) > 0 {
		b.WriteString("Block lists:\n\n")
		for _, r := range checkBlacklists(ctx, ips) {
			state := "not listed"
			switch {
			case r.Listed:
				state = "LISTED"
			case r.Error:
				state = "not checked"
			}
			fmt.Fprintf(&b, "  %-15s %-24s %s\n", r.IP, r.List, state)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Server: %d customers, %d domains, %d mailboxes, %.1f GB used.\n", t.Customers, t.Domains, t.Mailboxes, float64(t.UsedBytes)/(1<<30))
	return b.String(), nil
}

// blocklistResolver asks the local resolver (Unbound on 127.0.0.1:5335)
// when it runs: block lists refuse queries from big public resolvers.
func blocklistResolver() *net.Resolver {
	c, err := net.DialTimeout("udp", "127.0.0.1:5335", time.Second)
	if err != nil {
		return net.DefaultResolver
	}
	_ = c.Close()
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "127.0.0.1:5335")
	}}
	if _, err := r.LookupHost(context.Background(), "localhost."); err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) {
			return net.DefaultResolver
		}
	}
	return r
}

// handleCustomerOutbound assigns an extra sending address to a customer.
func (s *Server) handleCustomerOutbound(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	to := "/customers/" + c.ID + "#outbound"
	ip := strings.TrimSpace(r.FormValue("outbound_ip"))
	if ip != "" {
		if _, ok := s.MailConfig(r.Context()).OutboundAddress(ip); !ok {
			s.redirectErr(w, r, to, "Unknown outbound address.")
			return
		}
	}
	if err := s.store.SetCustomerOutboundIP(r.Context(), c.ID, ip); err != nil {
		s.serverError(w, r, err)
		return
	}
	if ip == "" {
		s.audit(r, "customer.outbound_ip", "customer:"+c.ID, "sends from the server's address")
	} else {
		s.audit(r, "customer.outbound_ip", "customer:"+c.ID, "sends from %s", ip)
	}
	go s.publishAllDNS(context.WithoutCancel(r.Context()))
	s.redirect(w, r, to, "Saved. Update the SPF records of the customer's domains (shown on each domain's page).")
}
