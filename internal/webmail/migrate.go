package webmail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// Moving mail from another server: every folder of the old mailbox is
// copied into the mailbox on this server (same folder names, the special
// folders mapped by their role), with flags and dates. Messages that are
// already there (same Message-ID) are skipped, so an import can run again
// after a change of the MX record to pick up what came late.

// Source is the old mailbox.
type Source struct {
	Host     string
	Port     int // 993 (TLS) or 143 (STARTTLS)
	Insecure bool
	User     string
	Password string
}

// Progress is called after every folder and every batch.
type Progress func(folders, copied, skipped int)

// ErrPrivate refuses old servers inside private networks (the panel must
// not be usable to probe the networks around it).
var ErrPrivate = errors.New("the old server has a private or local address; only servers on the internet can be imported from")

// dialSource connects to the old server; it must have a public address.
func dialSource(ctx context.Context, src Source, allowPrivate bool) (*client.Client, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", src.Host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("the name of the old server cannot be found")
	}
	ip := ips[0].Unmap()
	for _, a := range ips {
		a = a.Unmap()
		if !allowPrivate && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)) {
			return nil, ErrPrivate
		}
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(src.Port))
	// #nosec G402 -- only when the administrator says the old server has its own certificate
	cfg := &tls.Config{ServerName: src.Host, InsecureSkipVerify: src.Insecure, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: 20 * time.Second}
	var c *client.Client
	if src.Port == 993 {
		c, err = client.DialWithDialerTLS(d, addr, cfg)
	} else {
		c, err = client.DialWithDialer(d, addr)
		if err == nil {
			if err = c.StartTLS(cfg); err != nil {
				_ = c.Logout()
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("the old server is not reachable over TLS: %w", err)
	}
	c.Timeout = 2 * time.Minute
	if err := c.Login(src.User, src.Password); err != nil {
		_ = c.Logout()
		return nil, errors.New("the old server refused the user name or password")
	}
	return c, nil
}

// Migrate copies the old mailbox into s.
func (s *Session) Migrate(ctx context.Context, src Source, allowPrivate bool, progress Progress) error {
	old, err := dialSource(ctx, src, allowPrivate)
	if err != nil {
		return err
	}
	defer func() { _ = old.Logout() }()
	ch := make(chan *imap.MailboxInfo, 100)
	done := make(chan error, 1)
	go func() { done <- old.List("", "*", ch) }()
	var folders []*imap.MailboxInfo
	for m := range ch {
		if !hasAttr(m.Attributes, imap.NoSelectAttr) {
			folders = append(folders, m)
		}
	}
	if err := <-done; err != nil {
		return err
	}
	roles := map[string]string{}
	if mine, err := s.Folders(); err == nil {
		for _, f := range mine {
			if f.Special != "" {
				roles[f.Special] = f.Name
			}
		}
	}
	var nf, copied, skipped int
	for _, f := range folders {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dest := targetFolder(f, old.Mailbox(), roles)
		c, sk, err := s.copyFolder(ctx, old, f.Name, dest, progress, nf, copied, skipped)
		copied, skipped = copied+c, skipped+sk
		if err != nil {
			return fmt.Errorf("folder %s: %w", f.Name, err)
		}
		nf++
		progress(nf, copied, skipped)
	}
	return nil
}

// targetFolder maps a folder of the old server to one here.
func targetFolder(f *imap.MailboxInfo, _ *imap.MailboxStatus, roles map[string]string) string {
	if strings.EqualFold(f.Name, "INBOX") {
		return "INBOX"
	}
	for _, a := range f.Attributes {
		if t, ok := roles[a]; ok {
			return t
		}
	}
	name := f.Name
	if f.Delimiter != "" && f.Delimiter != "/" {
		name = strings.ReplaceAll(name, f.Delimiter, "/")
	}
	// common names of special folders on servers without SPECIAL-USE
	switch strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(name, "INBOX/"), "INBOX.")) {
	case "sent", "sent items", "sent messages", "poslato":
		if t, ok := roles[imap.SentAttr]; ok {
			return t
		}
	case "trash", "deleted items", "deleted messages":
		if t, ok := roles[imap.TrashAttr]; ok {
			return t
		}
	case "junk", "spam", "junk e-mail":
		if t, ok := roles[imap.JunkAttr]; ok {
			return t
		}
	case "drafts":
		if t, ok := roles[imap.DraftsAttr]; ok {
			return t
		}
	}
	return name
}

func (s *Session) copyFolder(ctx context.Context, old *client.Client, from, to string, progress Progress, nf, copiedBefore, skippedBefore int) (int, int, error) {
	st, err := old.Select(from, true)
	if err != nil {
		return 0, 0, err
	}
	if st.Messages == 0 {
		return 0, 0, nil
	}
	_ = s.c.Create(to) // exists already, or created now
	have, err := s.messageIDs(to)
	if err != nil {
		return 0, 0, err
	}
	var copied, skipped int
	const batch = 50
	for start := uint32(1); start <= st.Messages; start += batch {
		if ctx.Err() != nil {
			return copied, skipped, ctx.Err()
		}
		end := min(start+batch-1, st.Messages)
		set := new(imap.SeqSet)
		set.AddRange(start, end)
		section := &imap.BodySectionName{Peek: true}
		ch := make(chan *imap.Message, batch)
		done := make(chan error, 1)
		go func() {
			done <- old.Fetch(set, []imap.FetchItem{imap.FetchFlags, imap.FetchInternalDate, imap.FetchEnvelope, imap.FetchRFC822Size, section.FetchItem()}, ch)
		}()
		type msg struct {
			flags []string
			date  time.Time
			raw   []byte
		}
		var list []msg
		for m := range ch {
			id := msgKey(m)
			if id != "" && have[id] {
				skipped++
				continue
			}
			r := m.GetBody(section)
			if r == nil || m.Size > MaxImportSize {
				skipped++
				continue
			}
			raw, _ := io.ReadAll(io.LimitReader(r, MaxImportSize))
			var flags []string
			for _, f := range m.Flags {
				if f != imap.RecentFlag {
					flags = append(flags, f)
				}
			}
			list = append(list, msg{flags, m.InternalDate, raw})
			if id != "" {
				have[id] = true
			}
		}
		if err := <-done; err != nil {
			return copied, skipped, err
		}
		for _, m := range list {
			if err := s.c.Append(to, m.flags, m.date, bytes.NewReader(m.raw)); err != nil {
				if strings.Contains(strings.ToUpper(err.Error()), "QUOTA") {
					return copied, skipped, errors.New("the mailbox is full; give it more space and start the import again (what is copied stays)")
				}
				return copied, skipped, err
			}
			copied++
		}
		progress(nf, copiedBefore+copied, skippedBefore+skipped)
	}
	return copied, skipped, nil
}

// MaxImportSize is the largest message copied (bigger ones are skipped).
const MaxImportSize = 50 << 20

// messageIDs lists the Message-IDs of a folder here.
func (s *Session) messageIDs(folder string) (map[string]bool, error) {
	out := map[string]bool{}
	st, err := s.c.Select(folder, true)
	if err != nil {
		return out, nil // new folder
	}
	if st.Messages == 0 {
		return out, nil
	}
	set := new(imap.SeqSet)
	set.AddRange(1, st.Messages)
	ch := make(chan *imap.Message, 100)
	done := make(chan error, 1)
	go func() { done <- s.c.Fetch(set, []imap.FetchItem{imap.FetchEnvelope, imap.FetchRFC822Size}, ch) }()
	for m := range ch {
		if k := msgKey(m); k != "" {
			out[k] = true
		}
	}
	return out, <-done
}

// msgKey identifies a message for skipping duplicates: its Message-ID, or
// for messages without one the date, sender, subject and size together.
func msgKey(m *imap.Message) string {
	if m.Envelope == nil {
		return ""
	}
	if m.Envelope.MessageId != "" {
		return m.Envelope.MessageId
	}
	from := ""
	if len(m.Envelope.From) > 0 && m.Envelope.From[0] != nil {
		from = m.Envelope.From[0].Address()
	}
	return fmt.Sprintf("x:%d|%s|%s|%d", m.Envelope.Date.Unix(), from, m.Envelope.Subject, m.Size)
}
