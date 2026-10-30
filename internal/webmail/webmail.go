// Package webmail is the mail side of EmailZit's own webmail: it reads the
// user's mailbox over IMAP and sends over SMTP submission, both on the
// server itself, signed in with a short-lived webmail token (Dovecot accepts
// such tokens only from the loopback interface). So the webmail has exactly
// the rights of the mail user: Dovecot's per-customer system users, quotas,
// sending limits and DKIM signing all apply as for any mail program.
package webmail

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
)

func init() {
	// decode the usual legacy charsets of mail (ISO-8859-x, Windows-125x …)
	imap.CharsetReader = charset.Reader
}

// Limits.
const (
	PageSize       = 50
	MaxMessageSize = 30 << 20 // bigger messages are not opened in the webmail
)

// Session is one webmail request's connection.
type Session struct {
	c *client.Client
	// Address and Token sign in; IMAP and SMTP are the loopback addresses.
	Address string
	token   string
	smtp    string
}

// Open connects to Dovecot on the server itself and signs in.
func Open(imapAddr, smtpAddr, address, token string) (*Session, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := client.DialWithDialer(d, imapAddr)
	if err != nil {
		return nil, fmt.Errorf("the mail server is not reachable: %w", err)
	}
	c.Timeout = 60 * time.Second
	if err := c.Login(address, token); err != nil {
		_ = c.Logout()
		return nil, ErrSignIn
	}
	return &Session{c: c, Address: address, token: token, smtp: smtpAddr}, nil
}

// ErrSignIn means the webmail token was not accepted (expired, mailbox
// disabled): the user has to sign in again.
var ErrSignIn = errors.New("webmail sign-in refused")

// Close ends the connection.
func (s *Session) Close() { _ = s.c.Logout() }

// Folder is a mailbox folder.
type Folder struct {
	Name    string
	Special string // \Sent, \Trash …
	Unseen  uint32
	Total   uint32
}

// Label is the folder's name for display (top folders by role).
func (f Folder) Label() string { return f.Name }

var specialOrder = map[string]int{"": 9, `\Drafts`: 2, `\Sent`: 3, `\Archive`: 4, `\Junk`: 5, `\Trash`: 6}

// Folders lists the folders with their counts, INBOX first.
func (s *Session) Folders() ([]Folder, error) {
	ch := make(chan *imap.MailboxInfo, 50)
	done := make(chan error, 1)
	go func() { done <- s.c.List("", "*", ch) }()
	var out []Folder
	for m := range ch {
		if hasAttr(m.Attributes, imap.NoSelectAttr) {
			continue
		}
		f := Folder{Name: m.Name}
		for _, a := range m.Attributes {
			switch a {
			case imap.SentAttr, imap.TrashAttr, imap.JunkAttr, imap.DraftsAttr, imap.ArchiveAttr:
				f.Special = a
			}
		}
		out = append(out, f)
	}
	if err := <-done; err != nil {
		return nil, err
	}
	for i := range out {
		st, err := s.c.Status(out[i].Name, []imap.StatusItem{imap.StatusMessages, imap.StatusUnseen})
		if err == nil {
			out[i].Total, out[i].Unseen = st.Messages, st.Unseen
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name == "INBOX" || out[j].Name == "INBOX" {
			return out[i].Name == "INBOX"
		}
		oi, oj := specialOrder[out[i].Special], specialOrder[out[j].Special]
		if oi != oj {
			return oi < oj
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// FolderByRole finds the folder of a special use (\Sent, \Trash …).
func (s *Session) FolderByRole(role, fallback string) string {
	fs, err := s.Folders()
	if err == nil {
		for _, f := range fs {
			if f.Special == role {
				return f.Name
			}
		}
	}
	return fallback
}

func hasAttr(list []string, a string) bool {
	for _, x := range list {
		if strings.EqualFold(x, a) {
			return true
		}
	}
	return false
}

// Summary is a line of the message list.
type Summary struct {
	UID      uint32
	From     string
	To       string
	Subject  string
	Date     time.Time
	Seen     bool
	Flagged  bool
	Answered bool
	Size     uint32
}

// List returns a page of the folder, newest first; query searches the text.
func (s *Session) List(folder string, page int, query string) ([]Summary, int, error) {
	if _, err := s.c.Select(folder, true); err != nil {
		return nil, 0, err
	}
	crit := imap.NewSearchCriteria()
	if q := strings.TrimSpace(query); q != "" {
		crit.Text = []string{q}
	}
	uids, err := s.c.UidSearch(crit)
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
	total := len(uids)
	if page < 1 {
		page = 1
	}
	from := (page - 1) * PageSize
	if from >= total {
		return nil, total, nil
	}
	to := min(from+PageSize, total)
	set := new(imap.SeqSet)
	set.AddNum(uids[from:to]...)
	ch := make(chan *imap.Message, PageSize)
	done := make(chan error, 1)
	go func() {
		done <- s.c.UidFetch(set, []imap.FetchItem{imap.FetchUid, imap.FetchEnvelope, imap.FetchFlags, imap.FetchRFC822Size, imap.FetchInternalDate}, ch)
	}()
	var out []Summary
	for m := range ch {
		sm := Summary{UID: m.Uid, Size: m.Size, Date: m.InternalDate}
		if e := m.Envelope; e != nil {
			sm.Subject = decodeHeader(e.Subject)
			sm.From = addrList(e.From)
			sm.To = addrList(e.To)
			if !e.Date.IsZero() {
				sm.Date = e.Date
			}
		}
		for _, f := range m.Flags {
			switch f {
			case imap.SeenFlag:
				sm.Seen = true
			case imap.FlaggedFlag:
				sm.Flagged = true
			case imap.AnsweredFlag:
				sm.Answered = true
			}
		}
		out = append(out, sm)
	}
	if err := <-done; err != nil {
		return nil, 0, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID > out[j].UID })
	return out, total, nil
}

func decodeHeader(v string) string {
	d, err := (&mime.WordDecoder{CharsetReader: charset.Reader}).DecodeHeader(v)
	if err != nil {
		return v
	}
	return d
}

func addrList(l []*imap.Address) string {
	var parts []string
	for _, a := range l {
		if a == nil {
			continue
		}
		name := decodeHeader(a.PersonalName)
		addr := a.Address()
		if name != "" && name != addr {
			parts = append(parts, name+" <"+addr+">")
		} else {
			parts = append(parts, addr)
		}
	}
	return strings.Join(parts, ", ")
}

// Attachment is a part of a message that is offered for download.
type Attachment struct {
	Index int
	Name  string
	Type  string
	Size  int
	CID   string // Content-ID of an inline part (images in HTML)
	data  []byte
}

// Message is an opened message.
type Message struct {
	UID         uint32
	From, To    string
	Cc, ReplyTo string
	Subject     string
	Date        time.Time
	MessageID   string
	References  string
	Text        string
	HTML        string
	Attachments []*Attachment
	Seen        bool
}

// Get opens a message (and marks it as read).
func (s *Session) Get(folder string, uid uint32) (*Message, error) {
	if _, err := s.c.Select(folder, false); err != nil {
		return nil, err
	}
	set := new(imap.SeqSet)
	set.AddNum(uid)
	section := &imap.BodySectionName{}
	ch := make(chan *imap.Message, 1)
	done := make(chan error, 1)
	go func() {
		done <- s.c.UidFetch(set, []imap.FetchItem{imap.FetchUid, imap.FetchRFC822Size, imap.FetchFlags, section.FetchItem()}, ch)
	}()
	var raw []byte
	var size uint32
	for m := range ch {
		size = m.Size
		if r := m.GetBody(section); r != nil {
			raw, _ = io.ReadAll(io.LimitReader(r, MaxMessageSize+1))
		}
	}
	if err := <-done; err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, ErrNotFound
	}
	if size > MaxMessageSize || len(raw) > MaxMessageSize {
		return nil, ErrTooBig
	}
	msg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	msg.UID = uid
	return msg, nil
}

// Errors of Get.
var (
	ErrNotFound = errors.New("the message does not exist (any more)")
	ErrTooBig   = errors.New("the message is too big for the webmail; open it in a mail program")
)

// Parse reads a raw message into its text, HTML and attachments.
func Parse(raw []byte) (*Message, error) {
	r, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && r == nil {
		return nil, err
	}
	h := r.Header
	m := &Message{}
	m.Subject, _ = h.Subject()
	m.Date, _ = h.Date()
	m.MessageID, _ = h.MessageID()
	m.References = h.Get("References")
	for _, f := range []struct {
		key string
		dst *string
	}{{"From", &m.From}, {"To", &m.To}, {"Cc", &m.Cc}, {"Reply-To", &m.ReplyTo}} {
		if l, err := h.AddressList(f.key); err == nil {
			var parts []string
			for _, a := range l {
				parts = append(parts, a.String())
			}
			*f.dst = strings.Join(parts, ", ")
		} else {
			*f.dst = h.Get(f.key)
		}
	}
	for i := 0; i < 500; i++ {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if message.IsUnknownCharset(err) {
				continue
			}
			break
		}
		body, _ := io.ReadAll(io.LimitReader(p.Body, MaxMessageSize))
		switch ph := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := ph.ContentType()
			switch {
			case ct == "text/plain" && m.Text == "":
				m.Text = string(body)
			case ct == "text/html" && m.HTML == "":
				m.HTML = string(body)
			default:
				name := ct
				m.Attachments = append(m.Attachments, &Attachment{Index: len(m.Attachments), Name: name, Type: ct, Size: len(body), data: body,
					CID: strings.Trim(ph.Get("Content-Id"), "<>")})
			}
		case *mail.AttachmentHeader:
			name, _ := ph.Filename()
			ct, _, _ := ph.ContentType()
			if name == "" {
				name = "attachment"
			}
			m.Attachments = append(m.Attachments, &Attachment{Index: len(m.Attachments), Name: name, Type: ct, Size: len(body), data: body})
		}
	}
	return m, nil
}

// Part returns the data of an attachment.
func (a *Attachment) Data() []byte { return a.data }

// Move moves messages to another folder (delete = move to Trash).
func (s *Session) Move(folder string, uids []uint32, dest string) error {
	if len(uids) == 0 || dest == folder {
		return nil
	}
	if _, err := s.c.Select(folder, false); err != nil {
		return err
	}
	set := new(imap.SeqSet)
	set.AddNum(uids...)
	if err := s.c.UidCopy(set, dest); err != nil {
		return err
	}
	return s.expunge(set)
}

// Delete removes messages for good (in the Trash).
func (s *Session) Delete(folder string, uids []uint32) error {
	if len(uids) == 0 {
		return nil
	}
	if _, err := s.c.Select(folder, false); err != nil {
		return err
	}
	set := new(imap.SeqSet)
	set.AddNum(uids...)
	return s.expunge(set)
}

func (s *Session) expunge(set *imap.SeqSet) error {
	if err := s.c.UidStore(set, imap.FormatFlagsOp(imap.AddFlags, true), []interface{}{imap.DeletedFlag}, nil); err != nil {
		return err
	}
	return s.c.Expunge(nil)
}

// SetSeen marks messages as read or unread.
func (s *Session) SetSeen(folder string, uids []uint32, seen bool) error {
	if len(uids) == 0 {
		return nil
	}
	if _, err := s.c.Select(folder, false); err != nil {
		return err
	}
	set := new(imap.SeqSet)
	set.AddNum(uids...)
	op := imap.FlagsOp(imap.AddFlags)
	if !seen {
		op = imap.RemoveFlags
	}
	return s.c.UidStore(set, imap.FormatFlagsOp(op, true), []interface{}{imap.SeenFlag}, nil)
}

// Append stores a message in a folder (Sent, Drafts).
func (s *Session) Append(folder string, raw []byte, flags []string) error {
	return s.c.Append(folder, flags, time.Now(), bytes.NewReader(raw))
}

// Send hands a message to the submission service on the server itself:
// the same sending limits, sender checks and DKIM signing as for a mail
// program apply.
func (s *Session) Send(from string, rcpts []string, raw []byte) error {
	host, _, _ := net.SplitHostPort(s.smtp)
	d := &net.Dialer{Timeout: 10 * time.Second}
	// #nosec G402 -- loopback connection to the server's own submission port
	conn, err := tls.DialWithDialer(d, "tcp", s.smtp, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		return fmt.Errorf("the mail server is not reachable: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Auth(smtp.PlainAuth("", s.Address, s.token, host)); err != nil {
		return ErrSignIn
	}
	if err := c.Mail(from); err != nil {
		return smtpErr(err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return smtpErr(err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpErr(err)
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return smtpErr(err)
	}
	return c.Quit()
}

// SendError is a refusal of the mail server, shown to the user.
type SendError struct{ Msg string }

func (e *SendError) Error() string { return e.Msg }

func smtpErr(err error) error {
	msg := err.Error()
	// "450 4.7.1 <x>: Recipient address rejected: Sending limit reached …"
	if i := strings.LastIndex(msg, ": "); i > 0 && i+2 < len(msg) {
		msg = msg[i+2:]
	}
	return &SendError{Msg: msg}
}
