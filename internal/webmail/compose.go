package webmail

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/mail"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"
)

// Draft is a message written in the webmail.
type Draft struct {
	FromName   string
	From       string
	To, Cc     string // comma-separated addresses
	Bcc        string
	Subject    string
	Text       string
	InReplyTo  string
	References string
	Files      []File
}

// File is an attachment to send.
type File struct {
	Name string
	Type string
	Data []byte
}

// MaxRecipients a webmail message may have (the package may allow fewer).
const MaxRecipients = 100

// ParseAddresses checks a comma-separated address list.
func ParseAddresses(list string) ([]*mail.Address, error) {
	list = strings.TrimSpace(list)
	if list == "" {
		return nil, nil
	}
	l, err := mail.ParseAddressList(list)
	if err != nil {
		return nil, errors.New("an address is not valid")
	}
	return l, nil
}

// Build makes the message and returns it with the envelope recipients.
func (d *Draft) Build(host string) ([]byte, []string, error) {
	to, err := ParseAddresses(d.To)
	if err != nil {
		return nil, nil, err
	}
	cc, err := ParseAddresses(d.Cc)
	if err != nil {
		return nil, nil, err
	}
	bcc, err := ParseAddresses(d.Bcc)
	if err != nil {
		return nil, nil, err
	}
	var rcpts []string
	for _, l := range [][]*mail.Address{to, cc, bcc} {
		for _, a := range l {
			rcpts = append(rcpts, a.Address)
		}
	}
	if len(rcpts) == 0 {
		return nil, nil, errors.New("add at least one recipient")
	}
	if len(rcpts) > MaxRecipients {
		return nil, nil, errors.New("too many recipients")
	}
	var h gomail.Header
	h.SetDate(time.Now())
	h.SetAddressList("From", []*gomail.Address{{Name: d.FromName, Address: d.From}})
	h.SetAddressList("To", conv(to))
	if len(cc) > 0 {
		h.SetAddressList("Cc", conv(cc))
	}
	h.SetSubject(strings.ReplaceAll(strings.ReplaceAll(d.Subject, "\r", ""), "\n", " "))
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	h.SetMessageID(hex.EncodeToString(rnd[:]) + "@" + host)
	if d.InReplyTo != "" {
		h.Set("In-Reply-To", "<"+strings.Trim(d.InReplyTo, "<> \r\n")+">")
	}
	if refs := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(d.References, "\r", ""), "\n", " ")); refs != "" {
		h.Set("References", refs)
	}
	h.Set("User-Agent", "EmailZit webmail")
	var buf bytes.Buffer
	text := strings.ReplaceAll(d.Text, "\r\n", "\n")
	if len(d.Files) == 0 {
		var th gomail.InlineHeader
		th.Set("Content-Type", "text/plain; charset=utf-8")
		w, err := gomail.CreateSingleInlineWriter(&buf, h)
		if err != nil {
			return nil, nil, err
		}
		_ = th
		if _, err := io.WriteString(w, text); err != nil {
			return nil, nil, err
		}
		if err := w.Close(); err != nil {
			return nil, nil, err
		}
		return buf.Bytes(), rcpts, nil
	}
	mw, err := gomail.CreateWriter(&buf, h)
	if err != nil {
		return nil, nil, err
	}
	var th gomail.InlineHeader
	th.Set("Content-Type", "text/plain; charset=utf-8")
	tw, err := mw.CreateSingleInline(th)
	if err != nil {
		return nil, nil, err
	}
	if _, err := io.WriteString(tw, text); err != nil {
		return nil, nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	for _, f := range d.Files {
		var ah gomail.AttachmentHeader
		ct := f.Type
		if ct == "" || strings.ContainsAny(ct, "\r\n;") {
			ct = "application/octet-stream"
		}
		ah.Set("Content-Type", ct)
		ah.SetFilename(f.Name)
		aw, err := mw.CreateAttachment(ah)
		if err != nil {
			return nil, nil, err
		}
		if _, err := aw.Write(f.Data); err != nil {
			return nil, nil, err
		}
		if err := aw.Close(); err != nil {
			return nil, nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), rcpts, nil
}

func conv(l []*mail.Address) []*gomail.Address {
	out := make([]*gomail.Address, 0, len(l))
	for _, a := range l {
		out = append(out, &gomail.Address{Name: a.Name, Address: a.Address})
	}
	return out
}

// Quote makes the body of a reply.
func Quote(m *Message) string {
	var b strings.Builder
	b.WriteString("\n\n")
	b.WriteString(m.Date.Format("2006-01-02 15:04") + ", " + m.From + ":\n")
	for _, l := range strings.Split(strings.ReplaceAll(m.Body(), "\r\n", "\n"), "\n") {
		b.WriteString("> " + l + "\n")
	}
	return b.String()
}

// Body is the text of a message (the HTML part reduced to text when there
// is no text part).
func (m *Message) Body() string {
	if m.Text != "" {
		return m.Text
	}
	return HTMLToText(m.HTML)
}
