package submit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"net"
	"strings"
	"time"
)

// SystemLogin names EmailZit's own notices in the delivery log.
const SystemLogin = "emailzit-system"

// SendSystem sends a plain-text notice of the server itself (to the
// administrators) through the same Postfix service as mail from websites.
// The sender is postmaster@<host name>.
func SendSystem(ctx context.Context, dial func(context.Context) (net.Conn, error), host string, to []string, subject, body string) error {
	return SendAs(ctx, dial, host, "", to, subject, body)
}

// SendAs is SendSystem with the sender in one of the server's own domains
// (postmaster@<domain>), so the receiver sees the SPF, DKIM and DMARC of
// that domain. An empty domain sends as the server itself.
func SendAs(ctx context.Context, dial func(context.Context) (net.Conn, error), host, domain string, to []string, subject, body string) error {
	if len(to) == 0 {
		return errors.New("no recipient")
	}
	if domain != "" && (strings.ContainsAny(domain, "\r\n<>, @") || !strings.Contains(domain, ".")) {
		return fmt.Errorf("invalid domain %q", domain)
	}
	for _, a := range to {
		if strings.ContainsAny(a, "\r\n<>, ") || !strings.Contains(a, "@") {
			return fmt.Errorf("invalid recipient %q", a)
		}
	}
	if strings.ContainsAny(host, "\r\n<> ") {
		return errors.New("invalid host name")
	}
	from, data := systemMessage(host, domain, to, subject, body)
	_, err := injectAs(ctx, dial, host, SystemLogin, from, &prepared{from: from, rcpts: to, data: data})
	return err
}

// systemMessage builds the message: the sender is the postmaster of the
// domain when one is given, otherwise of the server itself.
func systemMessage(host, domain string, to []string, subject, body string) (from string, data []byte) {
	from = "postmaster@" + host
	if domain != "" {
		from = "postmaster@" + domain
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: EmailZit <%s>\nTo: %s\nSubject: %s\nDate: %s\nMessage-ID: <%d.notice@%s>\nAuto-Submitted: auto-generated\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n",
		from, strings.Join(to, ", "), mime.QEncoding.Encode("utf-8", strings.ReplaceAll(subject, "\n", " ")), time.Now().Format(time.RFC1123Z), time.Now().UnixNano(), host)
	b.WriteString(strings.ReplaceAll(body, "\r", ""))
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
	return from, b.Bytes()
}
