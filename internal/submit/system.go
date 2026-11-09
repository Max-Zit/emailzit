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
	if len(to) == 0 {
		return errors.New("no recipient")
	}
	for _, a := range to {
		if strings.ContainsAny(a, "\r\n<>, ") || !strings.Contains(a, "@") {
			return fmt.Errorf("invalid recipient %q", a)
		}
	}
	if strings.ContainsAny(host, "\r\n<> ") {
		return errors.New("invalid host name")
	}
	from := "postmaster@" + host
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: EmailZit <%s>\nTo: %s\nSubject: %s\nDate: %s\nMessage-ID: <%d.notice@%s>\nAuto-Submitted: auto-generated\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n",
		from, strings.Join(to, ", "), mime.QEncoding.Encode("utf-8", strings.ReplaceAll(subject, "\n", " ")), time.Now().Format(time.RFC1123Z), time.Now().UnixNano(), host)
	b.WriteString(strings.ReplaceAll(body, "\r", ""))
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
	_, err := injectAs(ctx, dial, host, SystemLogin, from, &prepared{from: from, rcpts: to, data: b.Bytes()})
	return err
}
