package submit

import (
	"context"
	"net"
	"strings"
	"testing"
)

// A test message of a domain is sent as the postmaster of that domain, so
// the receiver sees the domain's own SPF, DKIM and DMARC. Without a domain
// the server sends as itself.
func TestSystemMessageSender(t *testing.T) {
	for _, c := range []struct{ domain, want string }{
		{"", "postmaster@mail.example.test"},
		{"shop.test", "postmaster@shop.test"},
	} {
		from, data := systemMessage("mail.example.test", c.domain, []string{"someone@example.org"}, "Test", "Body")
		if from != c.want {
			t.Errorf("domain %q: sender %q, want %q", c.domain, from, c.want)
		}
		head := string(data)
		if !strings.Contains(head, "From: EmailZit <"+c.want+">") {
			t.Errorf("domain %q: the From header does not name %q:\n%s", c.domain, c.want, head)
		}
		if !strings.HasSuffix(head, "Body\n") {
			t.Errorf("domain %q: the body is missing or not closed:\n%s", c.domain, head)
		}
	}
}

// A domain that is not one cannot be smuggled into the sender.
func TestSendAsRefusesABadDomain(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) {
		t.Error("no connection expected")
		return nil, net.ErrClosed
	}
	for _, bad := range []string{"not a domain", "a@b.test", "x\r\nRCPT TO:<v@evil.test>", "local"} {
		if err := SendAs(context.Background(), dial, "mail.example.test", bad, []string{"a@b.test"}, "s", "b"); err == nil {
			t.Errorf("domain %q was accepted", bad)
		}
	}
}
