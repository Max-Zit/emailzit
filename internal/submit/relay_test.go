package submit

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/tlsutil"
)

// fakeRelayStore is the database of the relay in the tests. acme.test is a
// mail domain here, shop.test is hosted on HostZit (set by the test), and
// down.test cannot be asked about.
type fakeRelayStore struct {
	mu       sync.Mutex
	pass     string
	limits   store.SendLimits
	hour     int // recipients of an unknown customer's domain in the last hour
	sent     int
	log      []store.RelayMail
	touched  bool
	noLimits bool
}

func (f *fakeRelayStore) CheckRelayLogin(ctx context.Context, user, pass string) (string, error) {
	if user != "hostzit-relay@mail.test" || pass != f.pass {
		return "", store.ErrNotFound
	}
	return "relay-1", nil
}

func (f *fakeRelayStore) TouchRelayLogin(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = true
	return nil
}

func (f *fakeRelayStore) DomainCustomer(ctx context.Context, domain string) (string, error) {
	if domain == "acme.test" {
		return "cust-1", nil
	}
	return "", store.ErrNotFound
}

func (f *fakeRelayStore) RelayLimits(ctx context.Context, customerID string) (*store.SendLimits, error) {
	if f.noLimits {
		return nil, errors.New("database is away")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.limits
	l.CustomerID = customerID
	l.CustomerHour = f.sent
	return &l, nil
}

func (f *fakeRelayStore) RelayDomainHour(ctx context.Context, domain string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hour, nil
}

func (f *fakeRelayStore) LogRelaySent(ctx context.Context, customerID string, rcpts int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent += rcpts
	return nil
}

func (f *fakeRelayStore) LogRelay(ctx context.Context, m store.RelayMail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, m)
	return nil
}

func (f *fakeRelayStore) entries() []store.RelayMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.RelayMail(nil), f.log...)
}

// startRelay runs the relay on a loopback port and returns its address.
func startRelay(t *testing.T, f *fakeRelayStore, got chan<- string) string {
	return startRelayWith(t, f, got, 1<<20)
}

// startRelayWith also says how large a message may be.
func startRelayWith(t *testing.T, f *fakeRelayStore, got chan<- string, max int64) string {
	t.Helper()
	cert, err := tlsutil.LoadOrCreate(t.TempDir(), "panel", "EmailZit test", 1)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &RelayServer{Store: f, Log: slog.New(slog.DiscardHandler), TLS: tlsutil.ServerConfig(cert),
		Hostname: func(context.Context) string { return "mail.test" },
		MaxBytes: func(context.Context) int64 { return max },
		Dial:     fakePostfix(got),
		Hosted: func(_ context.Context, domain string) (string, bool, bool) {
			switch domain {
			case "shop.test":
				return "", true, false // hosted, but the customer is not in EmailZit
			case "down.test":
				return "", false, true // HostZit cannot be asked
			}
			return "", false, false
		},
	}
	go func() { _ = s.Serve(ctx, l) }()
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().String()
}

// signedIn returns a client that has signed in with the relay login.
func signedIn(t *testing.T, addr, pass string) *smtp.Client {
	t.Helper()
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true, ServerName: "mail.test"}); err != nil { // #nosec G402 -- our own test certificate
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(addr)
	if err := c.Auth(smtp.PlainAuth("", "hostzit-relay@mail.test", pass, host)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRelayTakesMailOfAHostedWebsite(t *testing.T) {
	f := &fakeRelayStore{pass: "s3cret", limits: store.SendLimits{CustomerPerHour: 100, RcptPerMsg: 10}}
	got := make(chan string, 4)
	addr := startRelay(t, f, got)
	c := signedIn(t, addr, "s3cret")
	if err := c.Mail("web@acme.test"); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"a@example.test", "b@example.test"} {
		if err := c.Rcpt(to); err != nil {
			t.Fatal(err)
		}
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("From: Shop <web@acme.test>\r\nSubject: Order\r\n\r\nThank you.\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("the message was not taken: %v", err)
	}
	_ = c.Quit()

	session := <-got
	for _, want := range []string{"XCLIENT LOGIN=relay", "MAIL FROM:<web@acme.test>", "RCPT TO:<a@example.test>", "Thank you."} {
		if !strings.Contains(session, want) {
			t.Errorf("Postfix did not see %q in:\n%s", want, session)
		}
	}
	if f.sent != 2 {
		t.Errorf("counted %d recipients, want 2", f.sent)
	}
	e := f.entries()
	if len(e) != 1 || e[0].Status != "sent" || e[0].CustomerID != "cust-1" || e[0].QueueID != "ABC123" || e[0].Rcpts != 2 {
		t.Errorf("the relay log holds %+v", e)
	}
	if !f.touched {
		t.Error("the last use of the login was not recorded")
	}
}

func TestRelayRefusesAForeignSenderAndAForeignFrom(t *testing.T) {
	f := &fakeRelayStore{pass: "s3cret", limits: store.SendLimits{CustomerPerHour: 100, RcptPerMsg: 10}}
	got := make(chan string, 4)
	addr := startRelay(t, f, got)
	c := signedIn(t, addr, "s3cret")

	// a domain nobody hosts
	err := c.Mail("someone@other.test")
	if err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("a foreign sender domain was answered with %v", err)
	}
	// HostZit cannot be asked: try again later, do not refuse for good
	if err := c.Mail("someone@down.test"); err == nil || !strings.Contains(err.Error(), "451") {
		t.Fatalf("an unreachable HostZit was answered with %v", err)
	}
	// a domain HostZit hosts, but the From header is of another domain
	if err := c.Mail("web@shop.test"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("a@example.test"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("From: web@acme.test\r\nSubject: x\r\n\r\nhi\r\n")); err != nil {
		t.Fatal(err)
	}
	err = w.Close()
	if err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("a From of another domain was answered with %v", err)
	}
	_ = c.Quit()

	var reasons []string
	for _, e := range f.entries() {
		if e.Status != "refused" {
			t.Errorf("entry %+v is not a refusal", e)
		}
		reasons = append(reasons, e.Reason)
	}
	if len(reasons) != 2 || !strings.Contains(reasons[1], "another domain") {
		t.Errorf("the refusals are %q", reasons)
	}
}

func TestRelayKeepsTheLimits(t *testing.T) {
	f := &fakeRelayStore{pass: "s3cret", limits: store.SendLimits{CustomerPerHour: 3, RcptPerMsg: 1}}
	got := make(chan string, 4)
	addr := startRelay(t, f, got)
	c := signedIn(t, addr, "s3cret")
	if err := c.Mail("web@acme.test"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("a@example.test"); err != nil {
		t.Fatal(err)
	}
	err := c.Rcpt("b@example.test")
	if err == nil || !strings.Contains(err.Error(), "452") {
		t.Fatalf("the second recipient was answered with %v", err)
	}
	_ = c.Quit()

	// a domain of HostZit without a customer here has its own limit
	f2 := &fakeRelayStore{pass: "s3cret", hour: RelayUnknownPerHour}
	addr2 := startRelay(t, f2, got)
	c2 := signedIn(t, addr2, "s3cret")
	if err := c2.Mail("web@shop.test"); err != nil {
		t.Fatal(err)
	}
	if err := c2.Rcpt("a@example.test"); err == nil || !strings.Contains(err.Error(), "452") {
		t.Fatalf("the hourly limit of the domain was answered with %v", err)
	}
	_ = c2.Quit()
}

func TestRelayRefusesAWrongPasswordAndAuthWithoutTLS(t *testing.T) {
	f := &fakeRelayStore{pass: "s3cret"}
	got := make(chan string, 4)
	addr := startRelay(t, f, got)

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true, ServerName: "mail.test"}); err != nil { // #nosec G402 -- our own test certificate
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(addr)
	err = c.Auth(smtp.PlainAuth("", "hostzit-relay@mail.test", "wrong", host))
	if err == nil || !strings.Contains(err.Error(), "535") {
		t.Fatalf("a wrong password was answered with %v", err)
	}
	// Without a sign-in no mail is taken, and AUTH before STARTTLS is
	// refused (the client of net/smtp hangs up after a failed sign-in and
	// will not try AUTH in the clear, so ask by hand).
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	tc := textproto.NewConn(raw)
	if _, _, err := tc.ReadResponse(220); err != nil {
		t.Fatal(err)
	}
	if err := tc.PrintfLine("EHLO h1.test"); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := tc.ReadResponse(250); err != nil {
		t.Fatal(err)
	} else if strings.Contains(msg, "AUTH") {
		t.Error("AUTH is offered before STARTTLS")
	}
	if err := tc.PrintfLine("MAIL FROM:<web@acme.test>"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tc.ReadResponse(530); err != nil {
		t.Errorf("MAIL FROM without a sign-in: %v", err)
	}
	if err := tc.PrintfLine("AUTH PLAIN AGhvc3R6aXQtcmVsYXlAbWFpbC50ZXN0AHMzY3JldA=="); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tc.ReadResponse(538); err != nil {
		t.Errorf("a sign-in without TLS: %v", err)
	}
}

func TestEnvelopeAddress(t *testing.T) {
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"FROM:<a@b.test>", "a@b.test", true},
		{"from:<a@b.test> SIZE=100 BODY=8BITMIME", "a@b.test", true},
		{" FROM: <a@b.test>", "a@b.test", true},
		{"FROM:<@relay.test:a@b.test>", "a@b.test", true},
		{"FROM:<>", "", true},
		{"TO:<a@b.test>", "", false},
		{"FROM:a@b.test", "", false},
		{"FROM:<a@b.test", "", false},
	} {
		got, _, ok := envelope(c.in, "FROM")
		if ok != c.ok || got != c.want {
			t.Errorf("envelope(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// A message larger than the limit is refused and the connection ends (the
// rest of the message is not read away); the next message goes over a new
// connection. A client that says SIZE is told before it sends.
func TestRelayRefusesATooLargeMessage(t *testing.T) {
	f := &fakeRelayStore{pass: "s3cret", limits: store.SendLimits{CustomerPerHour: 100, RcptPerMsg: 10}}
	got := make(chan string, 4)
	addr := startRelayWith(t, f, got, 2048)
	c := signedIn(t, addr, "s3cret")
	if err := c.Mail("web@acme.test"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("a@example.test"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("From: web@acme.test\r\nSubject: big\r\n\r\n" + strings.Repeat("x", 4096) + "\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err == nil || !strings.Contains(err.Error(), "552") {
		t.Fatalf("a message over the limit was answered with %v", err)
	}
	if err := c.Mail("web@acme.test"); err == nil {
		t.Error("the connection was kept open after a message over the limit")
	}
	c2 := signedIn(t, addr, "s3cret")
	if err := c2.Mail("web@acme.test"); err != nil {
		t.Fatalf("a new connection does not work: %v", err)
	}
	_ = c2.Quit()
	if e := f.entries(); len(e) != 1 || e[0].Reason != "the message is too large" {
		t.Errorf("the relay log holds %+v", e)
	}
}
