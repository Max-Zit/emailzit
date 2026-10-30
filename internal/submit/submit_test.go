package submit

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

func TestPrepare(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	msg := "To: Ana <ana@x.test>, bo@y.test\r\nCc: cy@z.test\r\nBcc: secret@w.test\r\nSubject: hi\r\n  folded\r\n\r\nbody\r\n.\r\n"
	p, err := prepare(Request{Extract: true, Sender: "web@acme.test", Name: "Shop Ž", Rcpts: []string{"cmd@q.test,ana@X.test"}}, []byte(msg), "mail.acme.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.rcpts, " ") != "cmd@q.test ana@X.test bo@y.test cy@z.test secret@w.test" {
		t.Fatalf("rcpts %v", p.rcpts)
	}
	d := string(p.data)
	if strings.Contains(d, "secret@") || strings.Contains(d, "\r") || !strings.Contains(d, "Subject: hi\n  folded\n\nbody\n.\n") {
		t.Fatalf("data %q", d)
	}
	if p.from != "web@acme.test" || !strings.HasPrefix(d, "From: =?utf-8?q?Shop_=C5=BD?= <web@acme.test>\nDate: Fri, 30 Oct 2026 12:00:00 +0000\nMessage-ID: <") {
		t.Fatalf("added headers %q", d)
	}

	// without -t the headers do not add recipients
	p, err = prepare(Request{Rcpts: []string{"a@b.test"}}, []byte("From: x@acme.test\nTo: other@c.test\nDate: x\nMessage-ID: <1@x>\n\nhi"), "h", now)
	if err != nil || len(p.rcpts) != 1 || p.from != "x@acme.test" || !strings.HasPrefix(string(p.data), "From: x@acme.test\n") {
		t.Fatalf("%v %+v", err, p)
	}

	bad := map[string]string{
		"no recipients": "From: x@acme.test\n\nhi",
		"two From":      "From: x@acme.test\nFrom: y@acme.test\nTo: a@b.test\n\nhi",
		"bad header":    "From x@acme.test\nTo: a@b.test\n\nhi",
		"bad To":        "From: x@acme.test\nTo: <<a\n\nhi",
		"no From":       "To: a@b.test\n\nhi",
		"two in From":   "From: x@acme.test, y@acme.test\nTo: a@b.test\n\nhi",
		"injection":     "From: x@acme.test\nTo: <a@b.test>\n\nhi",
	}
	for name, m := range bad {
		req := Request{Extract: true}
		if name == "injection" {
			req.Rcpts = []string{"a@b.test>\r\nRCPT TO:<c@d.test"}
		}
		if _, err := prepare(req, []byte(m), "h", now); err == nil || !IsPermanent(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type fakeStore struct {
	l       store.SendLimits
	sent    int
	refused int
	blocked bool
}

func (f *fakeStore) WebSendLimits(ctx context.Context, uid int) (*store.SendLimits, error) {
	if uid != 1000012 {
		return nil, store.ErrNotFound
	}
	l := f.l
	l.WebUID = uid
	l.SentHour, l.SentDay, l.CustomerHour, l.Blocked = f.sent, f.sent, f.sent, f.blocked
	return &l, nil
}
func (f *fakeStore) CustomerSendDomain(ctx context.Context, c, d string) (bool, error) {
	return d == "acme.test", nil
}
func (f *fakeStore) LogSent(ctx context.Context, l *store.SendLimits, n int, ip string) error {
	f.sent += n
	return nil
}
func (f *fakeStore) LogWebRefused(ctx context.Context, uid int, r string) (int, error) {
	f.refused++
	return f.refused, nil
}
func (f *fakeStore) SetWebSendBlocked(ctx context.Context, sc store.Scope, uid int, b bool) error {
	f.blocked = b
	return nil
}

// fakePostfix answers one SMTP session and records it.
func fakePostfix(got chan<- string) func(context.Context) (net.Conn, error) {
	return func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			tc := textproto.NewConn(b)
			var log strings.Builder
			_ = tc.PrintfLine("220 fake ESMTP")
			for {
				line, err := tc.ReadLine()
				if err != nil {
					got <- log.String()
					return
				}
				log.WriteString(line + "\n")
				switch {
				case strings.HasPrefix(line, "XCLIENT"):
					_ = tc.PrintfLine("220 fake ESMTP")
				case strings.HasPrefix(line, "RCPT TO:<refuse@"):
					_ = tc.PrintfLine("550 5.1.1 no such user")
				case line == "DATA":
					_ = tc.PrintfLine("354 go ahead")
					body, _ := tc.ReadDotBytes()
					log.WriteString(string(body) + "<end>\n")
					_ = tc.PrintfLine("250 2.0.0 Ok: queued as ABC123")
				case line == "QUIT":
					_ = tc.PrintfLine("221 bye")
					got <- log.String()
					return
				default:
					_ = tc.PrintfLine("250 ok")
				}
			}
		}()
		return a, nil
	}
}

func TestServer(t *testing.T) {
	f := &fakeStore{l: store.SendLimits{CustomerID: "c", PerHour: 4, PerDay: 100, CustomerPerHour: 100, RcptPerMsg: 3}}
	got := make(chan string, 10)
	uid := 1000012
	var blockedUID int
	s := &Server{Store: f, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		PeerUID:  func(net.Conn) (int, error) { return uid, nil },
		Dial:     fakePostfix(got),
		Hostname: func(context.Context) string { return "mail.acme.test" },
		MaxBytes: func(context.Context) int64 { return 1000 },
		Blocked:  func(u int, r string) { blockedUID = u },
	}
	ctx := context.Background()
	msg := "From: Shop <shop@acme.test>\nTo: a@x.test, b@y.test\nSubject: order\n\nthanks\n.\n"
	id, err := s.process(ctx, uid, Request{Extract: true, Sender: "bounce@acme.test"}, []byte(msg))
	if err != nil || id != "ABC123" {
		t.Fatalf("send: %q %v", id, err)
	}
	session := <-got
	for _, want := range []string{"EHLO mail.acme.test\nXCLIENT LOGIN=web-1000012\nEHLO mail.acme.test\nMAIL FROM:<bounce@acme.test>\nRCPT TO:<a@x.test>\nRCPT TO:<b@y.test>\nDATA\n", "Subject: order\n\nthanks\n.\n<end>"} {
		if !strings.Contains(session, want) {
			t.Fatalf("session misses %q:\n%s", want, session)
		}
	}
	if f.sent != 2 {
		t.Fatal("not counted", f.sent)
	}
	// a foreign -f falls back to the From address
	if _, err := s.process(ctx, uid, Request{Rcpts: []string{"c@x.test"}, Sender: "x@gmail.test"}, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	if session := <-got; !strings.Contains(session, "MAIL FROM:<shop@acme.test>\n") {
		t.Fatal(session)
	}
	// limits: per hour (3 sent, 4 allowed), recipients per message
	if _, err := s.process(ctx, uid, Request{Extract: true}, []byte(msg)); err == nil || IsPermanent(err) || !strings.Contains(err.Error(), "per hour") {
		t.Fatalf("hour limit: %v", err)
	}
	if _, err := s.process(ctx, uid, Request{Rcpts: []string{"1@x.test", "2@x.test", "3@x.test", "4@x.test"}}, []byte(msg)); !IsPermanent(err) {
		t.Fatalf("rcpt limit: %v", err)
	}
	// only the customer's own domains
	if _, err := s.process(ctx, uid, Request{Rcpts: []string{"a@x.test"}}, []byte("From: ceo@bank.test\n\nsend money")); !IsPermanent(err) || !strings.Contains(err.Error(), "bank.test") {
		t.Fatalf("foreign From: %v", err)
	}
	// unknown user IDs are refused
	if _, err := s.process(ctx, 1000099, Request{Rcpts: []string{"a@x.test"}}, []byte(msg)); !IsPermanent(err) {
		t.Fatalf("unknown uid: %v", err)
	}
	// Postfix refusing a recipient is permanent
	f.sent = 0
	if _, err := s.process(ctx, uid, Request{Rcpts: []string{"refuse@x.test"}}, []byte(msg)); !IsPermanent(err) {
		t.Fatalf("postfix 550: %v", err)
	}
	<-got
	// a website that keeps trying is blocked
	f.refused = AbuseThreshold - 1
	_, _ = s.process(ctx, uid, Request{Rcpts: []string{"a@x.test"}}, []byte("From: ceo@bank.test\n\nx"))
	if !f.blocked || blockedUID != uid {
		t.Fatal("not blocked")
	}
	if _, err := s.process(ctx, uid, Request{Rcpts: []string{"a@x.test"}}, []byte(msg)); !IsPermanent(err) || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("blocked: %v", err)
	}
}
