package submit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// Store is what the server needs from the database.
type Store interface {
	WebSendLimits(ctx context.Context, uid int) (*store.SendLimits, error)
	CustomerSendDomain(ctx context.Context, customerID, domain string) (bool, error)
	LogSent(ctx context.Context, l *store.SendLimits, rcpts int, ip string) error
	LogWebRefused(ctx context.Context, uid int, reason string) (int, error)
	SetWebSendBlocked(ctx context.Context, sc store.Scope, uid int, blocked bool) error
}

// AbuseThreshold is how many refused attempts within an hour block a
// hosting account's mail (same as for mailboxes).
const AbuseThreshold = 30

// PostfixService is the Postfix SMTP service (master.cf) that takes the
// messages, reachable only by the group postdrop (the EmailZit server).
const PostfixService = "/var/spool/postfix/public/emailzit-submit"

// Server takes mail from websites.
type Server struct {
	Store   Store
	Log     *slog.Logger
	PeerUID func(c net.Conn) (int, error)
	// Dial connects to Postfix (PostfixService); replaced in tests.
	Dial func(ctx context.Context) (net.Conn, error)
	// Hostname is the mail host name (EHLO, Message-ID).
	Hostname func(ctx context.Context) string
	// MaxBytes is the largest message accepted.
	MaxBytes func(ctx context.Context) int64
	// Blocked is called when a hosting account was blocked automatically.
	Blocked func(uid int, reason string)
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.conn(ctx, c)
	}
}

func (s *Server) conn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
	id, err := s.handle(ctx, c)
	r := Reply{ID: id}
	if err != nil {
		r.Error, r.Temp = err.Error(), !IsPermanent(err)
	}
	b, _ := json.Marshal(r)
	_, _ = c.Write(append(b, '\n'))
}

func (s *Server) handle(ctx context.Context, c net.Conn) (string, error) {
	uid, err := s.PeerUID(c)
	if err != nil {
		return "", fmt.Errorf("cannot tell who is connecting: %w", err)
	}
	br := bufio.NewReaderSize(c, 64<<10)
	line, err := br.ReadSlice('\n')
	if err != nil {
		return "", refuse("bad request")
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil || len(req.Rcpts) > MaxRcpts {
		return "", refuse("bad request")
	}
	max := s.MaxBytes(ctx)
	raw, err := io.ReadAll(io.LimitReader(br, max+1))
	if err != nil {
		return "", fmt.Errorf("reading the message: %w", err)
	}
	if int64(len(raw)) > max {
		return "", refuse("the message is larger than %d MB", max>>20)
	}
	return s.process(ctx, uid, req, raw)
}

// process checks one message of a hosting account and passes it on.
func (s *Server) process(ctx context.Context, uid int, req Request, raw []byte) (string, error) {
	l, err := s.Store.WebSendLimits(ctx, uid)
	if errors.Is(err, store.ErrNotFound) {
		s.Log.Warn("submit: unknown user", "uid", uid)
		return "", refuse("user ID %d may not send mail through EmailZit (not a hosting account of a customer)", uid)
	}
	if err != nil {
		return "", errors.New("temporary problem, try again later")
	}
	if l.Blocked {
		return "", refuse("sending mail from this hosting account is blocked; contact your provider")
	}
	p, err := prepare(req, raw, s.Hostname(ctx), time.Now())
	if err != nil {
		return "", err
	}
	// the website sends only as the customer's own domains
	allowed := func(a string) bool {
		ok, err := s.Store.CustomerSendDomain(ctx, l.CustomerID, domainOf(a))
		return err == nil && ok
	}
	if !allowed(p.from) {
		return "", s.limit(ctx, l, "foreign sender", refuse("the From address %s is not in one of your verified mail domains", p.from))
	}
	sender := p.from
	if req.Sender != "" && validAddr(req.Sender) && allowed(req.Sender) {
		sender = req.Sender
	}
	n := len(p.rcpts)
	switch {
	case n > l.RcptPerMsg:
		return "", s.limit(ctx, l, "recipients per message", refuse("too many recipients (at most %d per message)", l.RcptPerMsg))
	case l.PerHour >= 0 && l.SentHour+n > l.PerHour:
		return "", s.limit(ctx, l, "per hour", fmt.Errorf("sending limit reached (%d recipients per hour); try again later", l.PerHour))
	case l.PerDay >= 0 && l.SentDay+n > l.PerDay:
		return "", s.limit(ctx, l, "per day", fmt.Errorf("sending limit reached (%d recipients per day); try again later", l.PerDay))
	case l.CustomerPerHour >= 0 && l.CustomerHour+n > l.CustomerPerHour:
		return "", s.limit(ctx, l, "customer per hour", errors.New("sending limit of the account reached; try again later"))
	}
	id, err := s.inject(ctx, uid, sender, p)
	if err != nil {
		s.Log.Warn("submit: Postfix refused", "uid", uid, "err", err)
		return "", err
	}
	if err := s.Store.LogSent(ctx, l, n, ""); err != nil {
		s.Log.Error("submit: log", "uid", uid, "err", err)
	}
	s.Log.Info("submit: queued", "uid", uid, "id", id, "from", sender, "rcpts", n)
	return id, nil
}

// limit records a refused attempt and blocks the hosting account when it
// keeps trying far beyond its limits (a hacked website sending spam).
func (s *Server) limit(ctx context.Context, l *store.SendLimits, reason string, e error) error {
	n, err := s.Store.LogWebRefused(ctx, l.WebUID, reason)
	if err != nil {
		s.Log.Error("submit: refused log", "uid", l.WebUID, "err", err)
		return e
	}
	s.Log.Warn("submit: refused", "uid", l.WebUID, "reason", reason, "refused_last_hour", n)
	if n == AbuseThreshold {
		if err := s.Store.SetWebSendBlocked(ctx, store.Staff, l.WebUID, true); err == nil && s.Blocked != nil {
			s.Blocked(l.WebUID, fmt.Sprintf("%d sending attempts refused (%s) within an hour", n, reason))
		}
	}
	return e
}

// inject passes the message to Postfix. XCLIENT names the hosting account
// as the signed-in user, so Rspamd signs with the domain's DKIM key and
// the delivery log shows web-<uid>.
func (s *Server) inject(ctx context.Context, uid int, sender string, p *prepared) (string, error) {
	c, err := s.Dial(ctx)
	if err != nil {
		return "", fmt.Errorf("the mail server is not reachable: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Minute))
	t := textproto.NewConn(c)
	step := func(want int, format string, a ...any) (string, error) {
		if format != "" {
			if err := t.PrintfLine(format, a...); err != nil {
				return "", err
			}
		}
		_, msg, err := t.ReadResponse(want)
		return msg, smtpErr(err)
	}
	host := s.Hostname(ctx)
	if _, err := step(220, ""); err != nil {
		return "", err
	}
	if _, err := step(250, "EHLO %s", host); err != nil {
		return "", err
	}
	if _, err := step(220, "XCLIENT LOGIN=web-%d", uid); err != nil {
		return "", err
	}
	if _, err := step(250, "EHLO %s", host); err != nil {
		return "", err
	}
	params := ""
	if !ascii(p.data) {
		params = " BODY=8BITMIME"
	}
	utf8 := !ascii([]byte(sender))
	for _, r := range p.rcpts {
		utf8 = utf8 || !ascii([]byte(r))
	}
	if utf8 {
		params += " SMTPUTF8"
	}
	if _, err := step(250, "MAIL FROM:<%s>%s", sender, params); err != nil {
		return "", err
	}
	for _, r := range p.rcpts {
		if _, err := step(25, "RCPT TO:<%s>", r); err != nil {
			return "", fmt.Errorf("%s: %w", r, err)
		}
	}
	if _, err := step(354, "DATA"); err != nil {
		return "", err
	}
	w := t.DotWriter()
	if _, err := w.Write(p.data); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	msg, err := step(250, "")
	if err != nil {
		return "", err
	}
	_ = t.PrintfLine("QUIT")
	id := msg
	if i := strings.LastIndex(msg, "queued as "); i >= 0 {
		id = strings.TrimSpace(msg[i+len("queued as "):])
	}
	return id, nil
}

// smtpErr makes 5xx answers permanent.
func smtpErr(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		if te.Code >= 500 {
			return refuse("%s", te.Msg)
		}
		return fmt.Errorf("%s", te.Msg)
	}
	return err
}

func ascii(b []byte) bool {
	return bytes.IndexFunc(b, func(r rune) bool { return r >= 0x80 }) < 0
}
