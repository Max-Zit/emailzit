package submit

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// The relay for a linked HostZit on ANOTHER server (INTEGRATION.md E3).
// The websites there cannot reach the socket of emailzit-sendmail, so they
// send their mail over SMTP to this server with the relay login of the
// link. The listener is only open while a link with a relay login exists,
// and only for the addresses of that HostZit.
//
// Every message is checked here: the envelope sender must be a mail domain
// of this server or a domain HostZit hosts for one of its customers, the
// From address must use the same domain (so Rspamd signs it with that
// domain's DKIM key), and the customer's package limits apply. The message
// then goes to Postfix exactly like mail of a website on this server, so
// DKIM signing, the outgoing spam check and the delivery log all work as
// usual.

const (
	// RelayPort is where EmailZit takes mail from the websites of a linked
	// HostZit on another server.
	RelayPort = 2587
	// RelayUnknownPerHour caps the recipients an hour of a sender domain
	// that HostZit hosts for a customer who is not in EmailZit (no package
	// to count against).
	RelayUnknownPerHour = 200
	// RelayUnknownRcptPerMsg caps the recipients of one such message.
	RelayUnknownRcptPerMsg = 50
	// relayMaxRcpts caps the recipients of one message before any package
	// limit is looked at.
	relayMaxRcpts = 200
	// relayAuthTries is how many wrong passwords end the connection.
	relayAuthTries = 3
	// relayIdle is how long the client may say nothing.
	relayIdle = 2 * time.Minute
	// relayLineMax is the longest command line (the buffer size).
	relayLineMax = 4096
)

// RelayStore is what the relay needs from the database.
type RelayStore interface {
	CheckRelayLogin(ctx context.Context, username, password string) (string, error)
	TouchRelayLogin(ctx context.Context, id string) error
	DomainCustomer(ctx context.Context, domain string) (string, error)
	RelayLimits(ctx context.Context, customerID string) (*store.SendLimits, error)
	RelayDomainHour(ctx context.Context, domain string) (int, error)
	LogRelaySent(ctx context.Context, customerID string, rcpts int) error
	LogRelay(ctx context.Context, m store.RelayMail) error
}

// RelayServer takes mail from the websites of a linked HostZit.
type RelayServer struct {
	Store RelayStore
	Log   *slog.Logger
	// TLS is the panel's certificate; without it STARTTLS is not offered
	// and no mail is taken (the login would go in the clear).
	TLS      *tls.Config
	Hostname func(ctx context.Context) string
	MaxBytes func(ctx context.Context) int64
	// Dial connects to Postfix (PostfixService); replaced in tests.
	Dial func(ctx context.Context) (net.Conn, error)
	// Hosted asks HostZit whether the domain belongs to one of its
	// customers. temp: HostZit could not be asked, try again later.
	Hosted func(ctx context.Context, domain string) (customerID string, ok, temp bool)
	// Now is the clock (tests).
	Now func() time.Time
}

func (s *RelayServer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Serve accepts connections until the listener closes.
func (s *RelayServer) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			// the listener is closed when the link ends: not an error
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go func() {
			defer c.Close()
			(&relaySession{s: s, ctx: ctx, c: c}).run()
		}()
	}
}

// relaySession is one SMTP connection.
type relaySession struct {
	s   *RelayServer
	ctx context.Context
	c   net.Conn
	br  *bufio.Reader
	tr  *textproto.Reader

	host  string
	ip    string
	max   int64
	tlsOn bool
	login string // the ID of the relay login after AUTH
	user  string
	tries int

	// the message being taken
	from    string
	cust    string
	unknown bool // the sender's customer is not in EmailZit
	lim     *store.SendLimits
	rcpts   []string
}

func (z *relaySession) run() {
	z.ip, _, _ = net.SplitHostPort(z.c.RemoteAddr().String())
	z.host = z.s.Hostname(z.ctx)
	if z.host == "" {
		z.host = "localhost"
	}
	z.max = z.s.MaxBytes(z.ctx)
	if z.max <= 0 {
		z.max = 25 << 20
	}
	z.bind(z.c)
	if err := z.say(220, z.host+" EmailZit relay"); err != nil {
		return
	}
	for {
		_ = z.c.SetDeadline(z.s.now().Add(relayIdle))
		line, err := z.read()
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				_ = z.say(500, "5.5.2 Line too long")
			}
			return
		}
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(strings.TrimSpace(cmd))
		arg = strings.TrimSpace(arg)
		switch cmd {
		case "EHLO", "HELO":
			err = z.hello(cmd == "EHLO")
		case "STARTTLS":
			err = z.starttls()
		case "AUTH":
			err = z.auth(arg)
			if z.tries >= relayAuthTries {
				return
			}
		case "MAIL":
			err = z.mail(arg)
		case "RCPT":
			err = z.rcpt(arg)
		case "DATA":
			err = z.data()
		case "RSET":
			z.reset()
			err = z.say(250, "2.0.0 Ok")
		case "NOOP":
			err = z.say(250, "2.0.0 Ok")
		case "VRFY", "EXPN":
			err = z.say(252, "2.5.2 Cannot tell")
		case "QUIT":
			_ = z.say(221, "2.0.0 Bye")
			return
		default:
			err = z.say(500, "5.5.2 Unknown command")
		}
		if err != nil {
			return
		}
	}
}

// bind reads and writes on c (again after STARTTLS).
func (z *relaySession) bind(c net.Conn) {
	z.br = bufio.NewReaderSize(c, relayLineMax)
	z.tr = textproto.NewReader(z.br)
}

// read returns one command line without its line end. A line longer than
// the buffer ends the connection.
func (z *relaySession) read() (string, error) {
	b, err := z.br.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func (z *relaySession) say(code int, text string) error {
	_, err := fmt.Fprintf(z.c, "%d %s\r\n", code, text)
	return err
}

func (z *relaySession) reset() {
	z.from, z.cust, z.unknown, z.lim, z.rcpts = "", "", false, nil, nil
}

func (z *relaySession) hello(ehlo bool) error {
	z.reset()
	if !ehlo {
		return z.say(250, z.host)
	}
	lines := []string{z.host, "SIZE " + strconv.FormatInt(z.max, 10), "8BITMIME", "SMTPUTF8", "ENHANCEDSTATUSCODES"}
	if z.tlsOn {
		lines = append(lines, "AUTH PLAIN LOGIN")
	} else if z.s.TLS != nil {
		lines = append(lines, "STARTTLS")
	}
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		if _, err := fmt.Fprintf(z.c, "250%s%s\r\n", sep, l); err != nil {
			return err
		}
	}
	return nil
}

func (z *relaySession) starttls() error {
	if z.s.TLS == nil || z.tlsOn {
		return z.say(503, "5.5.1 STARTTLS is not possible")
	}
	if err := z.say(220, "2.0.0 Ready to start TLS"); err != nil {
		return err
	}
	c := tls.Server(z.c, z.s.TLS)
	if err := c.HandshakeContext(z.ctx); err != nil {
		z.s.Log.Warn("relay: TLS handshake", "ip", z.ip, "err", err)
		return err
	}
	z.c = c
	z.tlsOn = true
	z.login, z.user = "", ""
	z.reset()
	z.bind(c)
	return nil
}

// auth signs the relay login in; only over TLS.
func (z *relaySession) auth(arg string) error {
	if !z.tlsOn {
		return z.say(538, "5.7.11 Encryption is needed before signing in")
	}
	if z.login != "" {
		return z.say(503, "5.5.1 Already signed in")
	}
	mech, rest, _ := strings.Cut(arg, " ")
	var user, pass string
	switch strings.ToUpper(strings.TrimSpace(mech)) {
	case "PLAIN":
		data := strings.TrimSpace(rest)
		if data == "" || data == "=" {
			if err := z.say(334, ""); err != nil {
				return err
			}
			line, err := z.read()
			if err != nil {
				return err
			}
			data = strings.TrimSpace(line)
		}
		raw, err := decode64(data)
		if err != nil {
			return z.say(501, "5.5.2 The sign-in data is not valid")
		}
		parts := strings.Split(string(raw), "\x00")
		if len(parts) != 3 {
			return z.say(501, "5.5.2 The sign-in data is not valid")
		}
		user, pass = parts[1], parts[2]
	case "LOGIN":
		ask := func(prompt, have string) (string, error) {
			if have != "" {
				return have, nil
			}
			if err := z.say(334, base64.StdEncoding.EncodeToString([]byte(prompt))); err != nil {
				return "", err
			}
			return z.read()
		}
		u, err := ask("Username:", strings.TrimSpace(rest))
		if err != nil {
			return err
		}
		p, err := ask("Password:", "")
		if err != nil {
			return err
		}
		ub, err1 := decode64(strings.TrimSpace(u))
		pb, err2 := decode64(strings.TrimSpace(p))
		if err1 != nil || err2 != nil {
			return z.say(501, "5.5.2 The sign-in data is not valid")
		}
		user, pass = string(ub), string(pb)
	default:
		return z.say(504, "5.5.4 Only PLAIN and LOGIN")
	}
	id, err := z.s.Store.CheckRelayLogin(z.ctx, user, pass)
	if err != nil {
		z.tries++
		z.s.Log.Warn("relay: sign-in refused", "ip", z.ip, "user", user, "try", z.tries)
		time.Sleep(time.Second)
		return z.say(535, "5.7.8 The login is not right")
	}
	z.login, z.user, z.tries = id, user, 0
	if err := z.s.Store.TouchRelayLogin(z.ctx, id); err != nil {
		z.s.Log.Error("relay: last use", "err", err)
	}
	z.s.Log.Info("relay: signed in", "ip", z.ip, "user", user)
	return z.say(235, "2.7.0 Signed in")
}

// mail takes the envelope sender and decides whether the relay may send
// for its domain.
func (z *relaySession) mail(arg string) error {
	if z.login == "" {
		return z.say(530, "5.7.0 Sign in first")
	}
	if z.from != "" {
		return z.say(503, "5.5.1 A message is already being sent")
	}
	addr, params, ok := envelope(arg, "FROM")
	if !ok || addr == "" || !validAddr(addr) {
		return z.say(501, "5.1.7 MAIL FROM:<address> is needed")
	}
	for _, p := range params {
		if n, ok := strings.CutPrefix(strings.ToUpper(p), "SIZE="); ok {
			if v, err := strconv.ParseInt(n, 10, 64); err == nil && v > z.max {
				return z.say(552, fmt.Sprintf("5.3.4 The message is larger than %d MB", z.max>>20))
			}
		}
	}
	domain := strings.ToLower(domainOf(addr))
	cust, ok, temp := z.allowed(domain)
	switch {
	case temp:
		return z.say(451, "4.7.1 The hosting server cannot be asked about this domain; try again later")
	case !ok:
		z.refused(addr, 0, "the sender domain is not hosted here")
		return z.say(550, "5.7.1 Mail cannot be sent for this domain here")
	}
	z.from, z.cust, z.unknown = addr, cust, cust == ""
	if cust != "" {
		l, err := z.s.Store.RelayLimits(z.ctx, cust)
		if err != nil {
			z.s.Log.Error("relay: limits", "customer", cust, "err", err)
			z.reset()
			return z.say(451, "4.3.0 Temporary problem, try again later")
		}
		if l.Blocked {
			z.refused(addr, 0, "the customer is not active")
			z.reset()
			return z.say(550, "5.7.1 Mail cannot be sent for this domain here")
		}
		z.lim = l
	}
	return z.say(250, "2.1.0 Ok")
}

// allowed tells whether the relay may send for a domain: a mail domain of
// this server, or a domain HostZit hosts. The customer is the one in
// EmailZit ("" when the domain's customer is not here).
func (z *relaySession) allowed(domain string) (cust string, ok, temp bool) {
	if domain == "" {
		return "", false, false
	}
	switch id, err := z.s.Store.DomainCustomer(z.ctx, domain); {
	case err == nil:
		return id, true, false
	case !errors.Is(err, store.ErrNotFound):
		z.s.Log.Error("relay: domain", "domain", domain, "err", err)
		return "", false, true
	}
	if z.s.Hosted == nil {
		return "", false, false
	}
	return z.s.Hosted(z.ctx, domain)
}

func (z *relaySession) rcpt(arg string) error {
	if z.from == "" {
		return z.say(503, "5.5.1 MAIL FROM comes first")
	}
	addr, _, ok := envelope(arg, "TO")
	if !ok || !validAddr(addr) {
		return z.say(501, "5.1.3 RCPT TO:<address> is needed")
	}
	n := len(z.rcpts) + 1
	if n > relayMaxRcpts {
		return z.say(452, fmt.Sprintf("4.5.3 Too many recipients (at most %d per message)", relayMaxRcpts))
	}
	if code, text := z.overLimit(n); code != 0 {
		return z.say(code, text)
	}
	z.rcpts = append(z.rcpts, addr)
	return z.say(250, "2.1.5 Ok")
}

// overLimit checks the package limits for n recipients; code 0 = within
// the limits.
func (z *relaySession) overLimit(n int) (int, string) {
	if z.unknown {
		if n > RelayUnknownRcptPerMsg {
			return 452, fmt.Sprintf("4.5.3 Too many recipients (at most %d per message)", RelayUnknownRcptPerMsg)
		}
		sent, err := z.s.Store.RelayDomainHour(z.ctx, strings.ToLower(domainOf(z.from)))
		if err != nil {
			z.s.Log.Error("relay: count", "err", err)
			return 451, "4.3.0 Temporary problem, try again later"
		}
		if sent+n > RelayUnknownPerHour {
			return 452, fmt.Sprintf("4.7.1 Sending limit of the domain reached (%d recipients per hour); try again later", RelayUnknownPerHour)
		}
		return 0, ""
	}
	l := z.lim
	if l == nil {
		return 451, "4.3.0 Temporary problem, try again later"
	}
	switch {
	case l.RcptPerMsg > 0 && n > l.RcptPerMsg:
		return 452, fmt.Sprintf("4.5.3 Too many recipients (at most %d per message)", l.RcptPerMsg)
	case l.CustomerPerHour >= 0 && l.CustomerHour+n > l.CustomerPerHour:
		return 452, "4.7.1 Sending limit of the account reached; try again later"
	}
	return 0, ""
}

// data takes the message, checks it and hands it to Postfix.
func (z *relaySession) data() error {
	if z.from == "" || len(z.rcpts) == 0 {
		return z.say(503, "5.5.1 MAIL FROM and RCPT TO come first")
	}
	if err := z.say(354, "End with a single dot"); err != nil {
		return err
	}
	_ = z.c.SetDeadline(z.s.now().Add(10 * time.Minute))
	dot := z.tr.DotReader()
	raw, err := io.ReadAll(io.LimitReader(dot, z.max+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > z.max {
		// The rest of the message is not read away (that would be an
		// unbounded read), so the connection ends here: the next command
		// would otherwise be read out of the middle of the message. A
		// client that says SIZE in MAIL FROM is told before it sends.
		z.refused(z.from, len(z.rcpts), "the message is too large")
		z.reset()
		_ = z.say(552, fmt.Sprintf("5.3.4 The message is larger than %d MB", z.max>>20))
		return errors.New("the message is too large")
	}
	code, text := z.send(raw)
	z.reset()
	return z.say(code, text)
}

// send checks and queues one message.
func (z *relaySession) send(raw []byte) (int, string) {
	p, err := prepare(Request{Rcpts: z.rcpts}, raw, z.host, z.s.now())
	if err != nil {
		z.refused(z.from, len(z.rcpts), err.Error())
		if !IsPermanent(err) {
			return 451, "4.3.0 " + err.Error()
		}
		return 550, "5.6.0 " + err.Error()
	}
	// The From address must use the sender's domain: Rspamd signs with the
	// key of the From domain, and a website may not write another
	// customer's address into From.
	if !strings.EqualFold(domainOf(p.from), domainOf(z.from)) {
		z.refused(z.from, len(p.rcpts), "the From address uses another domain: "+p.from)
		return 550, "5.7.1 The From address must use the domain of the sender " + z.from
	}
	if code, text := z.overLimit(len(p.rcpts)); code != 0 {
		z.refused(z.from, len(p.rcpts), text)
		return code, text
	}
	id, err := injectAs(z.ctx, z.s.Dial, z.host, "relay", z.from, p)
	if err != nil {
		z.s.Log.Warn("relay: Postfix refused", "from", z.from, "err", err)
		z.refused(z.from, len(p.rcpts), err.Error())
		if IsPermanent(err) {
			return 550, "5.7.1 " + err.Error()
		}
		return 451, "4.3.0 " + err.Error()
	}
	if err := z.s.Store.LogRelaySent(z.ctx, z.cust, len(p.rcpts)); err != nil {
		z.s.Log.Error("relay: count", "err", err)
	}
	if err := z.s.Store.LogRelay(z.ctx, store.RelayMail{CustomerID: z.cust, Sender: z.from,
		Rcpts: len(p.rcpts), QueueID: id, Status: "sent", ClientIP: z.ip}); err != nil {
		z.s.Log.Error("relay: log", "err", err)
	}
	z.s.Log.Info("relay: queued", "id", id, "from", z.from, "rcpts", len(p.rcpts), "ip", z.ip)
	return 250, "2.0.0 Ok: queued as " + id
}

// refused records a refused message, so the customer sees it.
func (z *relaySession) refused(sender string, rcpts int, reason string) {
	if err := z.s.Store.LogRelay(z.ctx, store.RelayMail{CustomerID: z.cust, Sender: sender,
		Rcpts: rcpts, Status: "refused", Reason: reason, ClientIP: z.ip}); err != nil {
		z.s.Log.Error("relay: log", "err", err)
	}
}

// envelope reads "FROM:<address> PARAM=…" of MAIL and RCPT.
func envelope(arg, want string) (addr string, params []string, ok bool) {
	key, rest, ok := strings.Cut(arg, ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(key), want) {
		return "", nil, false
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "<") {
		return "", nil, false
	}
	end := strings.Index(rest, ">")
	if end < 0 {
		return "", nil, false
	}
	addr = strings.TrimSpace(rest[1:end])
	// nothing that could be a line of its own in the session with Postfix,
	// and no second pair of brackets
	if strings.ContainsAny(addr, "<>") || strings.ContainsFunc(addr, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return "", nil, false
	}
	params = append(params, strings.Fields(rest[end+1:])...)
	if i := strings.LastIndex(addr, ":"); i >= 0 { // source route @a:user@b
		addr = addr[i+1:]
	}
	return addr, params, true
}

func decode64(s string) ([]byte, error) {
	if len(s) > 1000 {
		return nil, errors.New("too long")
	}
	return base64.StdEncoding.DecodeString(s)
}
