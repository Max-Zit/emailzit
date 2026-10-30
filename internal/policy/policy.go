// Package policy is EmailZit's Postfix policy service: it enforces the
// sending limits of signed-in mailboxes (recipients per message, per hour
// and day for the mailbox, per hour for the whole customer) and blocks a
// mailbox that keeps trying far beyond its limit — the usual sign of a
// stolen password used for spam. Postfix asks it on the submission ports
// at RCPT (each recipient) and at DATA (the message is counted).
package policy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// Store is what the service needs from the database.
type Store interface {
	SendLimitsFor(ctx context.Context, address string) (*store.SendLimits, error)
	LogSent(ctx context.Context, l *store.SendLimits, rcpts int, ip string) error
	LogRefused(ctx context.Context, mailboxID, reason string) (int, error)
	BlockSending(ctx context.Context, mailboxID string) error
}

// AbuseThreshold is how many refused attempts within an hour block a
// mailbox's sending.
const AbuseThreshold = 30

// Service answers policy requests.
type Service struct {
	Store Store
	Log   *slog.Logger
	// Blocked is called when a mailbox was blocked automatically (audit,
	// notification).
	Blocked func(address, reason string)
	// AllowUID may connect (the postfix user); -1 = anybody (tests).
	AllowUID int
	PeerUID  func(c net.Conn) (int, error)

	mu    sync.Mutex
	count map[string]instance // recipients so far per SMTP transaction
}

type instance struct {
	n    int
	seen time.Time
}

// Serve accepts connections until the listener closes.
func (s *Service) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); _ = l.Close() }()
	go s.janitor(ctx)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.conn(ctx, c)
	}
}

func (s *Service) janitor(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			for k, v := range s.count {
				if time.Since(v.seen) > 30*time.Minute {
					delete(s.count, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Service) conn(ctx context.Context, c net.Conn) {
	defer c.Close()
	if s.AllowUID >= 0 && s.PeerUID != nil {
		uid, err := s.PeerUID(c)
		if err != nil || (uid != s.AllowUID && uid != 0) {
			s.Log.Warn("policy: connection refused", "uid", uid, "err", err)
			return
		}
	}
	r := bufio.NewReader(io.LimitReader(c, 1<<20))
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		req, err := readRequest(r)
		if err != nil {
			return
		}
		action := s.Decide(ctx, req)
		if _, err := fmt.Fprintf(c, "action=%s\n\n", action); err != nil {
			return
		}
	}
}

// readRequest reads name=value lines up to an empty line.
func readRequest(r *bufio.Reader) (map[string]string, error) {
	req := map[string]string{}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return req, nil
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && len(req) < 100 {
			req[k] = v
		}
	}
}

// Decide returns the Postfix action for one request.
func (s *Service) Decide(ctx context.Context, req map[string]string) string {
	user := strings.ToLower(req["sasl_username"])
	if user == "" || req["request"] != "smtpd_access_policy" {
		return "DUNNO"
	}
	l, err := s.Store.SendLimitsFor(ctx, user)
	if err != nil {
		s.Log.Error("policy: limits", "user", user, "err", err)
		return "DEFER_IF_PERMIT 4.3.0 Temporary problem, try again later"
	}
	key := req["instance"]
	switch req["protocol_state"] {
	case "RCPT":
		if l.Blocked {
			return "REJECT 5.7.1 Sending from this mailbox is blocked; contact your provider"
		}
		s.mu.Lock()
		n := s.count[key].n + 1
		s.mu.Unlock()
		if n > l.RcptPerMsg {
			return s.refuse(ctx, user, l, "recipients per message", fmt.Sprintf("REJECT 5.5.3 Too many recipients (at most %d per message)", l.RcptPerMsg))
		}
		switch {
		case l.PerHour >= 0 && l.SentHour+n > l.PerHour:
			return s.refuse(ctx, user, l, "per hour", fmt.Sprintf("DEFER_IF_PERMIT 4.7.1 Sending limit reached (%d recipients per hour); try again later", l.PerHour))
		case l.PerDay >= 0 && l.SentDay+n > l.PerDay:
			return s.refuse(ctx, user, l, "per day", fmt.Sprintf("DEFER_IF_PERMIT 4.7.1 Sending limit reached (%d recipients per day); try again later", l.PerDay))
		case l.CustomerPerHour >= 0 && l.CustomerHour+n > l.CustomerPerHour:
			return s.refuse(ctx, user, l, "customer per hour", "DEFER_IF_PERMIT 4.7.1 Sending limit of the account reached; try again later")
		}
		s.mu.Lock()
		if s.count == nil {
			s.count = map[string]instance{}
		}
		s.count[key] = instance{n: n, seen: time.Now()}
		s.mu.Unlock()
		return "DUNNO"
	case "DATA", "END-OF-MESSAGE":
		s.mu.Lock()
		n := s.count[key].n
		delete(s.count, key)
		s.mu.Unlock()
		if rc, err := strconv.Atoi(req["recipient_count"]); err == nil && rc > 0 {
			n = rc
		}
		if n > 0 {
			if err := s.Store.LogSent(ctx, l, n, req["client_address"]); err != nil {
				s.Log.Error("policy: log", "user", user, "err", err)
			}
		}
		return "DUNNO"
	}
	return "DUNNO"
}

// refuse records a refused attempt and blocks the mailbox when it keeps
// trying far beyond its limits.
func (s *Service) refuse(ctx context.Context, user string, l *store.SendLimits, reason, action string) string {
	n, err := s.Store.LogRefused(ctx, l.MailboxID, reason)
	if err != nil {
		s.Log.Error("policy: refused log", "user", user, "err", err)
		return action
	}
	s.Log.Warn("policy: sending limit", "user", user, "limit", reason, "refused_last_hour", n)
	if n == AbuseThreshold {
		if err := s.Store.BlockSending(ctx, l.MailboxID); err == nil {
			s.Log.Warn("policy: mailbox blocked for abuse", "user", user)
			if s.Blocked != nil {
				s.Blocked(user, fmt.Sprintf("%d sending attempts over the limit (%s) within an hour", n, reason))
			}
		}
	}
	return action
}
