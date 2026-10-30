// Package maillog reads Postfix's log lines into delivery events: what was
// delivered, deferred, bounced or refused, for whom. The root helper feeds
// it from the journal and stores the events; the panels show them as the
// delivery log ("Track delivery").
package maillog

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// Event statuses.
const (
	Sent     = "sent"
	Deferred = "deferred"
	Bounced  = "bounced"
	Rejected = "rejected"
)

// Event is one delivery attempt or refusal for one recipient.
type Event struct {
	At        time.Time
	QueueID   string
	Sender    string
	Recipient string
	Status    string
	Relay     string
	DSN       string
	Info      string
}

var (
	qidRE      = regexp.MustCompile(`^([0-9A-Za-z]{8,20}): (.*)$`)
	fromRE     = regexp.MustCompile(`^from=<([^>]*)>`)
	deliveryRE = regexp.MustCompile(`^to=<([^>]*)>,(?: orig_to=<[^>]*>,)? relay=([^,]*), .*?dsn=([0-9.]+), status=(sent|deferred|bounced) \((.*)\)$`)
	rejectRE   = regexp.MustCompile(`^NOQUEUE: reject: [A-Z]+ from [^:]*: ([0-9]{3} [0-9.]+ .*?); from=<([^>]*)> to=<([^>]*)>`)
	milterRE   = regexp.MustCompile(`^milter-reject: [A-Z-]+ from [^:]*: ([0-9.]+ .*?); from=<([^>]*)> to=<([^>]*)>`)
)

// Parser keeps the sender of each queue ID between the log lines.
type Parser struct {
	mu      sync.Mutex
	senders map[string]sender
}

type sender struct {
	addr string
	seen time.Time
}

// Line parses one log line of a Postfix program ("postfix/smtp" …) and
// returns the events it holds (usually none or one).
func (p *Parser) Line(at time.Time, program, msg string) []Event {
	if strings.HasPrefix(msg, "NOQUEUE: reject:") {
		if m := rejectRE.FindStringSubmatch(msg); m != nil {
			return []Event{{At: at, Sender: m[2], Recipient: strings.ToLower(m[3]), Status: Rejected, Info: clip(m[1])}}
		}
		return nil
	}
	m := qidRE.FindStringSubmatch(msg)
	if m == nil {
		return nil
	}
	qid, rest := m[1], m[2]
	switch {
	case strings.HasSuffix(program, "/qmgr") && strings.HasPrefix(rest, "from=<"):
		if f := fromRE.FindStringSubmatch(rest); f != nil {
			p.remember(qid, f[1], at)
		}
	case strings.HasPrefix(rest, "milter-reject:"):
		if r := milterRE.FindStringSubmatch(rest); r != nil {
			return []Event{{At: at, QueueID: qid, Sender: r[2], Recipient: strings.ToLower(r[3]), Status: Rejected, Info: clip(r[1])}}
		}
	case strings.HasPrefix(rest, "to=<"):
		if d := deliveryRE.FindStringSubmatch(rest); d != nil {
			return []Event{{At: at, QueueID: qid, Sender: p.sender(qid), Recipient: strings.ToLower(d[1]), Relay: clip(d[2]),
				DSN: d[3], Status: d[4], Info: clip(d[5])}}
		}
	case rest == "removed":
		p.forget(qid)
	}
	return nil
}

func clip(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

func (p *Parser) remember(qid, from string, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.senders == nil {
		p.senders = map[string]sender{}
	}
	p.senders[qid] = sender{addr: from, seen: at}
	if len(p.senders) > 100000 {
		for k, v := range p.senders {
			if at.Sub(v.seen) > 6*24*time.Hour {
				delete(p.senders, k)
			}
		}
	}
}

func (p *Parser) sender(qid string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.senders[qid].addr
}

func (p *Parser) forget(qid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.senders, qid)
}
