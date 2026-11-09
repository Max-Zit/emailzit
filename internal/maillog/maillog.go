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
	// Outbound: mail of signed-in users (refused on submission) or a
	// delivery to another server
	Outbound bool
}

var (
	qidRE      = regexp.MustCompile(`^([0-9A-Za-z]{8,20}): (.*)$`)
	fromRE     = regexp.MustCompile(`^from=<([^>]*)>`)
	deliveryRE = regexp.MustCompile(`^to=<([^>]*)>,(?: orig_to=<[^>]*>,)? relay=([^,]*), .*?dsn=([0-9.]+), status=(sent|deferred|bounced) \((.*)\)$`)
	rejectRE   = regexp.MustCompile(`^NOQUEUE: reject: [A-Z]+ from \S+?: ([0-9]{3} [0-9.]+ .*?); from=<([^>]*)>,? to=<([^>]*)>`)
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
	out  bool // came in on a submission port (signed-in user)
}

// Line parses one log line of a Postfix program ("postfix/smtp" …) and
// returns the events it holds (usually none or one).
func (p *Parser) Line(at time.Time, program, msg string) []Event {
	if strings.HasPrefix(msg, "NOQUEUE: reject:") {
		if m := rejectRE.FindStringSubmatch(msg); m != nil {
			return []Event{{At: at, Sender: addr(m[2]), Recipient: addr(m[3]), Status: Rejected, Info: clip(m[1]), Outbound: submission(program)}}
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
			p.remember(qid, addr(f[1]), at)
		}
	case submission(program) && strings.HasPrefix(rest, "client="):
		p.markOutbound(qid, at)
	case strings.HasPrefix(rest, "milter-reject:"):
		// logged by cleanup, which runs the milters for smtpd
		if r := milterRE.FindStringSubmatch(rest); r != nil {
			return []Event{{At: at, QueueID: qid, Sender: addr(r[2]), Recipient: addr(r[3]), Status: Rejected, Info: clip(r[1]), Outbound: submission(program) || p.outbound(qid)}}
		}
	case strings.HasPrefix(rest, "to=<"):
		if d := deliveryRE.FindStringSubmatch(rest); d != nil {
			return []Event{{At: at, QueueID: qid, Sender: p.sender(qid), Recipient: addr(d[1]), Relay: clip(d[2]),
				DSN: clip(d[3]), Status: d[4], Info: clip(d[5]), Outbound: strings.HasSuffix(program, "/smtp")}}
		}
	case rest == "removed":
		p.forget(qid)
	}
	return nil
}

// clip shortens a text of a log line for the delivery log (valid UTF-8).
func clip(s string) string {
	if len(s) > 300 {
		s = s[:300]
	}
	return strings.ToValidUTF8(s, "")
}

// addr is an address of a log line: lower case, at most 254 bytes.
func addr(s string) string {
	s = strings.ToLower(s)
	if len(s) > 254 {
		s = s[:254]
	}
	return strings.ToValidUTF8(s, "")
}

func (p *Parser) remember(qid, from string, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.senders == nil {
		p.senders = map[string]sender{}
	}
	p.senders[qid] = sender{addr: from, seen: at, out: p.senders[qid].out}
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

// submission tells whether a program takes mail of signed-in users (mail
// programs on 465/587, websites through emailzit-submit).
func submission(program string) bool {
	switch program {
	case "postfix/submission/smtpd", "postfix/submissions/smtpd", "postfix/emailzit-submit/smtpd":
		return true
	}
	return false
}

// Reasons of a refusal, from its text.
const (
	ReasonSpam       = "spam"
	ReasonVirus      = "virus"
	ReasonAttachment = "attachment"
)

// Reason classifies the text of a refusal by Rspamd (empty: another
// refusal).
func Reason(info string) string {
	l := strings.ToLower(info)
	switch {
	case strings.Contains(l, "virus found"):
		return ReasonVirus
	case strings.Contains(l, "as attachments"):
		return ReasonAttachment
	case strings.Contains(l, "spam message rejected"), strings.Contains(l, "gtube pattern"):
		return ReasonSpam
	}
	return ""
}

// markOutbound notes that a queue ID came from a signed-in user.
func (p *Parser) markOutbound(qid string, at time.Time) {
	p.mu.Lock()
	s := p.senders[qid]
	s.out, s.seen = true, at
	if p.senders == nil {
		p.senders = map[string]sender{}
	}
	p.senders[qid] = s
	p.mu.Unlock()
}

func (p *Parser) outbound(qid string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.senders[qid].out
}
