package web

import (
	"context"
	"fmt"
	"time"

	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/store"
)

// Notice puts a message of the server into a mailbox through the helper.
func (h *HelperMail) Notice(ctx context.Context, address, subject, body string) error {
	req := mailhelper.Request{Action: mailhelper.ActionNotice, Subject: subject, Body: body}
	req.Local, req.Domain, _ = cutAt(address)
	return h.C.Call(ctx, req)
}

// RunQuotaWarnings checks every 30 minutes which mailboxes filled 80 or
// 95 % of their quota and puts a warning into their Inbox, in the mailbox's
// language; a mailbox below 70 % can be warned again later.
func (s *Server) RunQuotaWarnings(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		s.QuotaWarnings(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// QuotaWarnings runs one check.
func (s *Server) QuotaWarnings(ctx context.Context) {
	if s.Mail == nil {
		return
	}
	checks, err := s.store.QuotaChecks(ctx)
	if err != nil {
		s.log.Warn("quota warnings", "err", err)
		return
	}
	for _, q := range checks {
		level := quotaLevel(q)
		if level > q.Warned {
			subject, body := quotaNotice(q)
			if err := s.Mail.Notice(ctx, q.Address, subject, body); err != nil {
				s.log.Warn("quota warning", "mailbox", q.Address, "err", err)
				continue
			}
		}
		if err := s.store.SetQuotaWarned(ctx, q.ID, level); err != nil {
			s.log.Warn("quota warning", "mailbox", q.Address, "err", err)
		}
	}
}

// quotaLevel is the warning level the usage reached now (0, 80 or 95);
// between 70 and 80 % the previous level stays.
func quotaLevel(q store.QuotaCheck) int {
	pct := q.UsedBytes * 100 / (int64(q.QuotaMB) << 20)
	switch {
	case pct >= 95:
		return 95
	case pct >= 80:
		return 80
	case pct < 70:
		return 0
	}
	return q.Warned
}

func quotaNotice(q store.QuotaCheck) (subject, body string) {
	pct := q.UsedBytes * 100 / (int64(q.QuotaMB) << 20)
	used := fmt.Sprintf("%.1f MB", float64(q.UsedBytes)/(1<<20))
	quota := fmt.Sprintf("%d MB", q.QuotaMB)
	subject = translate(q.Lang, "Your mailbox is %d%% full", pct)
	body = translate(q.Lang, "The mailbox %s uses %s of its %s.", q.Address, used, quota) + "\n\n" +
		translate(q.Lang, "When it is full, new mail is refused and senders get it back. Delete old messages, empty Trash and Junk, or ask your provider for more space.") + "\n"
	return subject, body
}
