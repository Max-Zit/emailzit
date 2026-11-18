package web

// What the receivers do with our mail.
//
// The delivery log answers questions about single messages. It does not
// answer the one question that decides whether a mail server is doing its
// job: does the mail arrive at the large receivers? A provider that
// refuses everything looks, message by message, like a handful of lines
// among thousands — our own server was refused by Outlook.com for five
// days before anybody noticed, although every single attempt was in the
// log.
//
// This page groups the outgoing mail by the receiving domain, so a
// receiver that takes nothing stands out, and the check below says it
// without anybody looking.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

type deliverabilityData struct {
	Days      int
	Receivers []store.Receiver
	Blocked   []store.Receiver
	Routes    map[string]bool // domains that already have a route
	Total     struct{ Sent, Deferred, Bounced int }
}

func (s *Server) handleDeliverability(w http.ResponseWriter, r *http.Request) {
	days := 7
	switch r.URL.Query().Get("days") {
	case "1":
		days = 1
	case "30":
		days = 30
	}
	recv, err := s.store.Receivers(r.Context(), s.now().AddDate(0, 0, -days), 200)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &deliverabilityData{Days: days, Receivers: recv, Routes: map[string]bool{}}
	for _, t := range s.MailConfig(r.Context()).Routes {
		d.Routes[t.Domain] = true
	}
	for _, x := range recv {
		d.Total.Sent += x.Sent
		d.Total.Deferred += x.Deferred
		d.Total.Bounced += x.Bounced
		if x.Blocked() {
			d.Blocked = append(d.Blocked, x)
		}
	}
	s.render(w, r, http.StatusOK, "deliverability", &Page{Title: "Deliverability", Nav: "deliverability", Data: d})
}

// noticeBlocked is the kind of the notice about receivers that refuse
// everything; its state is the list of those receivers.
const noticeBlocked = "blocked-receivers"

// blockedReceiverNotice tells the administrators when a receiver stops
// taking mail from this server, and when it takes mail again. Looking at
// one day keeps a single bad address out of it: five refusals to the same
// receiver with nothing delivered is the receiver, not the address.
func (s *Server) blockedReceiverNotice(ctx context.Context) {
	at, state, err := s.store.AdminNotice(ctx, noticeBlocked)
	if err != nil || s.now().Sub(at) < 6*time.Hour {
		return
	}
	recv, err := s.store.Receivers(ctx, s.now().AddDate(0, 0, -1), 200)
	if err != nil {
		return
	}
	var blocked []store.Receiver
	var names []string
	for _, x := range recv {
		if x.Blocked() {
			blocked = append(blocked, x)
			names = append(names, x.Domain)
		}
	}
	sort.Strings(names)
	now := strings.Join(names, " ")
	if err := s.store.SetAdminNotice(ctx, noticeBlocked, now); err != nil {
		return
	}
	was := map[string]bool{}
	for _, n := range strings.Fields(state) {
		was[n] = true
	}
	var fresh []store.Receiver
	for _, x := range blocked {
		if !was[x.Domain] {
			fresh = append(fresh, x)
		}
	}
	if len(fresh) > 0 {
		s.notifyAdmins(ctx, "a receiver refuses our mail", blockedNoticeText(fresh))
		return
	}
	// nothing new: say so when a receiver takes mail again
	var back []string
	for n := range was {
		if !strings.Contains(" "+now+" ", " "+n+" ") {
			back = append(back, n)
		}
	}
	if len(back) > 0 {
		sort.Strings(back)
		s.notifyAdmins(ctx, "a receiver takes our mail again",
			"Mail is being delivered again to:\n\n  "+strings.Join(back, "\n  ")+"\n\nDeliverability shows the last day in the panel.\n")
	}
}

// blockedNoticeText writes what a receiver said and what can be done.
func blockedNoticeText(blocked []store.Receiver) string {
	var b strings.Builder
	b.WriteString("Not one message of the last day reached these receivers, and several were refused or deferred:\n\n")
	for _, x := range blocked {
		fmt.Fprintf(&b, "  %s: %d refused, %d deferred, nothing delivered\n", x.Domain, x.Bounced, x.Deferred)
		if x.LastInfo != "" {
			fmt.Fprintf(&b, "    last answer: %s\n", clip(strings.Join(strings.Fields(x.LastInfo), " "), 300))
		}
	}
	b.WriteString("\nWhen the answer names this server's address and a block list of the receiver, the receiver is refusing the address range of the hosting provider; no record and no setting on this server changes that. Ask the provider to have the range delisted, and give the domain its own way out under Settings -> Delivery routes (a relay the receiver accepts). Deliverability in the panel shows the receivers and what they answered.\n")
	return b.String()
}
