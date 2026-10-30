package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/max-zit/emailzit/internal/sieve"
	"github.com/max-zit/emailzit/internal/store"
)

// The mail user's auto-reply and filters (/mail/filters): stored in the
// database, turned into a Sieve script and installed through ManageSieve
// on the server itself with the session's webmail token.

// WebmailSieve is ManageSieve on the server itself (tests replace it).
var WebmailSieve = "127.0.0.1:4190"

type filtersData struct {
	S       sieve.Settings
	Spam    *spamForm
	Folders []string
}

func (s *Server) loadSieve(r *http.Request) sieve.Settings {
	var st sieve.Settings
	if raw, err := s.store.MailboxSieve(r.Context(), mailboxFrom(r).ID); err == nil {
		_ = json.Unmarshal(raw, &st)
	}
	if st.AutoReply.Days == 0 {
		st.AutoReply.Days = 1
	}
	return st
}

func (s *Server) handleFilters(w http.ResponseWriter, r *http.Request) {
	s.showFilters(w, r, http.StatusOK, s.loadSieve(r), "")
}

func (s *Server) showFilters(w http.ResponseWriter, r *http.Request, status int, st sieve.Settings, errMsg string) {
	d := &filtersData{S: st}
	if ws := s.openWebmail(w, r); ws != nil {
		if fs, err := ws.Folders(); err == nil {
			for _, f := range fs {
				d.Folders = append(d.Folders, f.Name)
			}
		}
		ws.Close()
	} else {
		return
	}
	m := mailboxFrom(r)
	if sp, err := s.store.MailboxSpamSettings(r.Context(), store.Scope{CustomerID: m.CustomerID}, m.ID); err == nil {
		d.Spam = newSpamForm("/mail/spam", sp)
	}
	p := s.mailPage(r, "Auto-reply and filters", d)
	p.Nav = "filters"
	if errMsg != "" {
		p.Error = p.T(errMsg)
	}
	s.render(w, r, status, "filters", p)
}

func (s *Server) handleFiltersSave(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	st := sieve.Settings{AutoReply: sieve.AutoReply{On: r.FormValue("ar_on") == "1", Subject: r.FormValue("ar_subject"),
		Body: r.FormValue("ar_body"), From: r.FormValue("ar_from"), Until: r.FormValue("ar_until"), Days: formInt(r, "ar_days")}}
	fields, values, actions, folders := r.Form["field"], r.Form["value"], r.Form["action"], r.Form["folder"]
	for i := range fields {
		if i >= len(values) || i >= len(actions) || i >= len(folders) || strings.TrimSpace(values[i]) == "" {
			continue
		}
		st.Rules = append(st.Rules, sieve.Rule{Field: fields[i], Value: values[i], Action: actions[i], Folder: folders[i]})
	}
	if err := st.Validate(); err != nil {
		s.showFilters(w, r, http.StatusBadRequest, st, err.Error())
		return
	}
	tok, err := s.store.SessionWebmail(r.Context(), mailSessionFrom(r).Hash)
	if err == nil {
		err = sieve.Install(WebmailSieve, m.Address, tok, st.Script(m.Address))
	}
	if err != nil {
		s.log.Error("installing filters", "mailbox", m.Address, "err", err)
		s.showFilters(w, r, http.StatusBadGateway, st, "The filters could not be saved on the mail server. Try again in a moment.")
		return
	}
	raw, _ := json.Marshal(st)
	if err := s.store.SetMailboxSieve(r.Context(), m.ID, raw); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.auditAs(r, m.Address, "mail.filters", "mailbox:"+m.Address, "auto-reply %v, %d filter(s)", st.AutoReply.On, len(st.Rules))
	s.redirect(w, r, "/mail/filters", "Saved.")
}

type filterRowCtx struct {
	P *Page
	R sieve.Rule
}

func init() {
	funcs["filterRow"] = func(p *Page, r any) filterRowCtx {
		c := filterRowCtx{P: p}
		if rule, ok := r.(sieve.Rule); ok {
			c.R = rule
		}
		return c
	}
}
