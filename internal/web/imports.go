package web

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/webmail"
)

// Moving mail from another server into a mailbox: started on the mailbox
// page, done one after another in the background.

func (s *Server) handleMailboxImport(w http.ResponseWriter, r *http.Request) {
	m := s.loadMailbox(w, r)
	if m == nil {
		return
	}
	port, _ := strconv.Atoi(r.FormValue("port"))
	im, err := s.store.CreateImport(r.Context(), scopeOf(r), m.ID, r.FormValue("host"), port, r.FormValue("insecure") == "1",
		r.FormValue("username"), r.FormValue("password"), userFrom(r).Username)
	if err != nil {
		s.redirectErr(w, r, "/mailboxes/"+m.ID, mailErr(err))
		return
	}
	s.audit(r, "mailbox.import", "mailbox:"+m.Address, "import from %s:%d (%s) queued", im.Host, im.Port, im.Username)
	s.redirect(w, r, "/mailboxes/"+m.ID, "The import has started; this page shows how far it is.")
}

// RunImports works through the queued imports until ctx ends.
func (s *Server) RunImports(ctx context.Context) {
	if err := s.store.ResetRunningImports(ctx); err != nil {
		s.log.Warn("imports", "err", err)
	}
	for {
		im, pw, err := s.store.NextImport(ctx)
		if err != nil {
			s.log.Error("imports", "err", err)
		}
		if im == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}
		s.runImport(ctx, im, pw)
	}
}

func (s *Server) runImport(ctx context.Context, im *store.Import, pw string) {
	finish := func(msg string) {
		_ = s.store.FinishImport(context.Background(), im.ID, msg)
		_ = s.store.Audit(context.Background(), im.CreatedBy, "local", "mailbox.import.end", "mailbox:"+im.MailboxID,
			"import from "+im.Host+" ended: "+map[bool]string{true: "done", false: "failed: " + msg}[msg == ""])
	}
	m, err := s.store.MailboxByID(ctx, store.Staff, im.MailboxID)
	if err != nil {
		finish("the mailbox no longer exists")
		return
	}
	tok, err := s.store.CreateWebmailToken(ctx, m.ID, 24*time.Hour)
	if err != nil {
		finish("internal error")
		return
	}
	defer func() { _ = s.store.DeleteWebmailToken(context.Background(), tok) }()
	ws, err := webmail.Open(WebmailIMAP, WebmailSMTP, m.Address, tok)
	if err != nil {
		finish("the mailbox on this server cannot be opened: " + err.Error())
		return
	}
	defer ws.Close()
	src := webmail.Source{Host: im.Host, Port: im.Port, Insecure: im.Insecure, User: im.Username, Password: pw}
	err = ws.Migrate(ctx, src, s.MailConfig(ctx).AllowPrivateImports, func(f, c, sk int) {
		_ = s.store.ImportProgress(context.Background(), im.ID, f, c, sk)
	})
	if err != nil {
		s.log.Warn("import failed", "mailbox", m.Address, "from", im.Host, "err", err)
		finish(err.Error())
		return
	}
	s.log.Info("import done", "mailbox", m.Address, "from", im.Host)
	finish("")
}
