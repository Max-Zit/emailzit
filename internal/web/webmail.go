package web

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/webmail"
)

// The built-in webmail (/mail/webmail): folders, message list, reading
// (HTML in a sandboxed frame, reduced to safe markup), writing with
// attachments, reply, forward, delete, junk. It talks to Dovecot and
// Postfix on the server itself with the session's webmail token.

// Webmail addresses on the server itself (tests replace them).
var (
	WebmailIMAP = "127.0.0.1:143"
	WebmailSMTP = "127.0.0.1:465"
)

func (s *Server) webmailRoutes(m func(string, http.HandlerFunc)) {
	m("GET /mail/webmail", s.handleWebmail)
	m("GET /mail/webmail/msg", s.handleWebmailMessage)
	m("GET /mail/webmail/att", s.handleWebmailAttachment)
	m("GET /mail/webmail/compose", s.handleWebmailCompose)
	m("POST /mail/webmail/send", s.handleWebmailSend)
	m("POST /mail/webmail/action", s.handleWebmailAction)
}

// openWebmail connects for this request; on a refused token the user signs
// in again.
func (s *Server) openWebmail(w http.ResponseWriter, r *http.Request) *webmail.Session {
	x, m := mailSessionFrom(r), mailboxFrom(r)
	tok, err := s.store.SessionWebmail(r.Context(), x.Hash)
	if err == nil && tok == "" {
		err = webmail.ErrSignIn
	}
	var ws *webmail.Session
	if err == nil {
		ws, err = webmail.Open(WebmailIMAP, WebmailSMTP, m.Address, tok)
	}
	if err != nil {
		if errors.Is(err, webmail.ErrSignIn) {
			_ = s.store.DeleteMailSession(r.Context(), x.Hash)
			s.clearMailCookie(w, r)
			http.Redirect(w, r, "/mail/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return nil
		}
		s.log.Error("webmail", "mailbox", m.Address, "err", err)
		p := s.mailPage(r, "Webmail", nil)
		p.Error = p.T("The mail server is not reachable right now. Try again in a moment.")
		s.render(w, r, http.StatusServiceUnavailable, "message", p)
		return nil
	}
	return ws
}

type webmailData struct {
	Folders  []webmail.Folder
	Folder   string
	List     []webmail.Summary
	Total    int
	Page     int
	Pages    int
	Q        string
	Msg      *webmail.Message
	Body     string // safe HTML of the message; escaped into the srcdoc attribute
	Compose  *webmail.Draft
	Contacts []store.Contact // suggestions while writing
	Mode     string
	Max      int
}

func folderOf(r *http.Request) string {
	f := r.FormValue("f")
	if f == "" || len(f) > 200 || strings.ContainsAny(f, "\r\n\x00") {
		return "INBOX"
	}
	return f
}

func (s *Server) handleWebmail(w http.ResponseWriter, r *http.Request) {
	ws := s.openWebmail(w, r)
	if ws == nil {
		return
	}
	defer ws.Close()
	d := &webmailData{Folder: folderOf(r), Q: strings.TrimSpace(r.FormValue("q"))}
	d.Page, _ = strconv.Atoi(r.FormValue("p"))
	if d.Page < 1 {
		d.Page = 1
	}
	var err error
	if d.Folders, err = ws.Folders(); err == nil {
		d.List, d.Total, err = ws.List(d.Folder, d.Page, d.Q)
	}
	p := s.mailPage(r, "Webmail", d)
	p.Nav = "webmail"
	if err != nil {
		p.Error = p.T("The folder could not be opened.")
	}
	d.Pages = (d.Total + webmail.PageSize - 1) / webmail.PageSize
	s.render(w, r, http.StatusOK, "webmail", p)
}

func uidOf(r *http.Request) uint32 {
	n, _ := strconv.ParseUint(r.FormValue("uid"), 10, 32)
	return uint32(n)
}

func (s *Server) handleWebmailMessage(w http.ResponseWriter, r *http.Request) {
	ws := s.openWebmail(w, r)
	if ws == nil {
		return
	}
	defer ws.Close()
	d := &webmailData{Folder: folderOf(r)}
	d.Folders, _ = ws.Folders()
	msg, err := ws.Get(d.Folder, uidOf(r))
	p := s.mailPage(r, "Webmail", d)
	p.Nav = "webmail"
	if err != nil {
		p.Error = p.T(err.Error())
		s.render(w, r, http.StatusNotFound, "webmail", p)
		return
	}
	d.Msg = msg
	if msg.HTML != "" {
		safe := webmail.SafeHTML(msg.HTML)
		// images that came with the message are shown inline (data: URLs)
		for _, a := range msg.Attachments {
			if a.CID != "" && strings.HasPrefix(a.Type, "image/") && a.Size < 2<<20 {
				safe = strings.ReplaceAll(safe, `src="cid:`+a.CID+`"`, `src="`+dataURL(a)+`"`)
			}
		}
		d.Body = `<!doctype html><meta charset="utf-8"><base target="_blank">` + safe
	}
	s.render(w, r, http.StatusOK, "webmailmsg", p)
}

func dataURL(a *webmail.Attachment) string {
	ct, _, err := mime.ParseMediaType(a.Type)
	if err != nil || !strings.HasPrefix(ct, "image/") || ct == "image/svg+xml" {
		return ""
	}
	return "data:" + ct + ";base64," + b64(a.Data())
}

func (s *Server) handleWebmailAttachment(w http.ResponseWriter, r *http.Request) {
	ws := s.openWebmail(w, r)
	if ws == nil {
		return
	}
	defer ws.Close()
	msg, err := ws.Get(folderOf(r), uidOf(r))
	i, _ := strconv.Atoi(r.FormValue("i"))
	if err != nil || i < 0 || i >= len(msg.Attachments) {
		s.notFound(w, r)
		return
	}
	a := msg.Attachments[i]
	h := w.Header()
	// always a download, never shown by the browser in the panel's origin
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Name}))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(a.Data())
}

func (s *Server) handleWebmailCompose(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	d := &webmailData{Compose: &webmail.Draft{From: m.Address, FromName: m.DisplayName, To: r.FormValue("to")}, Mode: r.FormValue("mode"), Max: 25}
	if uid := uidOf(r); uid > 0 {
		ws := s.openWebmail(w, r)
		if ws == nil {
			return
		}
		orig, err := ws.Get(folderOf(r), uid)
		ws.Close()
		if err == nil {
			c := d.Compose
			subj := orig.Subject
			switch d.Mode {
			case "forward":
				if !strings.HasPrefix(strings.ToLower(subj), "fwd:") {
					subj = "Fwd: " + subj
				}
				c.Text = "\n\n-------- Forwarded message --------\nFrom: " + orig.From + "\nDate: " + orig.Date.Format("2006-01-02 15:04") + "\nSubject: " + orig.Subject + "\nTo: " + orig.To + "\n\n" + orig.Body()
			default:
				if !strings.HasPrefix(strings.ToLower(subj), "re:") {
					subj = "Re: " + subj
				}
				c.To = orig.ReplyTo
				if c.To == "" {
					c.To = orig.From
				}
				if d.Mode == "replyall" {
					c.Cc = strings.Trim(strings.Join([]string{orig.To, orig.Cc}, ", "), ", ")
				}
				c.InReplyTo = orig.MessageID
				c.References = strings.TrimSpace(orig.References + " <" + orig.MessageID + ">")
				c.Text = webmail.Quote(orig)
			}
			c.Subject = subj
		}
	}
	if sig, err := s.store.Signature(r.Context(), m.ID); err == nil {
		d.Compose.Text = withSignature(d.Compose.Text, sig)
	}
	d.Contacts, _ = s.store.Contacts(r.Context(), m.ID)
	p := s.mailPage(r, "Write a message", d)
	p.Nav = "webmail"
	s.render(w, r, http.StatusOK, "webmailcompose", p)
}

func (s *Server) handleWebmailSend(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	r.Body = http.MaxBytesReader(w, r.Body, 26<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		s.composeError(w, r, &webmail.Draft{From: m.Address}, "The message with its attachments is larger than 25 MB.")
		return
	}
	d := &webmail.Draft{From: m.Address, FromName: m.DisplayName, To: r.FormValue("to"), Cc: r.FormValue("cc"), Bcc: r.FormValue("bcc"),
		Subject: r.FormValue("subject"), Text: r.FormValue("text"), InReplyTo: r.FormValue("in_reply_to"), References: r.FormValue("references")}
	if r.MultipartForm != nil {
		for _, fh := range r.MultipartForm.File["files"] {
			f, err := fh.Open()
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(f, 25<<20))
			_ = f.Close()
			d.Files = append(d.Files, webmail.File{Name: fh.Filename, Type: fh.Header.Get("Content-Type"), Data: data})
		}
	}
	host := s.MailConfig(r.Context()).Hostname
	if host == "" {
		host = "localhost"
	}
	raw, rcpts, err := d.Build(host)
	if err != nil {
		s.composeError(w, r, d, err.Error())
		return
	}
	ws := s.openWebmail(w, r)
	if ws == nil {
		return
	}
	defer ws.Close()
	if err := ws.Send(m.Address, rcpts, raw); err != nil {
		var se *webmail.SendError
		msg := "The message could not be sent. Try again in a moment."
		if errors.As(err, &se) {
			msg = translate(s.mailLang(r, m), "The mail server refused the message: %s", se.Msg)
			s.composeError(w, r, d, "!"+msg)
			return
		}
		s.log.Error("webmail send", "mailbox", m.Address, "err", err)
		s.composeError(w, r, d, msg)
		return
	}
	if err := ws.Append(ws.FolderByRole(`\Sent`, "Sent"), raw, []string{`\Seen`}); err != nil {
		s.log.Warn("webmail: copy to Sent", "mailbox", m.Address, "err", err)
	}
	s.rememberRecipients(r, m.ID, d)
	s.auditAs(r, m.Address, "mail.webmail.send", "mailbox:"+m.Address, "message sent to %d recipient(s)", len(rcpts))
	s.redirect(w, r, "/mail/webmail", "The message was sent.")
}

func (s *Server) composeError(w http.ResponseWriter, r *http.Request, d *webmail.Draft, msg string) {
	wd := &webmailData{Compose: d, Max: 25}
	wd.Contacts, _ = s.store.Contacts(r.Context(), mailboxFrom(r).ID)
	p := s.mailPage(r, "Write a message", wd)
	p.Nav = "webmail"
	if strings.HasPrefix(msg, "!") {
		p.Error = msg[1:] // already translated
	} else {
		p.Error = p.T(msg)
	}
	d.Files = nil
	s.render(w, r, http.StatusBadRequest, "webmailcompose", p)
}

// handleWebmailAction moves, deletes or marks the chosen messages.
func (s *Server) handleWebmailAction(w http.ResponseWriter, r *http.Request) {
	ws := s.openWebmail(w, r)
	if ws == nil {
		return
	}
	defer ws.Close()
	folder := folderOf(r)
	var uids []uint32
	for _, v := range r.Form["uid"] {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil && n > 0 {
			uids = append(uids, uint32(n))
		}
	}
	back := "/mail/webmail?f=" + url.QueryEscape(folder)
	var err error
	switch r.FormValue("op") {
	case "delete":
		trash := ws.FolderByRole(`\Trash`, "Trash")
		if folder == trash {
			err = ws.Delete(folder, uids)
		} else {
			err = ws.Move(folder, uids, trash)
		}
	case "junk":
		err = ws.Move(folder, uids, ws.FolderByRole(`\Junk`, "Junk"))
	case "notjunk":
		err = ws.Move(folder, uids, "INBOX")
	case "seen":
		err = ws.SetSeen(folder, uids, true)
	case "unseen":
		err = ws.SetSeen(folder, uids, false)
	case "move":
		err = ws.Move(folder, uids, folderOf(&http.Request{Form: url.Values{"f": {r.FormValue("to")}}}))
	}
	if err != nil {
		s.log.Warn("webmail action", "op", r.FormValue("op"), "err", err)
		s.redirectErr(w, r, back, "The action could not be done.")
		return
	}
	s.redirect(w, r, back, "")
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func init() {
	funcs["add"] = func(a, b int) int { return a + b }
}
