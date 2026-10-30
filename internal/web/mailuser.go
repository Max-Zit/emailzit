package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/auth"
	"github.com/max-zit/emailzit/internal/store"
)

// The mail user's own pages under /mail: sign-in with the address, the web
// password and always a second factor; the own password, app passwords
// for mail programs, and (later) webmail, auto-reply and filters. They
// have their own cookie, separate from the panel logins.

const (
	ctxMailbox ctxKey = iota + 100
	ctxMailSession
)

func mailboxFrom(r *http.Request) *store.Mailbox {
	m, _ := r.Context().Value(ctxMailbox).(*store.Mailbox)
	return m
}

func mailSessionFrom(r *http.Request) *store.MailSession {
	x, _ := r.Context().Value(ctxMailSession).(*store.MailSession)
	return x
}

func mailCookieName(r *http.Request) string {
	if r.TLS != nil {
		return "__Host-ezmail"
	}
	return "ezmail"
}

func (s *Server) setMailCookie(w http.ResponseWriter, r *http.Request, tok string, life time.Duration) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: mailCookieName(r), Value: tok, Path: "/", MaxAge: int(life.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (s *Server) clearMailCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: mailCookieName(r), Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

// loadMailSession puts the mailbox of a full mail user session into the
// request context (and the session of any stage).
func (s *Server) loadMailSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(mailCookieName(r))
		if err != nil || !strings.HasPrefix(r.URL.Path, "/mail") {
			next.ServeHTTP(w, r)
			return
		}
		sec := s.security(r.Context())
		x, err := s.store.MailSessionByToken(r.Context(), c.Value, time.Duration(sec.IdleMinutes)*time.Minute)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.serverError(w, r, err)
				return
			}
			s.clearMailCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}
		ok, err := s.store.MailboxActive(r.Context(), x.MailboxID)
		if err != nil || !ok {
			_ = s.store.DeleteMailSession(r.Context(), x.Hash)
			s.clearMailCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), ctxMailSession, x)
		if x.Stage == store.StageFull {
			m, err := s.store.MailboxByID(r.Context(), store.Staff, x.MailboxID)
			if err != nil {
				s.clearMailCookie(w, r)
				next.ServeHTTP(w, r)
				return
			}
			_ = s.store.TouchMailSession(r.Context(), x)
			ctx = context.WithValue(ctx, ctxMailbox, m)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireMailUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mailboxFrom(r) == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/mail/login?next="+url.QueryEscape(safeNext(r.URL.RequestURI())), http.StatusSeeOther)
				return
			}
			http.Error(w, "signed out", http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

func (s *Server) mailUserRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /mail/login", s.handleMailLogin)
	mux.HandleFunc("POST /mail/login", s.handleMailLogin)
	mux.HandleFunc("GET /mail/login/2fa", s.handleMailLogin2FA)
	mux.HandleFunc("POST /mail/login/2fa", s.handleMailLogin2FA)
	mux.HandleFunc("GET /mail/login/enroll", s.handleMailEnroll)
	mux.HandleFunc("POST /mail/login/enroll", s.handleMailEnroll)
	mux.HandleFunc("POST /mail/logout", s.handleMailLogout)
	mux.HandleFunc("POST /mail/lang", s.handleMailLang)
	m := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireMailUser(h)) }
	m("GET /mail", s.handleMailHome)
	m("GET /mail/{$}", s.handleMailHome)
	m("POST /mail/password", s.handleMailPassword)
	m("POST /mail/apppasswords", s.handleMailAppPasswordCreate)
	m("POST /mail/apppasswords/{id}/delete", s.handleMailAppPasswordDelete)
	s.webmailRoutes(m)
	m("GET /mail/mobileconfig", s.handleMobileconfig)
	m("GET /mail/filters", s.handleFilters)
	m("POST /mail/filters", s.handleFiltersSave)
	m("POST /mail/spam", s.handleMailSpam)
}

// mailLang is the language of a mail user page.
func (s *Server) mailLang(r *http.Request, m *store.Mailbox) string {
	if m != nil && validLang(m.Lang) {
		return m.Lang
	}
	return s.lang(r, nil)
}

func (s *Server) handleMailLogin(w http.ResponseWriter, r *http.Request) {
	d := &loginData{Next: safeMailNext(r.FormValue("next")), Base: "/mail"}
	p := &Page{Title: "Sign in to your mailbox", Data: d}
	if r.Method == http.MethodGet {
		if mailboxFrom(r) != nil {
			http.Redirect(w, r, d.Next, http.StatusSeeOther)
			return
		}
		s.render(w, r, http.StatusOK, "login", p)
		return
	}
	d.Username = strings.TrimSpace(r.FormValue("username"))
	ip := clientIP(r)
	lang := s.lang(r, nil)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
		p.Error = translate(lang, "Too many failed attempts from your address. Try again after %s.", until.Local().Format("15:04"))
		s.render(w, r, http.StatusTooManyRequests, "login", p)
		return
	}
	key := "mail:" + strings.ToLower(d.Username)
	if s.guard.userThrottled(key) {
		auth.BurnTime(r.FormValue("password"))
		p.Error = translate(lang, "Too many failed attempts for this user. Try again later.")
		s.render(w, r, http.StatusTooManyRequests, "login", p)
		return
	}
	m, err := s.store.CheckMailboxPassword(r.Context(), d.Username, r.FormValue("password"))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		s.guard.fail(r.Context(), ip, key, "mail password")
		s.auditAs(r, d.Username, "mail.login.failed", "mailbox:"+strings.ToLower(d.Username), "wrong address or password")
		p.Error = translate(lang, "Wrong address or password.")
		s.render(w, r, http.StatusUnauthorized, "login", p)
		return
	}
	stage := store.StageMFA
	next := "/mail/login/2fa"
	if !m.TOTPEnabled {
		stage, next = store.StageEnroll, "/mail/login/enroll"
	}
	tok, _, err := s.store.CreateMailSession(r.Context(), m.ID, stage, store.MFATimeout, ip, r.UserAgent())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setMailCookie(w, r, tok, store.MFATimeout)
	http.Redirect(w, r, next+"?next="+url.QueryEscape(d.Next), http.StatusSeeOther)
}

// safeMailNext keeps mail user redirects inside /mail.
func safeMailNext(p string) string {
	p = safeNext(p)
	if p == "/mail" || strings.HasPrefix(p, "/mail/") || strings.HasPrefix(p, "/mail?") {
		return p
	}
	return "/mail"
}

// pendingMailbox is the mailbox of a password-verified sign-in.
func (s *Server) pendingMailbox(r *http.Request, stage string) (*store.MailSession, *store.Mailbox) {
	x := mailSessionFrom(r)
	if x == nil || x.Stage != stage {
		return nil, nil
	}
	m, err := s.store.MailboxByID(r.Context(), store.Staff, x.MailboxID)
	if err != nil {
		return nil, nil
	}
	return x, m
}

func (s *Server) finishMailLogin(w http.ResponseWriter, r *http.Request, x *store.MailSession, m *store.Mailbox, how string) bool {
	sec := s.security(r.Context())
	life := time.Duration(sec.SessionHours) * time.Hour
	tok, err := s.store.PromoteMailSession(r.Context(), x, life)
	if err != nil {
		s.serverError(w, r, err)
		return false
	}
	s.setMailCookie(w, r, tok, life)
	// the webmail signs in to IMAP/SMTP with its own short-lived token
	if wt, err := s.store.CreateWebmailToken(r.Context(), m.ID, life); err == nil {
		_ = s.store.SetSessionWebmail(r.Context(), auth.HashToken("mailsession", tok), wt)
	}
	_ = s.store.MarkMailboxLogin(r.Context(), m.ID)
	s.guard.success(clientIP(r), "mail:"+m.Address)
	s.auditAs(r, m.Address, "mail.login", "mailbox:"+m.Address, "signed in (%s)", how)
	return true
}

func (s *Server) handleMailLogin2FA(w http.ResponseWriter, r *http.Request) {
	x, m := s.pendingMailbox(r, store.StageMFA)
	if m == nil {
		http.Redirect(w, r, "/mail/login", http.StatusSeeOther)
		return
	}
	d := &twoFAData{Next: safeMailNext(r.FormValue("next")), Base: "/mail"}
	p := &Page{Title: "Two-factor sign-in", Data: d, Lang: s.mailLang(r, m)}
	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "login2fa", p)
		return
	}
	ip := clientIP(r)
	key := "mail:" + m.Address
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() || s.guard.userThrottled(key) {
		_ = s.store.DeleteMailSession(r.Context(), x.Hash)
		s.clearMailCookie(w, r)
		http.Redirect(w, r, "/mail/login", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	ok, how := false, "authenticator code"
	if len(strings.ReplaceAll(code, " ", "")) == 6 {
		tf, err := s.store.MailboxTwoFactor(r.Context(), m.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if step, good := auth.TOTPVerify(tf.Secret, code, s.now(), tf.LastStep); good {
			ok, _ = s.store.UseMailboxTOTPStep(r.Context(), m.ID, step)
		}
	} else if code != "" {
		ok, _ = s.store.UseMailboxRecoveryCode(r.Context(), m.ID, code)
		how = "recovery code"
	}
	if !ok {
		s.guard.fail(r.Context(), ip, key, "second factor")
		s.auditAs(r, m.Address, "mail.login.failed", "mailbox:"+m.Address, "wrong second-factor code")
		p.Error = p.T("The code is wrong or was already used.")
		s.render(w, r, http.StatusUnauthorized, "login2fa", p)
		return
	}
	if s.finishMailLogin(w, r, x, m, how) {
		http.Redirect(w, r, d.Next, http.StatusSeeOther)
	}
}

// handleMailEnroll sets up the mandatory authenticator app of a mail user.
func (s *Server) handleMailEnroll(w http.ResponseWriter, r *http.Request) {
	x, m := s.pendingMailbox(r, store.StageEnroll)
	if m == nil {
		http.Redirect(w, r, "/mail/login", http.StatusSeeOther)
		return
	}
	d := &enrollData{Next: safeMailNext(r.FormValue("next")), Base: "/mail"}
	p := &Page{Title: "Set up two-factor sign-in", Data: d, Lang: s.mailLang(r, m)}
	show := func(status int) {
		tf, err := s.store.MailboxTwoFactor(r.Context(), m.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if tf.Secret == "" {
			tf.Secret = auth.NewTOTPSecret()
			if err := s.store.SetMailboxPendingTOTP(r.Context(), m.ID, tf.Secret); err != nil {
				s.serverError(w, r, err)
				return
			}
		}
		d.Secret = tf.Secret
		d.QR, _ = auth.QRFor(auth.TOTPURI(tf.Secret, m.Address))
		s.render(w, r, status, "enroll", p)
	}
	if r.Method == http.MethodGet {
		show(http.StatusOK)
		return
	}
	tf, err := s.store.MailboxTwoFactor(r.Context(), m.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	step, ok := auth.TOTPVerify(tf.Secret, r.FormValue("code"), s.now(), 0)
	if tf.Secret == "" || !ok {
		s.guard.fail(r.Context(), clientIP(r), "mail:"+m.Address, "second factor setup")
		p.Error = p.T("The code is wrong. Check that the time of your phone is correct and try again.")
		show(http.StatusBadRequest)
		return
	}
	plain, hashed := auth.NewRecoveryCodes()
	if err := s.store.EnableMailboxTOTP(r.Context(), m.ID, step, hashed); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.auditAs(r, m.Address, "mail.2fa.enable", "mailbox:"+m.Address, "authenticator app set up")
	if !s.finishMailLogin(w, r, x, m, "new authenticator") {
		return
	}
	d.Codes = plain
	s.render(w, r, http.StatusOK, "recoverycodes", p)
}

func (s *Server) handleMailLogout(w http.ResponseWriter, r *http.Request) {
	if x := mailSessionFrom(r); x != nil {
		if wt, err := s.store.SessionWebmail(r.Context(), x.Hash); err == nil && wt != "" {
			_ = s.store.DeleteWebmailToken(r.Context(), wt)
		}
		_ = s.store.DeleteMailSession(r.Context(), x.Hash)
		if m := mailboxFrom(r); m != nil {
			s.auditAs(r, m.Address, "mail.logout", "mailbox:"+m.Address, "signed out")
		}
	}
	s.clearMailCookie(w, r)
	http.Redirect(w, r, "/mail/login", http.StatusSeeOther)
}

func (s *Server) handleMailLang(w http.ResponseWriter, r *http.Request) {
	l := r.FormValue("lang")
	if !validLang(l) {
		http.Error(w, "unknown language", http.StatusBadRequest)
		return
	}
	if m := mailboxFrom(r); m != nil {
		_ = s.store.SetMailboxLang(r.Context(), m.ID, l)
	}
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: "lang", Value: l, Path: "/", MaxAge: 365 * 86400, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	back := "/mail"
	if ref, err := url.Parse(r.Referer()); err == nil && ref.Host == r.Host {
		back = safeMailNext(ref.RequestURI())
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// ---- the mail user's home page

type mailHomeData struct {
	M            *store.Mailbox
	AppPasswords []*store.AppPassword
	NewPassword  string // shown once
	NewName      string
	Mail         MailSettings
}

func (s *Server) mailPage(r *http.Request, title string, d any) *Page {
	m := mailboxFrom(r)
	return &Page{Title: title, Nav: "mail", Lang: s.mailLang(r, m), Data: d}
}

func (s *Server) handleMailHome(w http.ResponseWriter, r *http.Request) {
	s.showMailHome(w, r, http.StatusOK, &mailHomeData{}, "")
}

func (s *Server) showMailHome(w http.ResponseWriter, r *http.Request, status int, d *mailHomeData, errMsg string) {
	m := mailboxFrom(r)
	d.M, d.Mail = m, s.MailConfig(r.Context())
	var err error
	if d.AppPasswords, err = s.store.AppPasswords(r.Context(), m.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	p := s.mailPage(r, "My mailbox", d)
	if errMsg != "" {
		p.Error = translate(p.Lang, errMsg)
	}
	s.render(w, r, status, "mailhome", p)
}

func (s *Server) handleMailPassword(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	if r.FormValue("new") != r.FormValue("new2") {
		s.showMailHome(w, r, http.StatusBadRequest, &mailHomeData{}, "The passwords do not match.")
		return
	}
	if err := s.store.ChangeMailboxPassword(r.Context(), m.ID, r.FormValue("old"), r.FormValue("new"), mailSessionFrom(r).Hash); err != nil {
		s.guard.fail(r.Context(), clientIP(r), "mail:"+m.Address, "password change")
		s.showMailHome(w, r, http.StatusBadRequest, &mailHomeData{}, err.Error())
		return
	}
	s.auditAs(r, m.Address, "mail.password", "mailbox:"+m.Address, "own web password changed; other sessions signed out")
	s.redirect(w, r, "/mail", "Password changed.")
}

func (s *Server) handleMailAppPasswordCreate(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	pw, ap, err := s.store.CreateAppPassword(r.Context(), m.ID, r.FormValue("name"))
	if err != nil {
		s.showMailHome(w, r, http.StatusBadRequest, &mailHomeData{}, err.Error())
		return
	}
	s.auditAs(r, m.Address, "mail.apppassword.create", "mailbox:"+m.Address, "app password %q created", ap.Name)
	s.showMailHome(w, r, http.StatusOK, &mailHomeData{NewPassword: pw, NewName: ap.Name}, "")
}

func (s *Server) handleMailAppPasswordDelete(w http.ResponseWriter, r *http.Request) {
	m := mailboxFrom(r)
	if err := s.store.DeleteAppPassword(r.Context(), m.ID, r.PathValue("id")); err != nil {
		s.redirectErr(w, r, "/mail", mailErr(err))
		return
	}
	s.auditAs(r, m.Address, "mail.apppassword.delete", "mailbox:"+m.Address, "app password %s revoked", r.PathValue("id"))
	s.redirect(w, r, "/mail", "App password revoked.")
}
