package store

import (
	"context"
	"errors"
	"time"

	"github.com/max-zit/emailzit/internal/auth"
)

// Mail users (mailbox owners) sign in to webmail and their own settings
// with the address, the web password and always a second factor. Mail
// programs never use the web password: they get app passwords.

// MailSession is a sign-in of a mail user.
type MailSession struct {
	Hash      string
	MailboxID string
	Stage     string // mfa, enroll (no second factor yet: must set it up), full
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

// StageEnroll is a password-verified sign-in of a mail user that has to set
// up the second factor before anything else.
const StageEnroll = "enroll"

// CheckMailboxPassword verifies the web password of a mailbox. Unknown
// addresses, disabled mailboxes, mailboxes of customers that are not
// active and wrong passwords all give ErrNotFound after the same work.
func (s *Store) CheckMailboxPassword(ctx context.Context, addr, password string) (*Mailbox, error) {
	a, err := ParseAddress(addr)
	if err != nil {
		auth.BurnTime(password)
		return nil, ErrNotFound
	}
	var id, hash, status string
	var disabled, domDisabled bool
	err = s.db.QueryRow(ctx, `SELECT m.id, m.web_password_hash, m.disabled, d.disabled, c.status FROM mailboxes m
		JOIN domains d ON d.id=m.domain_id JOIN customers c ON c.id=m.customer_id WHERE m.address=$1`, a).
		Scan(&id, &hash, &disabled, &domDisabled, &status)
	if err != nil || hash == "" {
		auth.BurnTime(password)
		return nil, ErrNotFound
	}
	ok, err := auth.VerifyPassword(hash, password)
	if err != nil {
		return nil, err
	}
	if !ok || disabled || domDisabled || status != CustomerActive {
		return nil, ErrNotFound
	}
	return s.MailboxByID(ctx, Staff, id)
}

// MailboxActive reports whether a mailbox may still be used (checked on
// every request of a mail user session).
func (s *Store) MailboxActive(ctx context.Context, id string) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT NOT m.disabled AND NOT d.disabled AND c.status='active' FROM mailboxes m
		JOIN domains d ON d.id=m.domain_id JOIN customers c ON c.id=m.customer_id WHERE m.id=$1`, id).Scan(&ok)
	if err != nil {
		return false, notFound(err)
	}
	return ok, nil
}

// CreateMailSession starts a mail user session and returns the cookie value.
func (s *Store) CreateMailSession(ctx context.Context, mailboxID, stage string, life time.Duration, ip, ua string) (string, *MailSession, error) {
	tok := auth.RandomToken(32)
	now := s.now()
	if len(ua) > 300 {
		ua = ua[:300]
	}
	x := &MailSession{Hash: auth.HashToken("mailsession", tok), MailboxID: mailboxID, Stage: stage, CreatedAt: now, LastSeen: now,
		ExpiresAt: now.Add(life), IP: ip, UserAgent: ua}
	_, err := s.db.Exec(ctx, `INSERT INTO mail_sessions(token_hash, mailbox_id, stage, created_at, last_seen, expires_at, ip, user_agent)
		VALUES($1,$2,$3,$4,$4,$5,$6,$7)`, x.Hash, mailboxID, stage, now, x.ExpiresAt, ip, ua)
	return tok, x, err
}

// MailSessionByToken loads a mail user session; expired or idle sessions
// are deleted and reported as ErrNotFound.
func (s *Store) MailSessionByToken(ctx context.Context, tok string, idle time.Duration) (*MailSession, error) {
	if tok == "" {
		return nil, ErrNotFound
	}
	x := &MailSession{Hash: auth.HashToken("mailsession", tok)}
	err := s.db.QueryRow(ctx, `SELECT mailbox_id, stage, created_at, last_seen, expires_at, ip, user_agent FROM mail_sessions WHERE token_hash=$1`, x.Hash).
		Scan(&x.MailboxID, &x.Stage, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt, &x.IP, &x.UserAgent)
	if err != nil {
		return nil, notFound(err)
	}
	now := s.now()
	if now.After(x.ExpiresAt) || (idle > 0 && x.Stage == StageFull && now.Sub(x.LastSeen) > idle) {
		_ = s.DeleteMailSession(ctx, x.Hash)
		return nil, ErrNotFound
	}
	return x, nil
}

// TouchMailSession updates the last activity (at most once a minute).
func (s *Store) TouchMailSession(ctx context.Context, x *MailSession) error {
	now := s.now()
	if now.Sub(x.LastSeen) < time.Minute {
		return nil
	}
	x.LastSeen = now
	_, err := s.db.Exec(ctx, `UPDATE mail_sessions SET last_seen=$2 WHERE token_hash=$1`, x.Hash, now)
	return err
}

// PromoteMailSession turns a pending sign-in into a full session under a
// new token.
func (s *Store) PromoteMailSession(ctx context.Context, x *MailSession, life time.Duration) (string, error) {
	if err := s.DeleteMailSession(ctx, x.Hash); err != nil {
		return "", err
	}
	tok, _, err := s.CreateMailSession(ctx, x.MailboxID, StageFull, life, x.IP, x.UserAgent)
	return tok, err
}

// DeleteMailSession signs a mail user session out.
func (s *Store) DeleteMailSession(ctx context.Context, hash string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM mail_sessions WHERE token_hash=$1`, hash)
	return err
}

// PurgeMailSessions deletes expired sessions and webmail tokens.
func (s *Store) PurgeMailSessions(ctx context.Context) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM mail_sessions WHERE expires_at < $1`, s.now()); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM app_passwords WHERE kind='webmail' AND expires_at < $1`, s.now())
	return err
}

// MarkMailboxLogin records a successful sign-in.
func (s *Store) MarkMailboxLogin(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `UPDATE mailboxes SET last_login_at=$2 WHERE id=$1`, id, s.now())
	return err
}

// SetMailboxLang stores the language of a mail user.
func (s *Store) SetMailboxLang(ctx context.Context, id, lang string) error {
	_, err := s.db.Exec(ctx, `UPDATE mailboxes SET lang=$2 WHERE id=$1`, id, lang)
	return err
}

// ChangeMailboxPassword is the mail user's own password change: the old
// password must be right; other sessions end.
func (s *Store) ChangeMailboxPassword(ctx context.Context, id, oldPw, newPw, keepSession string) error {
	var hash string
	if err := s.db.QueryRow(ctx, `SELECT web_password_hash FROM mailboxes WHERE id=$1`, id).Scan(&hash); err != nil {
		return notFound(err)
	}
	ok, err := auth.VerifyPassword(hash, oldPw)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the current password is wrong")
	}
	if err := auth.CheckPasswordPolicy(newPw); err != nil {
		return err
	}
	h, err := auth.HashPassword(newPw)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(ctx, `UPDATE mailboxes SET web_password_hash=$2 WHERE id=$1`, id, h); err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM mail_sessions WHERE mailbox_id=$1 AND token_hash<>$2`, id, keepSession)
	return err
}

// ---- second factor of mail users

// MailboxTwoFactor loads the second factor of a mailbox.
func (s *Store) MailboxTwoFactor(ctx context.Context, id string) (TwoFactor, error) {
	var t TwoFactor
	var sealed string
	err := s.db.QueryRow(ctx, `SELECT totp_enabled, totp_secret, totp_last_step, recovery_codes FROM mailboxes WHERE id=$1`, id).
		Scan(&t.Enabled, &sealed, &t.LastStep, &t.Codes)
	if err != nil {
		return t, notFound(err)
	}
	t.Secret, err = s.box.open("mailboxes.totp_secret", sealed)
	return t, err
}

// SetMailboxPendingTOTP stores a secret that is not confirmed yet.
func (s *Store) SetMailboxPendingTOTP(ctx context.Context, id, secret string) error {
	tag, err := s.db.Exec(ctx, `UPDATE mailboxes SET totp_secret=$2, totp_last_step=0 WHERE id=$1 AND NOT totp_enabled`,
		id, s.box.seal("mailboxes.totp_secret", secret))
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("two-factor sign-in is already set up")
	}
	return err
}

// EnableMailboxTOTP confirms the pending secret.
func (s *Store) EnableMailboxTOTP(ctx context.Context, id string, step int64, recoveryHashes []string) error {
	tag, err := s.db.Exec(ctx, `UPDATE mailboxes SET totp_enabled=true, totp_last_step=$2, recovery_codes=$3 WHERE id=$1 AND NOT totp_enabled AND totp_secret<>''`,
		id, step, recoveryHashes)
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("no pending two-factor setup")
	}
	return err
}

// UseMailboxTOTPStep records the last accepted step (no replay).
func (s *Store) UseMailboxTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE mailboxes SET totp_last_step=$2 WHERE id=$1 AND totp_last_step<$2`, id, step)
	return err == nil && tag.RowsAffected() == 1, err
}

// UseMailboxRecoveryCode consumes a recovery code of a mail user.
func (s *Store) UseMailboxRecoveryCode(ctx context.Context, id, code string) (bool, error) {
	h := auth.HashRecoveryCode(code)
	tag, err := s.db.Exec(ctx, `UPDATE mailboxes SET recovery_codes=array_remove(recovery_codes,$2) WHERE id=$1 AND $2=ANY(recovery_codes)`, id, h)
	return err == nil && tag.RowsAffected() == 1, err
}

// ---- webmail tokens

// CreateWebmailToken makes a short-lived password with which the built-in
// webmail signs in to IMAP and SMTP for a mail user session. Dovecot
// accepts it only from the server itself.
func (s *Store) CreateWebmailToken(ctx context.Context, mailboxID string, life time.Duration) (string, error) {
	pw := auth.RandomToken(32)
	_, err := s.db.Exec(ctx, `INSERT INTO app_passwords(id, mailbox_id, kind, name, hash, created_at, expires_at) VALUES($1,$2,'webmail','webmail',$3,$4,$5)`,
		NewID(), mailboxID, HashAppPassword(pw), s.now(), s.now().Add(life))
	return pw, err
}

// DeleteWebmailToken removes a webmail token (sign-out).
func (s *Store) DeleteWebmailToken(ctx context.Context, pw string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM app_passwords WHERE kind='webmail' AND hash=$1`, HashAppPassword(pw))
	return err
}
