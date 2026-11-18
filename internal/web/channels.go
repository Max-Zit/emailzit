package web

// Notices that do not go by mail.
//
// Every notice of this server is a mail: the weekly report, an address on
// a block list, a mailbox blocked for spam, a receiver that refuses
// everything. That is exactly the wrong way round for the worst case — a
// mail server that cannot send mail cannot tell anybody that it cannot
// send mail. A webhook and Telegram are therefore not a nicety here but
// the way the bad news gets out at all.
//
// The same two channels exist in HostZit, with the same payload, so one
// receiving end understands both products.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const settingChannels = "notify_channels"

// ChannelSettings are the channels of the notices besides mail.
type ChannelSettings struct {
	// Webhook gets a JSON POST per notice.
	Webhook string `json:"webhook,omitempty"`
	// TelegramToken is the bot token, sealed with the server key.
	TelegramToken string `json:"telegram_token,omitempty"`
	TelegramChat  string `json:"telegram_chat,omitempty"`
}

// On tells whether anything is set up at all.
func (c ChannelSettings) On() bool {
	return c.Webhook != "" || (c.TelegramToken != "" && c.TelegramChat != "")
}

var (
	telegramTokenRE = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{30,64}$`)
	telegramChatRE  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
)

// telegramAPI is Telegram's Bot API (tests point it elsewhere).
var telegramAPI = "https://api.telegram.org"

func (s *Server) channelSettings(ctx context.Context) ChannelSettings {
	var c ChannelSettings
	_ = s.store.GetSetting(ctx, settingChannels, &c)
	return c
}

// webhookPayload is what the webhook gets.
type webhookPayload struct {
	Product string    `json:"product"`
	Server  string    `json:"server"`
	Key     string    `json:"key"`
	Subject string    `json:"subject"`
	Text    string    `json:"text"`
	Time    time.Time `json:"time"`
}

// sendChannels delivers one notice to the webhook and to Telegram; the
// errors of both are joined, so one broken channel does not hide the
// other.
func (s *Server) sendChannels(ctx context.Context, key, subject, body string) error {
	ch := s.channelSettings(ctx)
	if !ch.On() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	hc := &http.Client{Timeout: 20 * time.Second}
	server := s.MailConfig(ctx).Hostname
	var errs []error
	if ch.Webhook != "" {
		p := webhookPayload{Product: "emailzit", Server: server, Key: key, Subject: subject, Text: body, Time: s.now().UTC()}
		b, _ := json.Marshal(p)
		if err := postNotice(ctx, hc, ch.Webhook, "application/json", b); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}
	if ch.TelegramToken != "" && ch.TelegramChat != "" {
		tok, err := s.store.OpenSecret(telegramSecret, ch.TelegramToken)
		if err == nil {
			text := subject + "\n\n" + body
			if server != "" {
				text = "[" + server + "] " + text
			}
			if len(text) > 4000 {
				text = text[:4000]
			}
			form := url.Values{"chat_id": {ch.TelegramChat}, "text": {text}, "disable_web_page_preview": {"true"}}
			err = postNotice(ctx, hc, telegramAPI+"/bot"+tok+"/sendMessage", "application/x-www-form-urlencoded", []byte(form.Encode()))
		}
		if err != nil {
			// the token is part of the address: the error's URL never goes
			// into a log or onto a page
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			errs = append(errs, fmt.Errorf("telegram: %w", err))
		}
	}
	return errors.Join(errs...)
}

// telegramSecret is the purpose the bot token is sealed with.
const telegramSecret = "telegram.token"

func postNotice(ctx context.Context, hc *http.Client, u, ctype string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "EmailZit notifications")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("answer %d", resp.StatusCode)
	}
	return nil
}

// validWebhook checks the address of the webhook.
func validWebhook(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "https" || p.Scheme == "http") && p.Host != "" && p.User == nil &&
		len(u) <= 1000 && !strings.ContainsAny(u, " \r\n")
}

func (s *Server) handleChannelsSave(w http.ResponseWriter, r *http.Request) {
	old := s.channelSettings(r.Context())
	ch := ChannelSettings{Webhook: strings.TrimSpace(r.FormValue("webhook")),
		TelegramChat: strings.TrimSpace(r.FormValue("telegram_chat")), TelegramToken: old.TelegramToken}
	if ch.Webhook != "" && !validWebhook(ch.Webhook) {
		s.redirectErr(w, r, "/settings/mail", "The webhook must be an http(s) address.")
		return
	}
	if tok := strings.TrimSpace(r.FormValue("telegram_token")); tok != "" {
		if !telegramTokenRE.MatchString(tok) {
			s.redirectErr(w, r, "/settings/mail", "This is not a Telegram bot token (from @BotFather, like 123456:ABC…).")
			return
		}
		ch.TelegramToken = s.store.SealSecret(telegramSecret, tok)
	}
	if r.FormValue("telegram_off") != "" {
		ch.TelegramToken, ch.TelegramChat = "", ""
	}
	if ch.TelegramChat != "" && !telegramChatRE.MatchString(ch.TelegramChat) {
		s.redirectErr(w, r, "/settings/mail", "The Telegram chat is a number (like -1001234567890) or @channel.")
		return
	}
	if err := s.store.SetSetting(r.Context(), settingChannels, ch); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.channels", "settings", "webhook %t, telegram %t", ch.Webhook != "", ch.TelegramToken != "" && ch.TelegramChat != "")
	s.redirect(w, r, "/settings/mail", "Saved.")
}

func (s *Server) handleChannelsTest(w http.ResponseWriter, r *http.Request) {
	if !s.channelSettings(r.Context()).On() {
		s.redirectErr(w, r, "/settings/mail", "Enter a webhook or a Telegram bot first.")
		return
	}
	if err := s.sendChannels(r.Context(), "test", "test message",
		"This is a test message from the EmailZit panel. The notices of this server reach you here, also when its mail does not."); err != nil {
		s.redirectErr(w, r, "/settings/mail", err.Error())
		return
	}
	s.redirect(w, r, "/settings/mail", "The test message was sent.")
}
