package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The notices have to reach the administrators exactly when the mail of
// this server does not: a server refused by a receiver cannot report that
// by mail. The webhook and Telegram are therefore tried even when the
// mail went nowhere.
func TestNoticeChannels(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)

	var hooks []webhookPayload
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p webhookPayload
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err := json.Unmarshal(b, &p); err != nil {
			t.Errorf("the webhook got no JSON: %s", b)
		}
		hooks = append(hooks, p)
	}))
	defer hook.Close()

	var tgPaths, tgTexts []string
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tgPaths = append(tgPaths, r.URL.Path)
		tgTexts = append(tgTexts, r.FormValue("text"))
	}))
	defer tg.Close()
	old := telegramAPI
	telegramAPI = tg.URL
	t.Cleanup(func() { telegramAPI = old })

	m := s.MailConfig(ctx)
	m.Hostname = "mail.ours.test"
	if err := st.SetSetting(ctx, settingMail, m); err != nil {
		t.Fatal(err)
	}
	ch := ChannelSettings{Webhook: hook.URL + "/notice", TelegramChat: "-1001234567890",
		TelegramToken: st.SealSecret(telegramSecret, "123456:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	if err := st.SetSetting(ctx, settingChannels, ch); err != nil {
		t.Fatal(err)
	}

	t.Run("a notice goes out although the mail fails", func(t *testing.T) {
		s.SystemMail = func(context.Context, string, []string, string, string) error {
			return errors.New("the mail of this server is refused")
		}
		m := s.MailConfig(ctx)
		m.NoticeTo = "admin@ours.test"
		if err := st.SetSetting(ctx, settingMail, m); err != nil {
			t.Fatal(err)
		}
		s.notifyAdmins(ctx, "receiver-blocked", "a receiver refuses our mail", "hotmail.com refused 6 messages")
		if len(hooks) != 1 {
			t.Fatalf("the webhook got %d notices", len(hooks))
		}
		got := hooks[0]
		if got.Product != "emailzit" || got.Server != "mail.ours.test" || got.Key != "receiver-blocked" {
			t.Errorf("the payload is wrong: %+v", got)
		}
		if !strings.Contains(got.Text, "hotmail.com") || got.Subject != "a receiver refuses our mail" {
			t.Errorf("the payload lost the notice: %+v", got)
		}
		if len(tgTexts) != 1 || !strings.Contains(tgTexts[0], "hotmail.com") || !strings.Contains(tgTexts[0], "mail.ours.test") {
			t.Errorf("Telegram got %q", tgTexts)
		}
		if len(tgPaths) != 1 || !strings.HasPrefix(tgPaths[0], "/bot123456:") {
			t.Errorf("the bot token is not used as the path: %q", tgPaths)
		}
	})

	t.Run("a notice goes out without any mail address", func(t *testing.T) {
		m := s.MailConfig(ctx)
		m.NoticeTo = ""
		if err := st.SetSetting(ctx, settingMail, m); err != nil {
			t.Fatal(err)
		}
		s.notifyAdmins(ctx, "weekly-report", "weekly report", "nothing to report")
		if len(hooks) != 2 || hooks[1].Key != "weekly-report" {
			t.Fatalf("the webhook got %+v", hooks)
		}
	})

	t.Run("a broken channel is reported but does not stop the other", func(t *testing.T) {
		bad := ch
		bad.Webhook = "http://127.0.0.1:1/nothing-here"
		if err := st.SetSetting(ctx, settingChannels, bad); err != nil {
			t.Fatal(err)
		}
		before := len(tgTexts)
		err := s.sendChannels(ctx, "test", "test", "body")
		if err == nil || !strings.Contains(err.Error(), "webhook") {
			t.Errorf("the broken webhook was not reported: %v", err)
		}
		if len(tgTexts) != before+1 {
			t.Error("Telegram was skipped because the webhook failed")
		}
		if err := st.SetSetting(ctx, settingChannels, ch); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("what is not a channel is refused", func(t *testing.T) {
		for _, u := range []string{"ftp://example.com/x", "https://user:pw@example.com/x", "not a url", "https:// example.com", ""} {
			if validWebhook(u) {
				t.Errorf("%q was accepted as a webhook", u)
			}
		}
		if !validWebhook("https://example.com/hook?x=1") {
			t.Error("a normal webhook was refused")
		}
		for _, tok := range []string{"123456:short", "nocolon", "123456:" + strings.Repeat("a", 100)} {
			if telegramTokenRE.MatchString(tok) {
				t.Errorf("%q was accepted as a bot token", tok)
			}
		}
		for _, chat := range []string{"", "name", "@a", "12 34"} {
			if telegramChatRE.MatchString(chat) {
				t.Errorf("%q was accepted as a chat", chat)
			}
		}
	})
}
