package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

type shareMail struct {
	stubMail
	calls []string
}

func (m *shareMail) Share(_ context.Context, owner, with, folder, rights string) error {
	m.calls = append(m.calls, fmt.Sprintf("%s|%s|%s|%s", owner, with, folder, rights))
	return nil
}

// The panel is only half of a shared folder: the rights live in the mail
// store, so every change has to reach the helper, and everything has to
// be written again after a restore, which carries the database and not
// the mail.
func TestSharedFolders(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	s.DevNo2FA = true
	mail := &shareMail{}
	s.Mail = mail
	const pw = "correct horse battery staple"
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "admin", Password: pw, Role: store.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	p := &store.Package{Slug: "sh", Name: "SH", MaxDomains: 2, MaxMailboxes: 4, MaxAliases: 2, StorageMB: 400, MailboxMB: 100, MaxMailboxMB: 200, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "Office", PackageID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	d, err := st.CreateDomain(ctx, store.Staff, c.ID, "office.test", true)
	if err != nil {
		t.Fatal(err)
	}
	info, err := st.CreateMailbox(ctx, store.Staff, store.NewMailbox{DomainID: d.ID, LocalPart: "info", Password: "a-long-password-1"})
	if err != nil {
		t.Fatal(err)
	}
	ana, err := st.CreateMailbox(ctx, store.Staff, store.NewMailbox{DomainID: d.ID, LocalPart: "ana", Password: "a-long-password-2"})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if loc := post(t, cl, srv.URL, "/login", url.Values{"username": {"admin"}, "password": {pw}}); loc != "/" {
		t.Fatalf("sign-in went to %q", loc)
	}

	t.Run("sharing reaches the mail server", func(t *testing.T) {
		loc := post(t, cl, srv.URL, "/mailboxes/"+info.ID+"/share",
			url.Values{"with": {ana.ID}, "folder": {"INBOX"}, "rights": {"write"}})
		if loc != "/mailboxes/"+info.ID {
			t.Fatalf("the form answered %q", loc)
		}
		want := info.Address + "|" + ana.Address + "|INBOX|write"
		if len(mail.calls) != 1 || mail.calls[0] != want {
			t.Fatalf("the helper got %q, want %q", mail.calls, want)
		}
		shared, _, err := st.SharesOf(ctx, store.Staff, info.ID)
		if err != nil || len(shared) != 1 {
			t.Fatalf("saved %+v (%v)", shared, err)
		}
	})

	t.Run("the page shows it to both sides", func(t *testing.T) {
		body := func(path string) string {
			t.Helper()
			resp, err := cl.Get(srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s answered %d: %s", path, resp.StatusCode, b)
			}
			return string(b)
		}
		if page := body("/mailboxes/" + info.ID); !strings.Contains(page, ana.Address) {
			t.Error("the owner's page does not name the mailbox the folder is open for")
		}
		if page := body("/mailboxes/" + ana.ID); !strings.Contains(page, "shared/"+info.Address+"/INBOX") {
			t.Error("the other page does not say what it may use")
		}
	})

	t.Run("everything is written again at a start", func(t *testing.T) {
		mail.calls = nil
		s.syncShares(ctx)
		if len(mail.calls) != 1 || !strings.HasSuffix(mail.calls[0], "|INBOX|write") {
			t.Fatalf("the helper got %q", mail.calls)
		}
	})

	t.Run("closing it reaches the mail server too", func(t *testing.T) {
		mail.calls = nil
		loc := post(t, cl, srv.URL, "/mailboxes/"+info.ID+"/share/delete",
			url.Values{"with": {ana.ID}, "folder": {"INBOX"}})
		if loc != "/mailboxes/"+info.ID {
			t.Fatalf("the form answered %q", loc)
		}
		want := info.Address + "|" + ana.Address + "|INBOX|"
		if len(mail.calls) != 1 || mail.calls[0] != want {
			t.Fatalf("the helper got %q, want %q", mail.calls, want)
		}
		if all, _ := st.AllShares(ctx); len(all) != 0 {
			t.Fatalf("the share is still saved: %+v", all)
		}
	})
}
