package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

func TestPublicHandler(t *testing.T) {
	s, st := testServer(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, settingMail, MailSettings{Hostname: "mail.example.net", MaxMessageMB: 25}); err != nil {
		t.Fatal(err)
	}
	p := &store.Package{Slug: "pub", Name: "Pub", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 100, MailboxMB: 10, MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	_ = st.SavePackage(ctx, p)
	c, _ := st.CreateCustomer(ctx, store.NewCustomer{Name: "Pub", PackageID: p.ID})
	if _, err := st.CreateDomain(ctx, store.Staff, c.ID, "acme.test", true); err != nil {
		t.Fatal(err)
	}
	h := s.PublicHandler("8444")
	get := func(method, host, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader("<Autodiscover><Request><EMailAddress>ana@acme.test</EMailAddress></Request></Autodiscover>"))
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := get("GET", "mail.example.net", "/"); w.Code != http.StatusFound || w.Header().Get("Location") != "https://mail.example.net:8444/mail" {
		t.Fatalf("root %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := get("GET", "autoconfig.acme.test", "/mail/config-v1.1.xml?emailaddress=ana@acme.test"); w.Code != 200 || !strings.Contains(w.Body.String(), "clientConfig") {
		t.Fatalf("autoconfig %d %s", w.Code, w.Body.String())
	}
	if w := get("POST", "autodiscover.acme.test", "/autodiscover/autodiscover.xml"); w.Code != 200 || !strings.Contains(w.Body.String(), "Autodiscover") {
		t.Fatalf("autodiscover %d %s", w.Code, w.Body.String())
	}
	// nothing of the panels is reachable here
	for _, p := range []string{"/login", "/api/v1/customers", "/mail/login", "/settings/mail"} {
		if w := get("POST", "mail.example.net", p); w.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
	if w := get("GET", "evil/../x", "/"); w.Code != http.StatusNotFound {
		t.Fatalf("bad host: %d", w.Code)
	}
}
