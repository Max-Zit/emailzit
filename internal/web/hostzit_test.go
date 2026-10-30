package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

func TestHostZitLink(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	var mu sync.Mutex
	got := map[string][]hzRecord{}
	var deleted []string
	var customer string
	hz := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer hzt_test" {
			w.WriteHeader(401)
			return
		}
		zone := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/dns/zones/"), "/owned/emailzit")
		if zone == "elsewhere.test" {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"no such zone"}}`)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var in struct {
				CustomerID string     `json:"customer_id"`
				Records    []hzRecord `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			got[zone], customer = in.Records, in.CustomerID
			_, _ = io.WriteString(w, `{"zone":"`+zone+`"}`)
		case http.MethodDelete:
			deleted = append(deleted, zone)
		}
	}))
	defer hz.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.SetSetting(ctx, settingMail, MailSettings{Hostname: "mail.example.net", RequireVerification: true, MaxMessageMB: 25}))
	must(st.SetSetting(ctx, settingHostZit, HostZitLink{URL: hz.URL, Token: st.SealSecret("hostzit.token", "hzt_test"), Insecure: true}))
	p := &store.Package{Slug: "p", Name: "P", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 100, MailboxMB: 10, MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	must(st.SavePackage(ctx, p))
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "C", PackageID: p.ID})
	must(err)
	d, err := st.CreateDomain(ctx, store.Staff, c.ID, "hosted.test", false)
	must(err)
	s.installDKIM(ctx, d.ID)
	s.publishDNS(ctx, d.ID, false, nil)
	mu.Lock()
	recs := got["hosted.test"]
	mu.Unlock()
	if customer != c.ID || len(recs) < 8 {
		t.Fatalf("customer %q, %d records", customer, len(recs))
	}
	seen := map[string]string{}
	for _, r := range recs {
		seen[r.Type+" "+r.Name] = r.Content
		if strings.HasPrefix(r.Name, "_emailzit") || strings.HasSuffix(r.Content, ".") || r.TTL != 3600 {
			t.Errorf("record %+v", r)
		}
	}
	if seen["MX @"] != "10 mail.example.net" || !strings.HasPrefix(seen["TXT _dmarc"], "v=DMARC1") || seen["CNAME autoconfig"] != "mail.example.net" {
		t.Fatalf("records %v", seen)
	}
	var dkim bool
	for k := range seen {
		if strings.HasPrefix(k, "TXT ez") && strings.HasSuffix(k, "._domainkey") {
			dkim = true
		}
	}
	if !dkim {
		t.Fatal("no DKIM record")
	}
	d, _ = st.DomainByID(ctx, store.Staff, d.ID)
	if !d.Verified || !d.DNSManaged {
		t.Fatal("domain hosted in HostZit not verified/managed")
	}
	// a zone HostZit does not host stays unverified with a note
	e, err := st.CreateDomain(ctx, store.Staff, c.ID, "elsewhere.test", false)
	must(err)
	s.publishDNS(ctx, e.ID, false, nil)
	e, _ = st.DomainByID(ctx, store.Staff, e.ID)
	if e.Verified || e.DNSManaged || e.DNSNote != errNoZone.Error() {
		t.Fatalf("elsewhere: %+v", e)
	}
	s.publishDNS(ctx, d.ID, true, d)
	if len(deleted) != 1 || deleted[0] != "hosted.test" {
		t.Fatalf("delete: %v", deleted)
	}

	// HostZit tells EmailZit the hosting user IDs
	tok, _, err := st.CreateAPIToken(ctx, "hostzit", []string{store.ScopeCustomersWrite}, nil, 0, "admin")
	must(err)
	h := s.Handler()
	if code, m := call(t, h, "PUT", "/api/v1/customers/"+c.ID+"/web-uids", tok, `{"uids":[1000012]}`); code != 200 {
		t.Fatalf("web-uids: %d %v", code, m)
	}
	if code, _ := call(t, h, "PUT", "/api/v1/customers/"+c.ID+"/web-uids", tok, `{"uids":[2000001]}`); code != 400 {
		t.Fatalf("mail uid accepted as web uid: %d", code)
	}
	if u, _ := st.WebUIDs(ctx, c.ID); len(u) != 1 || u[0] != 1000012 {
		t.Fatal(u)
	}
}
