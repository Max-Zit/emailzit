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

	// mail from the websites of the hosting account (emailzit-sendmail)
	l, err := st.WebSendLimits(ctx, 1000012)
	must(err)
	if l.CustomerID != c.ID || l.Blocked || l.PerHour != 1 || l.RcptPerMsg != 1 {
		t.Fatalf("limits %+v", l)
	}
	must(st.LogSent(ctx, l, 1, ""))
	if n, err := st.LogWebRefused(ctx, 1000012, "per hour"); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	must(st.SetWebSendBlocked(ctx, store.Staff, 1000012, true))
	// HostZit sending the list again keeps the block; another customer
	// cannot take the user ID
	must(st.SetWebUIDs(ctx, c.ID, []int{1000012, 1000013}))
	if l, _ = st.WebSendLimits(ctx, 1000012); !l.Blocked || l.SentHour != 1 || l.CustomerHour != 1 {
		t.Fatalf("after resend %+v", l)
	}
	c2, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "C2", PackageID: p.ID})
	must(err)
	if err := st.SetWebUIDs(ctx, c2.ID, []int{1000013}); err == nil {
		t.Fatal("user ID of another customer taken")
	}
	if err := st.SetWebSendBlocked(ctx, store.Scope{CustomerID: c2.ID}, 1000012, false); err == nil {
		t.Fatal("other customer unblocked")
	}
	if ws, _ := st.WebSenders(ctx, c.ID); len(ws) != 2 || !ws[0].Blocked || ws[0].Hour != 1 || ws[0].RefusedHour != 1 {
		t.Fatalf("senders %+v", ws)
	}
	if ok, _ := st.CustomerSendDomain(ctx, c.ID, "HOSTED.test"); !ok {
		t.Fatal("own verified domain")
	}
	if ok, _ := st.CustomerSendDomain(ctx, c.ID, "elsewhere.test"); ok {
		t.Fatal("unverified domain")
	}
	must(st.SetWebUIDs(ctx, c.ID, nil))
	if _, err := st.WebSendLimits(ctx, 1000012); err == nil {
		t.Fatal("removed user ID still known")
	}
}

// HostedDomain asks HostZit once and then uses the answer for a while; an
// unreachable HostZit decides nothing (the relay then lets the sender try
// again later).
func TestHostedDomain(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	p := &store.Package{Slug: "p2", Name: "P2", MaxDomains: 1, MaxMailboxes: 1, MaxAliases: 1, StorageMB: 10, MailboxMB: 10, MaxMailboxMB: 10, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "Hosting customer", PackageID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	known := c.ID
	var mu sync.Mutex
	asked := map[string]int{}
	down := false
	hz := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		domain := strings.TrimPrefix(r.URL.Path, "/api/v1/domains/")
		asked[domain]++
		switch {
		case down:
			w.WriteHeader(http.StatusBadGateway)
		case domain == "shop.test": // a customer HostZit has and EmailZit does not
			_, _ = io.WriteString(w, `{"domain":"shop.test","customer_id":"6f1d0e8a-0000-4000-8000-000000000000","status":"active"}`)
		case domain == "known.test":
			_, _ = io.WriteString(w, `{"domain":"known.test","customer":{"id":"`+known+`"}}`)
		case domain == "paused.test":
			_, _ = io.WriteString(w, `{"domain":"paused.test","status":"suspended"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer hz.Close()
	if err := st.SetSetting(ctx, settingHostZit, HostZitLink{URL: hz.URL, Token: st.SealSecret("hostzit.token", "hzt_test"), Insecure: true}); err != nil {
		t.Fatal(err)
	}

	// the same customer in both products (P1): its mail counts against its
	// package here
	if cust, ok, _ := s.HostedDomain(ctx, "known.test"); !ok || cust != known {
		t.Errorf("known.test gave %q, %v; want the customer of EmailZit", cust, ok)
	}
	// a domain of HostZit whose customer is not in EmailZit: hosted, but
	// no customer here (P1)
	cust, ok, temp := s.HostedDomain(ctx, "SHOP.test")
	if !ok || temp || cust != "" {
		t.Errorf("shop.test gave %q, %v, %v", cust, ok, temp)
	}
	if _, ok, _ := s.HostedDomain(ctx, "shop.test"); !ok {
		t.Error("the second answer differs")
	}
	if asked["shop.test"] != 1 {
		t.Errorf("HostZit was asked %d times", asked["shop.test"])
	}
	if _, ok, _ := s.HostedDomain(ctx, "paused.test"); ok {
		t.Error("a suspended domain may send")
	}
	if _, ok, _ := s.HostedDomain(ctx, "nobody.test"); ok {
		t.Error("an unknown domain may send")
	}
	mu.Lock()
	down = true
	mu.Unlock()
	// the known answers are still used
	if _, ok, temp := s.HostedDomain(ctx, "shop.test"); !ok || temp {
		t.Error("the remembered answer was dropped")
	}
	s.ForgetHostedDomains()
	if _, ok, temp := s.HostedDomain(ctx, "shop.test"); ok || !temp {
		t.Error("an unreachable HostZit must decide nothing")
	}
	// without a link nothing is asked at all
	if err := st.SetSetting(ctx, settingHostZit, HostZitLink{}); err != nil {
		t.Fatal(err)
	}
	s.ForgetHostedDomains()
	if _, ok, temp := s.HostedDomain(ctx, "shop.test"); ok || temp {
		t.Error("a domain was taken without a link")
	}
}
