package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// mailDomain is a customer with one domain, for the tests of publishDNS.
func mailDomain(t *testing.T, s *Server, st *store.Store, name string) *store.Domain {
	t.Helper()
	ctx := context.Background()
	if err := st.SetSetting(ctx, settingMail, MailSettings{Hostname: "mail.example.net", MaxMessageMB: 25}); err != nil {
		t.Fatal(err)
	}
	p := &store.Package{Slug: "p", Name: "P", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 100,
		MailboxMB: 10, MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "C", PackageID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	d, err := st.CreateDomain(ctx, store.Staff, c.ID, name, false)
	if err != nil {
		t.Fatal(err)
	}
	s.installDKIM(ctx, d.ID)
	return d
}

// A HostZit that cannot be reached must not keep the records of the other
// links out of their DNS: every link is asked, as with a zone another
// HostZit does not hold (HostZit's lab retest of 2026-11-15, found in
// released 0.11.1).
func TestOneUnreachableHostZitDoesNotStopTheOthers(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	var mu sync.Mutex
	got := map[string][]hzRecord{}
	hz := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zone := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/dns/zones/"), "/owned/emailzit")
		var in struct {
			Records []hzRecord `json:"records"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		got[zone] = in.Records
		mu.Unlock()
		_, _ = io.WriteString(w, `{"zone":"`+zone+`"}`)
	}))
	defer hz.Close()
	// a HostZit nobody answers for any more (the appliance was stopped or
	// renamed), saved BEFORE the one that holds the zone
	dead := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	for _, u := range []string{deadURL, hz.URL} {
		l := &store.HostZitLink{URL: u, Token: st.SealSecret("hostzit.token", "hzt_test"), Insecure: true, ScopeAll: true}
		if err := st.SaveHostZitLink(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	d := mailDomain(t, s, st, "two.test")
	s.publishDNS(ctx, d.ID, false, nil)

	mu.Lock()
	recs := got["two.test"]
	mu.Unlock()
	if len(recs) < 8 {
		t.Fatalf("the HostZit that holds the zone got %d records", len(recs))
	}
	d, err := st.DomainByID(ctx, store.Staff, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.DNSManaged || d.DNSNote != "" {
		t.Fatalf("the records of the second link did not count: managed=%v note=%q", d.DNSManaged, d.DNSNote)
	}
}

// A HostZit before 0.10.1 does not know the name _emailzit and refuses the
// whole set because of it. The mail records are then written without the
// proof record, so an EmailZit upgraded on its own does not leave the
// domain without MX, SPF, DKIM and DMARC (HostZit's question 1).
func TestAnOldHostZitGetsTheRecordsWithoutTheProof(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	var mu sync.Mutex
	var last []hzRecord
	var puts int
	hz := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Records []hzRecord `json:"records"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		defer mu.Unlock()
		puts++
		for _, rec := range in.Records {
			if strings.HasPrefix(rec.Name, "_emailzit") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":{"code":"bad_request","message":"name _emailzit is not managed by emailzit"}}`)
				return
			}
		}
		last = in.Records
		_, _ = io.WriteString(w, `{"zone":"old.test"}`)
	}))
	defer hz.Close()
	l := &store.HostZitLink{URL: hz.URL, Token: st.SealSecret("hostzit.token", "hzt_test"), Insecure: true, ScopeAll: true}
	if err := st.SaveHostZitLink(ctx, l); err != nil {
		t.Fatal(err)
	}
	d := mailDomain(t, s, st, "old.test")
	s.publishDNS(ctx, d.ID, false, nil)

	mu.Lock()
	recs, tries := last, puts
	mu.Unlock()
	if tries != 2 {
		t.Fatalf("%d writes, want the refused one and the one without the proof", tries)
	}
	var mx bool
	for _, r := range recs {
		if strings.HasPrefix(r.Name, "_emailzit") {
			t.Fatalf("the proof record was sent again: %+v", r)
		}
		if r.Type == "MX" {
			mx = true
		}
	}
	if !mx {
		t.Fatal("the domain got no MX record")
	}
	d, err := st.DomainByID(ctx, store.Staff, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.DNSManaged || d.DNSNote != oldHostZitNote || d.Verified {
		t.Fatalf("domain %+v", d)
	}
}

// The record of a name inside a zone lives in that zone: a website
// shop.x.com has no name servers of its own, so the check asks the name
// servers of x.com for _emailzit.shop.x.com (HostZit's question 3).
func TestTheZoneOfANameInsideAZoneIsFound(t *testing.T) {
	ctx := context.Background()
	zones := map[string]bool{"x.com.": true, "y.co.uk.": true} // asked absolutely
	var asked []string
	lookup := func(_ context.Context, name string) ([]*net.NS, error) {
		asked = append(asked, name)
		if !strings.HasSuffix(name, ".") {
			return nil, fmt.Errorf("the question %q is not absolute, so a search domain can be added to it", name)
		}
		if zones[name] {
			return []*net.NS{{Host: "ns1." + name}}, nil
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	for _, c := range []struct{ name, want string }{
		{"shop.x.com", "x.com"},
		{"x.com", "x.com"},
		{"_emailzit.shop.y.co.uk", "y.co.uk"},
		{"shop.unknown.test", ""}, // nothing is delegated: the system resolver
		{"a.b.c.d.x.com", ""},     // too far up: the walk is short on purpose
	} {
		if got, _ := zoneOf(ctx, lookup, c.name); got != c.want {
			t.Errorf("the zone of %s is %q, want %q", c.name, got, c.want)
		}
	}
	// a one-label name is never asked: a registry must not be taken for
	// the zone of a domain
	for _, name := range asked {
		if !strings.Contains(strings.TrimSuffix(name, "."), ".") {
			t.Errorf("%q was asked for name servers", name)
		}
	}
}

// The panel shows the record of a website domain that has no mail here, so
// an administrator can read it out to a customer whose DNS is not on
// HostZit (HostZit's question 2).
func TestThePanelShowsTheRecordOfAWebsiteDomain(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	l := &store.HostZitLink{URL: "https://hz.example.test:8442", Token: st.SealSecret("hostzit.token", "hzt_x"), ScopeAll: true}
	if err := st.SaveHostZitLink(ctx, l); err != nil {
		t.Fatal(err)
	}
	save := func(p *store.RelayDomain) {
		t.Helper()
		if err := st.SaveRelayDomainProof(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	save(&store.RelayDomain{Domain: "proven.test", LinkID: l.ID, Token: "aaa", ProvenAt: now, CheckedAt: now})
	save(&store.RelayDomain{Domain: "waiting.test", LinkID: l.ID, Token: "bbb", CheckedAt: now})

	states := func() map[string]proofView {
		t.Helper()
		page := s.hostzitPage(ctx)
		if len(page.Links) != 1 {
			t.Fatalf("%d links", len(page.Links))
		}
		out := map[string]proofView{}
		for _, v := range page.Links[0].Proofs {
			if v.Name != "_emailzit."+v.Domain || !strings.HasPrefix(v.Value, relayProofPrefix) {
				t.Errorf("the record of %s is %s TXT %q", v.Domain, v.Name, v.Value)
			}
			out[v.Domain] = v
		}
		return out
	}
	// the record of a proven domain and the one a domain still has to show
	now = now.Add(time.Minute)
	got := states()
	if len(got) != 2 || got["proven.test"].State != "ok" || got["waiting.test"].State != "waiting" {
		t.Fatalf("the panel shows %+v", got)
	}
	if got["proven.test"].Value == got["waiting.test"].Value {
		t.Fatal("every link and domain carries a value of its own")
	}
	// once the record has had its time, the panel says it is missing — that
	// is the mail the relay refuses
	now = now.Add(relayProofGrace)
	got = states()
	if got["waiting.test"].State != "missing" || got["proven.test"].State != "ok" {
		t.Fatalf("after the grace the panel shows %+v", got)
	}
}

// A domain whose DNS EmailZit keeps in HostZit takes its _emailzit record
// back off HostZit once it is verified, by the hourly check and by the
// button (joint test J1 on h1 ↔ e1: the record stayed in HostZit's zone).
// The button asks the name servers of the zone like the check, so an
// answer the system resolver remembered cannot keep it saying "not found".
func TestAVerifiedDomainTakesItsRecordOffHostZit(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	s.DevNo2FA = true // the test signs in with a password only
	var mu sync.Mutex
	last := map[string][]hzRecord{}
	hz := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zone := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/dns/zones/"), "/owned/emailzit")
		var in struct {
			Records []hzRecord `json:"records"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		last[zone] = in.Records
		mu.Unlock()
		_, _ = io.WriteString(w, `{"zone":"`+zone+`"}`)
	}))
	defer hz.Close()
	l := &store.HostZitLink{URL: hz.URL, Token: st.SealSecret("hostzit.token", "hzt_test"), Insecure: true, ScopeAll: true}
	if err := st.SaveHostZitLink(ctx, l); err != nil {
		t.Fatal(err)
	}
	withRecord := func(zone string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range last[zone] {
			if strings.HasPrefix(r.Name, "_emailzit") {
				return true
			}
		}
		return false
	}
	inDNS := map[string]string{}
	s.PublicTXT = func(_ context.Context, _, name string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if v, ok := inDNS[name]; ok {
			return []string{v}, nil
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	publish := func(d *store.Domain) *store.Domain {
		t.Helper()
		s.publishDNS(ctx, d.ID, false, nil)
		d, err := st.DomainByID(ctx, store.Staff, d.ID)
		if err != nil || !d.DNSManaged || !withRecord(d.Name) {
			t.Fatalf("%s before the verification: %+v (%v), record sent %v", d.Name, d, err, withRecord(d.Name))
		}
		mu.Lock()
		inDNS[d.VerifyName()] = d.VerifyValue()
		mu.Unlock()
		return d
	}

	// the hourly check
	d := publish(mailDomain(t, s, st, "job.test"))
	s.verifyInDNS(ctx, d)
	if got, _ := st.DomainByID(ctx, store.Staff, d.ID); !got.Verified || withRecord("job.test") {
		t.Fatalf("after the check: verified %v, _emailzit still in HostZit %v", got.Verified, withRecord("job.test"))
	}

	// the button
	b, err := st.CreateDomain(ctx, store.Staff, d.CustomerID, "button.test", false)
	if err != nil {
		t.Fatal(err)
	}
	s.installDKIM(ctx, b.ID)
	b = publish(b)
	const pw = "correct horse battery staple"
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "anna", Password: pw, Role: store.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if loc := post(t, cl, srv.URL, "/login", url.Values{"username": {"anna"}, "password": {pw}}); loc != "/" {
		t.Fatalf("login went to %q", loc)
	}
	if loc := post(t, cl, srv.URL, "/domains/"+b.ID+"/verify", url.Values{}); loc != "/domains/"+b.ID {
		t.Fatalf("the button went to %q", loc)
	}
	if got, _ := st.DomainByID(ctx, store.Staff, b.ID); !got.Verified || withRecord("button.test") {
		t.Fatalf("after the button: verified %v, _emailzit still in HostZit %v", got.Verified, withRecord("button.test"))
	}
	// the page of a domain whose records EmailZit keeps in HostZit does not
	// also ask to put them at a DNS provider (J1: both sentences were shown)
	resp, err := cl.Get(srv.URL + "/domains/" + b.ID)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "kept in HostZit") || strings.Contains(string(page), "Put these records at the DNS provider") {
		t.Fatal("the page of a domain kept in HostZit's DNS asks to put the records at a DNS provider")
	}
}
