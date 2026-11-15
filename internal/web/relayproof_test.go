package web

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// A zone inside HostZit proves nothing: every hosting account may create
// one for someone else's name. The public DNS of the domain has to show
// the record EmailZit asked that HostZit to publish, and until it does the
// sender is asked to try again — afterwards its mail is refused (HostZit's
// security review of the relay, 2026-11-14).
func TestAZoneInHostZitDoesNotVouchForADomain(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	var mu sync.Mutex
	published := map[string]string{} // the zones HostZit really publishes
	hz := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if name, ok := strings.CutPrefix(r.URL.Path, "/api/v1/dns/zones/"); ok {
			name = strings.TrimSuffix(name, "/owned/emailzit")
			var in struct {
				Records []hzRecord `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			// real.test is delegated to this HostZit, fake.test only
			// exists inside it
			if name == "real.test" {
				for _, rec := range in.Records {
					published[rec.Name+"."+name] = rec.Content
				}
			}
			_, _ = io.WriteString(w, `{"zone":"`+name+`"}`)
			return
		}
		domain := strings.TrimPrefix(r.URL.Path, "/api/v1/domains/")
		_, _ = io.WriteString(w, `{"domain":"`+domain+`","customer_id":"hz-7","status":"active"}`)
	}))
	defer hz.Close()
	link := &store.HostZitLink{URL: hz.URL, Token: st.SealSecret("hostzit.token", "hzt_test"), Insecure: true, ScopeAll: true}
	if err := st.SaveHostZitLink(ctx, link); err != nil {
		t.Fatal(err)
	}
	s.PublicTXT = func(_ context.Context, _, name string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if v, ok := published[name]; ok {
			return []string{v}, nil
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}

	// the domain whose zone is really delegated to that HostZit may send
	if _, ok, temp := s.HostedDomain(ctx, link.ID, "real.test"); !ok || temp {
		t.Fatalf("a domain of that HostZit cannot send: ok=%v temp=%v", ok, temp)
	}
	// the record is published under the name EmailZit asks for
	mu.Lock()
	value := published["_emailzit.real.test"]
	mu.Unlock()
	if !strings.HasPrefix(value, relayProofPrefix) {
		t.Fatalf("the proof record says %q", value)
	}
	// a zone that only exists inside HostZit: first "try again later"
	if _, ok, temp := s.HostedDomain(ctx, link.ID, "fake.test"); ok || !temp {
		t.Fatalf("a zone that is not in the public DNS: ok=%v temp=%v", ok, temp)
	}
	// and once the record has had its time, the mail is refused
	now = now.Add(relayProofGrace + time.Minute)
	s.ForgetHostedDomains()
	if _, ok, temp := s.HostedDomain(ctx, link.ID, "fake.test"); ok || temp {
		t.Fatalf("a zone that is not in the public DNS was accepted: ok=%v temp=%v", ok, temp)
	}
	// nothing was written into the zone of a mail domain of this server
	if _, err := st.RelayDomainProof(ctx, "real.test"); err != nil {
		t.Fatalf("the proof of real.test was not kept: %v", err)
	}
	p, err := st.RelayDomainProof(ctx, "fake.test")
	if err != nil || !p.ProvenAt.IsZero() {
		t.Fatalf("fake.test counts as proven: %+v (%v)", p, err)
	}

	// A SECOND HostZit must not pass with the record of the first: the
	// record of real.test is in the zone of the server that really holds
	// it, so the second link gets a value of its own to publish.
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/dns/zones/") {
			_, _ = io.WriteString(w, `{"zone":"real.test"}`) // takes it, publishes nothing
			return
		}
		_, _ = io.WriteString(w, `{"domain":"real.test","customer_id":"hz-9","status":"active"}`)
	}))
	defer other.Close()
	second := &store.HostZitLink{URL: other.URL, Token: st.SealSecret("hostzit.token", "hzt_other"),
		Insecure: true, ScopeAll: true}
	if err := st.SaveHostZitLink(ctx, second); err != nil {
		t.Fatal(err)
	}
	now = now.Add(relayProofRetry + time.Minute)
	s.ForgetHostedDomains()
	if _, ok, temp := s.HostedDomain(ctx, second.ID, "real.test"); ok || temp {
		t.Fatalf("another HostZit passed with the proof of the first: ok=%v temp=%v", ok, temp)
	}
	// and the first link proves its domain again by itself
	now = now.Add(relayProofRetry + time.Minute)
	s.ForgetHostedDomains()
	if _, ok, temp := s.HostedDomain(ctx, link.ID, "real.test"); !ok || temp {
		t.Fatalf("the HostZit that holds the zone cannot prove it again: ok=%v temp=%v", ok, temp)
	}
}

// The relay port is open for the addresses of all links together, so the
// login of a link may only be used from the addresses of that link (E8).
func TestRelayLoginOnlyFromTheAddressesOfTheLink(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	one := &store.HostZitLink{URL: "https://one.example.test:8442", ScopeAll: true, Addresses: []string{"203.0.113.5"}}
	two := &store.HostZitLink{URL: "https://two.example.test:8442", ScopeAll: true, Addresses: []string{"198.51.100.9/32"}}
	byHand := &store.HostZitLink{URL: "https://hand.example.test:8442", ScopeAll: true}
	for _, l := range []*store.HostZitLink{one, two, byHand} {
		if err := st.SaveHostZitLink(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		link *store.HostZitLink
		ip   string
		want bool
	}{
		{one, "203.0.113.5", true},
		{one, "198.51.100.9", false}, // the server of the other link
		{one, "127.0.0.1", true},     // a test on the server itself
		{two, "198.51.100.9", true},
		{two, "203.0.113.5", false},
		{byHand, "198.51.100.9", true}, // a link added by hand knows no addresses
	}
	for _, c := range cases {
		if got := s.RelayLoginAllows(ctx, c.link.ID, c.ip); got != c.want {
			t.Errorf("%s from %s: %v, want %v", c.link.URL, c.ip, got, c.want)
		}
	}
	if s.RelayLoginAllows(ctx, 9999, "203.0.113.5") {
		t.Error("a login without a link may be used")
	}
}
