package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/store"
)

// pairWith pairs this EmailZit with a HostZit and returns its answer.
func pairWith(t *testing.T, s *Server, url, name, addr string) (token string, relayUser, relayPass string) {
	t.Helper()
	ctx := context.Background()
	code, _, err := s.NewPairingCode(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairingPrefix))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	payload := `{"hostzit_url":"` + url + `","server_name":"` + name + `","addresses":["` + addr + `"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/link/hostzit", strings.NewReader(payload))
	r.Header.Set("Authorization", "Pairing "+body.Secret)
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = addr + ":50000"
	local := &net.TCPAddr{IP: net.ParseIP("213.136.66.211"), Port: 8444}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(local)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("pairing with %s answered %d: %s", url, w.Code, w.Body.String())
	}
	var out struct {
		Token string `json:"api_token"`
		Relay struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"relay"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Token, out.Relay.Username, out.Relay.Password
}

// linkServer is an EmailZit that takes mail and answers every address, so
// two HostZit servers can pair with it.
func linkServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	s, st := testServer(t)
	s.Mail = &stubMail{}
	if err := st.SetSetting(context.Background(), settingMail, MailSettings{Hostname: "mail.example.net", MaxMessageMB: 25}); err != nil {
		t.Fatal(err)
	}
	all, err := netacl.Parse([]string{"0.0.0.0/0", "::/0"})
	if err != nil {
		t.Fatal(err)
	}
	s.MgmtACL.Set(all)
	return s, st
}

// Two HostZit servers on one EmailZit (INTEGRATION.md E7–E9): the second
// pairing adds a link instead of replacing the first, both keep their own
// token and relay login, pairing again with the same address replaces only
// that link, and an unlink ends only the link of the token it carries.
func TestTwoHostZitLinks(t *testing.T) {
	ctx := context.Background()
	s, st := linkServer(t)

	tokenA, userA, passA := pairWith(t, s, "https://h1.example.net:8442", "h1", "144.91.79.144")
	tokenB, userB, passB := pairWith(t, s, "https://h2.example.net:8442", "h2", "203.0.113.7")
	if userA == userB {
		t.Fatalf("both links got the relay login %q", userA)
	}
	links, err := st.HostZitLinks(ctx)
	if err != nil || len(links) != 2 {
		t.Fatalf("the links are %+v (%v)", links, err)
	}
	// the first link is untouched by the second pairing
	if _, _, err := st.CheckRelayLogin(ctx, userA, passA); err != nil {
		t.Errorf("the relay login of the first link stopped working: %v", err)
	}
	if _, err := st.APITokenBySecret(ctx, tokenA, "144.91.79.144"); err != nil {
		t.Errorf("the token of the first link stopped working: %v", err)
	}
	if _, _, err := st.CheckRelayLogin(ctx, userB, passB); err != nil {
		t.Errorf("the relay login of the second link does not work: %v", err)
	}

	// pairing again with the FIRST address replaces only that link
	tokenA2, userA2, passA2 := pairWith(t, s, "https://h1.example.net:8442", "h1", "144.91.79.144")
	if links, err := st.HostZitLinks(ctx); err != nil || len(links) != 2 {
		t.Fatalf("after pairing again the links are %+v (%v)", links, err)
	}
	if _, err := st.APITokenBySecret(ctx, tokenA, "144.91.79.144"); err == nil {
		t.Error("the old token of that link still works")
	}
	if _, _, err := st.CheckRelayLogin(ctx, userA, passA); err == nil {
		t.Error("the old relay login of that link still works")
	}
	if _, _, err := st.CheckRelayLogin(ctx, userA2, passA2); err != nil {
		t.Errorf("the new relay login does not work: %v", err)
	}
	if _, _, err := st.CheckRelayLogin(ctx, userB, passB); err != nil {
		t.Errorf("the second link lost its relay login: %v", err)
	}

	// HostZit A ends its link: only that one goes
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/link/hostzit", nil)
	r.Header.Set("Authorization", "Bearer "+tokenA2)
	r.RemoteAddr = "144.91.79.144:50001"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("the unlink answered %d: %s", w.Code, w.Body.String())
	}
	left, err := st.HostZitLinks(ctx)
	if err != nil || len(left) != 1 || left[0].ServerName != "h2" {
		t.Fatalf("after the unlink the links are %+v (%v)", left, err)
	}
	if _, _, err := st.CheckRelayLogin(ctx, userA2, passA2); err == nil {
		t.Error("the relay login of the ended link still works")
	}
	if _, _, err := st.CheckRelayLogin(ctx, userB, passB); err != nil {
		t.Errorf("the other link lost its relay login: %v", err)
	}
	if _, err := st.APITokenBySecret(ctx, tokenB, "203.0.113.7"); err != nil {
		t.Errorf("the other link lost its token: %v", err)
	}
}

// A link that serves only the customers assigned to it (E13) sees nothing
// of the others: a HostZit of one client, linked to a shared EmailZit,
// must not read or open the other customers.
func TestLinkScopeAssignedCustomers(t *testing.T) {
	ctx := context.Background()
	s, st := linkServer(t)
	p := &store.Package{Slug: "sc", Name: "SC", MaxDomains: 2, MaxMailboxes: 2, MaxAliases: 2, StorageMB: 0, MailboxMB: 10,
		MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	mine, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "Client of h1", PackageID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	other, err := st.CreateCustomer(ctx, store.NewCustomer{Name: "Someone else", PackageID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	// the token is bound to the addresses of that HostZit, and the API
	// calls of this test come from the loopback
	token, _, _ := pairWith(t, s, "https://h1.example.net:8442", "h1", "127.0.0.1")
	links, err := st.HostZitLinks(ctx)
	if err != nil || len(links) != 1 {
		t.Fatalf("the links are %+v (%v)", links, err)
	}
	link := links[0]
	// as long as the link serves everybody it sees both customers
	if code, _ := call(t, s.Handler(), "GET", "/api/v1/customers/"+other.ID, token, ""); code != 200 {
		t.Fatalf("a link that serves all customers got %d for another customer", code)
	}
	if err := st.SetLinkScope(ctx, link.ID, false, []string{mine.ID}); err != nil {
		t.Fatal(err)
	}
	// now only its own customer exists for it
	if code, _ := call(t, s.Handler(), "GET", "/api/v1/customers/"+mine.ID, token, ""); code != 200 {
		t.Errorf("the link cannot read its own customer (%d)", code)
	}
	code, body := call(t, s.Handler(), "GET", "/api/v1/customers/"+other.ID, token, "")
	if code != 404 {
		t.Errorf("another customer answered %d, want 404", code)
	}
	if e, _ := body["error"].(map[string]any); e == nil || e["code"] != "customer_not_found" {
		t.Errorf("the error is %v", body["error"])
	}
	// the one-time sign-in link of another customer is refused as well
	if code, _ := call(t, s.Handler(), "POST", "/api/v1/customers/"+other.ID+"/sso", token, ""); code != 404 {
		t.Errorf("the one-time link of another customer answered %d", code)
	}
	// and the list holds only its own
	code, list := call(t, s.Handler(), "GET", "/api/v1/customers", token, "")
	items, _ := list["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("the list answered %d with %d customers", code, len(items))
	}
	if first, _ := items[0].(map[string]any); first["id"] != mine.ID {
		t.Errorf("the list holds %v", items[0])
	}
	// a customer this HostZit creates belongs to it
	code, made := call(t, s.Handler(), "POST", "/api/v1/customers", token, `{"name":"New one","package":"sc"}`)
	if code != 201 {
		t.Fatalf("the create answered %d: %v", code, made)
	}
	newID, _ := made["id"].(string)
	if !st.LinkServes(ctx, link, newID) {
		t.Error("the customer it created is not one of its own")
	}
	// the relay of that link only carries the mail of its customers
	if !s.RelayCustomer(ctx, link.ID, mine.ID) || s.RelayCustomer(ctx, link.ID, other.ID) {
		t.Error("the relay check does not follow the scope of the link")
	}
	// the billing system's own token still sees everything
	full, _, err := st.CreateAPIToken(ctx, "portal", store.Scopes, nil, 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, s.Handler(), "GET", "/api/v1/customers/"+other.ID, full, ""); code != 200 {
		t.Errorf("the billing system got %d for a customer of the server", code)
	}
}

// A token the pairing made does nothing once its link is gone, even if
// it was not revoked (the HostZit review asked for this). Tokens made by
// hand are not touched.
func TestPairedTokenWithoutItsLinkIsDead(t *testing.T) {
	ctx := context.Background()
	s, st := linkServer(t)
	token, _, _ := pairWith(t, s, "https://h1.example.net:8442", "h1", "127.0.0.1")
	if code, _ := call(t, s.Handler(), "GET", "/api/v1/customers", token, ""); code != 200 {
		t.Fatalf("the token of the link answered %d", code)
	}
	links, err := st.HostZitLinks(ctx)
	if err != nil || len(links) != 1 {
		t.Fatalf("the links are %+v (%v)", links, err)
	}
	// the link goes without revoking the token (a restore of an older
	// backup, a row removed by hand …)
	if err := st.DeleteHostZitLink(ctx, links[0].ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, s.Handler(), "GET", "/api/v1/customers", token, ""); code != 401 {
		t.Errorf("the token of a link that is gone answered %d, want 401", code)
	}
	// a token made by hand still works
	own, _, err := st.CreateAPIToken(ctx, "portal", store.Scopes, nil, 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, s.Handler(), "GET", "/api/v1/customers", own, ""); code != 200 {
		t.Errorf("a token made by hand answered %d", code)
	}
}
