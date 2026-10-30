package authpolicy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func call(t *testing.T, g *Guard, cmd, body, token string) reply {
	t.Helper()
	r := httptest.NewRequest("POST", "/?command="+cmd, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		return reply{Status: -999}
	}
	var rep reply
	_ = json.NewDecoder(w.Body).Decode(&rep)
	return rep
}

func TestGuard(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	var banned []netip.Addr
	g := &Guard{Token: "tok", Now: func() time.Time { return now }, Ban: func(ip netip.Addr, d time.Duration) { banned = append(banned, ip) }}
	if call(t, g, "allow", `{"login":"a@x.test","remote":"203.0.113.5"}`, "wrong").Status != -999 {
		t.Fatal("wrong token accepted")
	}
	fail := `{"login":"a@x.test","remote":"203.0.113.5","success":false,"fail_type":"credentials"}`
	for i := 0; i < IPFailures-1; i++ {
		call(t, g, "report", fail, "tok")
	}
	if call(t, g, "allow", `{"login":"b@x.test","remote":"203.0.113.5"}`, "tok").Status != 0 {
		t.Fatal("blocked too early")
	}
	call(t, g, "report", fail, "tok")
	if call(t, g, "allow", `{"login":"b@x.test","remote":"203.0.113.5"}`, "tok").Status >= 0 || len(banned) != 1 {
		t.Fatal("address not blocked")
	}
	if call(t, g, "allow", `{"login":"b@x.test","remote":"203.0.113.6"}`, "tok").Status != 0 {
		t.Fatal("other address blocked")
	}
	now = now.Add(IPBan + time.Minute)
	if call(t, g, "allow", `{"login":"b@x.test","remote":"203.0.113.5"}`, "tok").Status != 0 {
		t.Fatal("block did not end")
	}
	// an account attacked from many addresses is slowed down, not locked
	for i := 0; i < AccountFailures; i++ {
		call(t, g, "report", `{"login":"c@x.test","remote":"198.51.100.`+string(rune('1'+i%9))+`","success":false,"fail_type":"credentials"}`, "tok")
	}
	if s := call(t, g, "allow", `{"login":"c@x.test","remote":"192.0.2.1"}`, "tok").Status; s != AccountDelay {
		t.Fatalf("account status %d", s)
	}
	// loopback (webmail) is never blocked
	for i := 0; i < 20; i++ {
		call(t, g, "report", `{"login":"d@x.test","remote":"127.0.0.1","success":false,"fail_type":"credentials"}`, "tok")
	}
	if call(t, g, "allow", `{"login":"e@x.test","remote":"127.0.0.1"}`, "tok").Status != 0 {
		t.Fatal("loopback blocked")
	}
}
