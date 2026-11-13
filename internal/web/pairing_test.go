package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A pairing code works once and only for ten minutes, and EmailZit keeps
// only its hash.
func TestPairingCodeIsOneUseAndExpires(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	now := time.Now()
	s.now = func() time.Time { return now }

	code, until, err := s.NewPairingCode(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, pairingPrefix) {
		t.Fatalf("code %q does not start with %q", code, pairingPrefix)
	}
	if until.Sub(now) != PairingLife {
		t.Errorf("the code lives %v, want %v", until.Sub(now), PairingLife)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairingPrefix))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		V      int    `json:"v"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.V != 1 || body.Secret == "" || !strings.HasPrefix(body.URL, "https://") {
		t.Fatalf("the code holds %+v", body)
	}
	var kept pairing
	if err := st.GetSetting(ctx, settingPairing, &kept); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(kept.Hash, body.Secret) || kept.Hash == body.Secret {
		t.Error("the secret itself is stored, not its hash")
	}

	if err := s.usePairingCode(ctx, "wrong"); err == nil {
		t.Error("a wrong code was accepted")
	}
	// a wrong attempt also uses the code up
	if err := s.usePairingCode(ctx, body.Secret); err == nil {
		t.Error("the code still worked after an attempt")
	}

	code, _, err = s.NewPairingCode(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairingPrefix))
	_ = json.Unmarshal(raw, &body)
	if err := s.usePairingCode(ctx, body.Secret); err != nil {
		t.Fatalf("a fresh code was refused: %v", err)
	}

	code, _, _ = s.NewPairingCode(ctx, "admin")
	raw, _ = base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairingPrefix))
	_ = json.Unmarshal(raw, &body)
	now = now.Add(PairingLife + time.Second)
	if err := s.usePairingCode(ctx, body.Secret); err == nil {
		t.Error("an expired code was accepted")
	}
}

// At most five attempts a minute, per address and for the open code.
func TestPairingLimiter(t *testing.T) {
	var l pairingLimiter
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !l.allow(now, "ip:203.0.113.5", "code") {
			t.Fatalf("attempt %d was already refused", i+1)
		}
	}
	if l.allow(now, "ip:203.0.113.5", "code") {
		t.Error("the sixth attempt within a minute was allowed")
	}
	if l.allow(now, "ip:198.51.100.7", "code") {
		t.Error("another address got through although the code is at its limit")
	}
	if !l.allow(now.Add(61*time.Second), "ip:203.0.113.5", "code") {
		t.Error("after a minute the attempts are not forgotten")
	}
}

// Only addresses and networks of the other server are taken.
func TestValidAddresses(t *testing.T) {
	if _, err := validAddresses(nil); err == nil {
		t.Error("an empty list was accepted")
	}
	got, err := validAddresses([]string{" 144.91.79.144 ", "2a02:c207:2374:9029::1", "", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("kept %v", got)
	}
	if _, err := validAddresses([]string{"h1.maxzit.com"}); err == nil {
		t.Error("a name was accepted as an address")
	}
}
