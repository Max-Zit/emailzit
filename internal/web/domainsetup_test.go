package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// writeCert puts a certificate with these names where the panel looks for
// the one it serves on 443.
func writeCert(t *testing.T, dir string, names ...string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "tls", "public.crt"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertNamesAndCovers(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir, "mail.example.test", "autoconfig.a.test", "*.wild.test")
	names := certNames(dir)
	for _, c := range []struct {
		name string
		want bool
	}{
		{"mail.example.test", true},
		{"autoconfig.a.test", true},
		{"anything.wild.test", true},   // a wildcard covers one label
		{"deep.down.wild.test", false}, // but not two
		{"mta-sts.a.test", false},
	} {
		if got := covers(names, c.name); got != c.want {
			t.Errorf("covers(%q) = %v, want %v", c.name, got, c.want)
		}
	}
	if certNames(t.TempDir()) != nil {
		t.Error("names found although there is no certificate")
	}
}

// The step follows the state of the domain: verify, first mailbox, host
// names and certificate, records.
func TestDomainSetupSteps(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := &Server{DataDir: dir}
	old := checkResolver
	checkResolver = func(context.Context, string) *net.Resolver { return &net.Resolver{} }
	t.Cleanup(func() { checkResolver = old })

	mail := MailSettings{Hostname: "mail.example.test"}
	d := &domainData{D: &store.Domain{Name: "a.test"}, Mail: mail}
	if got := s.domainSetup(ctx, d, "a.test").Step; got != StepVerify {
		t.Errorf("not verified: step %d, want %d", got, StepVerify)
	}
	d.D.Verified = true
	if got := s.domainSetup(ctx, d, "a.test").Step; got != StepMailbox {
		t.Errorf("no mailbox: step %d, want %d", got, StepMailbox)
	}
	d.Mailboxes = []*store.Mailbox{{Address: "ana@a.test"}}
	// no certificate for the host names yet
	x := s.domainSetup(ctx, d, "a.test")
	if x.Step != StepHosts || len(x.CertMissing) != len(hostNames) {
		t.Errorf("without a certificate: step %d, missing %v", x.Step, x.CertMissing)
	}
	writeCert(t, dir, "mail.example.test", "autoconfig.a.test", "autodiscover.a.test", "mta-sts.a.test")
	d.Records = []DNSRecord{{Name: "a.test", Type: "MX", Value: "10 mail.example.test.", Required: true}}
	d.Checked = map[int]string{0: CheckMissing}
	if got := s.domainSetup(ctx, d, "a.test").Step; got != StepRecords {
		t.Errorf("records missing: step %d, want %d", got, StepRecords)
	}
	d.Checked[0] = CheckOK
	x = s.domainSetup(ctx, d, "a.test")
	if !x.Done() || x.RequiredOK != 1 {
		t.Errorf("everything in place: step %d, %d of %d required", x.Step, x.RequiredOK, x.Required)
	}
}
