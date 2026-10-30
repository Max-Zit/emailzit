package web

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

func TestExportAndStatus(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	p := &store.Package{Slug: "ex", Name: "EX", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 100, MailboxMB: 10, MaxMailboxMB: 50, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, _ := st.CreateCustomer(ctx, store.NewCustomer{Name: "Export C", PackageID: p.ID})
	d, _ := st.CreateDomain(ctx, store.Staff, c.ID, "ex.test", true)
	m, err := st.CreateMailbox(ctx, store.Staff, store.NewMailbox{DomainID: d.ID, LocalPart: "ana", Password: "a-long-password-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAlias(ctx, store.Staff, d.ID, "info", []string{"ana@ex.test"}, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMailboxSieve(ctx, m.ID, []byte(`{"auto_reply":{"on":true,"body":"away"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMailboxSpam(ctx, store.Staff, m.ID, "strict", []string{"boss.test"}, nil); err != nil {
		t.Fatal(err)
	}

	man, err := s.exportManifest(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(man)
	js := string(b)
	for _, want := range []string{`"format":"emailzit-export/1"`, `"address":"ana@ex.test"`, `"folder":"mail/ex.test/ana"`, `"spam_level":"strict"`, `"address":"info@ex.test"`, `"body":"away"`} {
		if !strings.Contains(js, want) {
			t.Fatalf("manifest misses %s: %s", want, js)
		}
	}
	for _, secret := range []string{"password_hash", "argon2", "totp", "BEGIN"} {
		if strings.Contains(strings.ToLower(js), strings.ToLower(secret)) {
			t.Fatalf("manifest holds %s", secret)
		}
	}

	ro, _, _ := st.CreateAPIToken(ctx, "watch", []string{store.ScopeCustomersRead}, nil, 0, "admin")
	rw, _, _ := st.CreateAPIToken(ctx, "backup", []string{store.ScopeCustomersWrite}, nil, 0, "admin")
	h := s.Handler()
	if code, out := call(t, h, "GET", "/api/v1/server/status", ro, ""); code != 200 || out["product"] != "emailzit" || out["customers"] == nil || out["helper_error"] == nil {
		t.Fatalf("status %d %v", code, out)
	}
	if code, _ := call(t, h, "POST", "/api/v1/customers/"+c.ID+"/export", ro, ""); code != 403 {
		t.Fatalf("export with a read token: %d", code)
	}
	code, out := call(t, h, "POST", "/api/v1/customers/"+c.ID+"/export", rw, "")
	id, _ := out["job_id"].(string)
	if code != 202 || !strings.HasPrefix(id, "job_") {
		t.Fatalf("export %d %v", code, out)
	}
	// no mail helper in the test: the job fails and says so
	var j map[string]any
	for i := 0; i < 50; i++ {
		_, j = call(t, h, "GET", "/api/v1/jobs/"+id, ro, "")
		if j["status"] != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if j["status"] != "failed" || j["customer_id"] != c.ID {
		t.Fatalf("job %v", j)
	}
	if code, out := call(t, h, "GET", "/api/v1/customers/"+c.ID+"/exports", ro, ""); code != 200 || out["items"] == nil {
		t.Fatalf("list %d %v", code, out)
	}
	for _, bad := range []string{"../../secret.key", "x.tar.gz", "20261030-120000.tar.gz"} {
		if code, _ := call(t, h, "GET", "/api/v1/customers/"+c.ID+"/exports/"+bad, rw, ""); code == 200 {
			t.Fatalf("download %q: %d", bad, code)
		}
	}
}
