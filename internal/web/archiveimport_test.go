package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

func TestArchiveImport(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	s.DataDir = t.TempDir()
	p := &store.Package{Slug: "im", Name: "IM", MaxDomains: 3, MaxMailboxes: 3, MaxAliases: 3, StorageMB: 1000, MailboxMB: 10, MaxMailboxMB: 100, SendPerHour: 1, SendPerDay: 1, CustomerPerHour: 1, RcptPerMsg: 1}
	if err := st.SavePackage(ctx, p); err != nil {
		t.Fatal(err)
	}
	c, _ := st.CreateCustomer(ctx, store.NewCustomer{Name: "Import C", PackageID: p.ID})
	other, _ := st.CreateCustomer(ctx, store.NewCustomer{Name: "Other", PackageID: p.ID})
	if _, err := st.CreateDomain(ctx, store.Staff, other.ID, "taken.test", true); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	for name, body := range map[string]string{
		"cpmove-bob/homedir/etc/shop.test/passwd":          "info:x:1:1::/h:/h\nsales:x:1:1::/h:/h\n",
		"cpmove-bob/homedir/etc/shop.test/quota":           "info:52428800\nsales:999999999999\n",
		"cpmove-bob/homedir/etc/taken.test/passwd":         "x:x:1:1::/h:/h\n",
		"cpmove-bob/homedir/mail/shop.test/info/cur/1:2,S": "Subject: hi\n\nhello",
		"cpmove-bob/va/shop.test":                          "boss@shop.test: info@shop.test\n",
	} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = zw.Close()

	tok, _, _ := st.CreateAPIToken(ctx, "hostzit", []string{store.ScopeCustomersWrite}, nil, 0, "admin")
	h := s.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/customers/"+c.ID+"/import?format=cpanel", bytes.NewReader(b.Bytes()))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), "job_") {
		t.Fatalf("import %d %s", rec.Code, rec.Body)
	}
	var j *job
	for i := 0; i < 100; i++ {
		s.jobs.Lock()
		for _, x := range s.jobs.m {
			if x.Status != "running" {
				c := *x
				j = &c
			}
		}
		s.jobs.Unlock()
		if j != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if j == nil || j.Status != "done" || j.Report == nil || j.Report.Domains != 1 || j.Report.Mailboxes != 2 || j.Report.Aliases != 1 {
		t.Fatalf("job %+v report %+v", j, j.Report)
	}
	notes := strings.Join(j.Report.Notes, "\n")
	if !strings.Contains(notes, "taken.test belongs to another customer") || !strings.Contains(notes, "not installed") {
		t.Fatalf("notes %s", notes)
	}
	m, err := st.MailboxByAddress(ctx, "info@shop.test")
	if err != nil || m.CustomerID != c.ID || m.QuotaMB != 50 {
		t.Fatalf("mailbox %+v %v", m, err)
	}
	if m, _ := st.MailboxByAddress(ctx, "sales@shop.test"); m == nil || m.QuotaMB != 10 {
		t.Fatalf("too large quota should fall back to the package default: %+v", m)
	}
	// an unknown format is refused
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/customers/"+c.ID+"/import?format=nope", bytes.NewReader(b.Bytes()))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("bad format: %d", rec.Code)
	}
}
