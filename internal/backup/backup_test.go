package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type fakeDB string

func (f fakeDB) Dump(_ context.Context, w io.Writer) error {
	_, err := io.WriteString(w, string(f))
	return err
}

func TestCreateRestore(t *testing.T) {
	for _, pass := range []string{"", "correct horse battery"} {
		src := t.TempDir()
		_ = os.WriteFile(filepath.Join(src, "secret.key"), []byte("KEY"), 0o600)
		_ = os.MkdirAll(filepath.Join(src, "tls"), 0o700)
		_ = os.WriteFile(filepath.Join(src, "tls", "console.key"), []byte("AGENT"), 0o600)
		_ = os.MkdirAll(filepath.Join(src, "logs"), 0o700)
		_ = os.WriteFile(filepath.Join(src, "logs", "server.log"), []byte("not in a backup"), 0o600)
		big := strings.Repeat("database rows ", 20000) // several encryption chunks
		var buf bytes.Buffer
		m, err := Create(context.Background(), fakeDB(big), src, t.TempDir(), "0.11.0", pass, &buf)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Files) != 2 {
			t.Fatalf("files %v", m.Files)
		}
		if pass != "" {
			if bytes.Contains(buf.Bytes(), []byte("AGENT")) || !bytes.HasPrefix(buf.Bytes(), []byte(encMagic)) {
				t.Fatal("not encrypted")
			}
			if _, err := Inspect(bytes.NewReader(buf.Bytes()), "wrong"); !errors.Is(err, ErrPassphrase) {
				t.Fatalf("wrong passphrase: %v", err)
			}
			var gotDB string
			_, err := Restore(context.Background(), bytes.NewReader(buf.Bytes()[:buf.Len()-100]), pass, t.TempDir(), func(_ context.Context, r io.Reader) error {
				b, err := io.ReadAll(r)
				gotDB = string(b)
				return err
			})
			if err == nil {
				t.Fatalf("a cut file restored (%d bytes of database)", len(gotDB))
			}
		}
		dst := t.TempDir()
		var gotDB string
		m2, err := Restore(context.Background(), bytes.NewReader(buf.Bytes()), pass, dst, func(_ context.Context, r io.Reader) error {
			b, err := io.ReadAll(r)
			gotDB = string(b)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if gotDB != big || m2.ServerVersion != "0.11.0" {
			t.Fatal("database or manifest differ")
		}
		if b, _ := os.ReadFile(filepath.Join(dst, "tls", "console.key")); string(b) != "AGENT" {
			t.Fatal("tls file not restored")
		}
		if _, err := os.Stat(filepath.Join(dst, "logs")); err == nil {
			t.Fatal("logs restored")
		}
	}
}

func TestSafeRel(t *testing.T) {
	for p, ok := range map[string]bool{"secret.key": true, "tls/console.key": true, "library/a/b.msi": false,
		"../etc/passwd": false, "tls/../../x": false, "/etc/passwd": false, "logs/x": false, "tls\\x": false, "": false} {
		if safeRel(p) != ok {
			t.Errorf("safeRel(%q) = %v", p, !ok)
		}
	}
}

// A file in the data directory that the server may not read (an old
// certificate an administrator put aside) must not cost it the backup: it
// is left out and named in the manifest. A file EmailZit needs is an error.
func TestCreateSkipsUnreadableExtras(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	tls := filepath.Join(dir, "tls")
	if err := os.Mkdir(tls, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"panel.crt", "panel.key"} {
		if err := os.WriteFile(filepath.Join(tls, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stray := filepath.Join(tls, "panel.key.selfsigned")
	if err := os.WriteFile(stray, []byte("old"), 0o000); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(stray); err == nil { // some systems ignore the mode
		_ = f.Close()
		t.Skip("this file system does not refuse the read")
	}
	var buf bytes.Buffer
	m, err := Create(context.Background(), fakeDB("db"), dir, t.TempDir(), "test", "", &buf)
	if err != nil {
		t.Fatalf("the backup failed because of a stray file: %v", err)
	}
	if !slices.Contains(m.Skipped, "tls/panel.key.selfsigned") {
		t.Errorf("the skipped file is not in the manifest: %v", m.Skipped)
	}
	if slices.Contains(m.Files, "tls/panel.key.selfsigned") {
		t.Error("the unreadable file is listed as part of the backup")
	}
	for _, want := range []string{"secret.key", "tls/panel.crt", "tls/panel.key"} {
		if !slices.Contains(m.Files, want) {
			t.Errorf("%s is missing from the backup", want)
		}
	}
}

// Which files a backup may do without: EmailZit's own are required, the
// rest of the TLS folder is extra.
func TestRequiredFiles(t *testing.T) {
	for _, c := range []struct {
		name     string
		required bool
	}{
		{"secret.key", true},
		{"tls/panel.crt", true},
		{"tls/panel.key", true},
		{"tls/panel.key.selfsigned", false},
		{"tls/public.crt", false},
		{"tls/old-2024.pem", false},
	} {
		if requiredFiles[c.name] != c.required {
			t.Errorf("%s: required = %v, want %v", c.name, requiredFiles[c.name], c.required)
		}
	}
}
