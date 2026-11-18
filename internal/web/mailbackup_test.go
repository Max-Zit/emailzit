package web

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/emailzit/internal/backup"
)

// A backup nobody can read back is not a backup. The nightly copy of the
// customers' mail is sealed with the passphrase of the backups, and the
// import on the customer page has to take it exactly as it takes a plain
// export — otherwise a restore needs a shell and a manual.
func TestSealedMailBackupIsImportedLikeAnExport(t *testing.T) {
	ctx := context.Background()
	s, st := testServer(t)
	plain := []byte("this stands for a tar.gz of a customer's mail")

	seal := func(pass string) []byte {
		var buf bytes.Buffer
		w, err := backup.Seal(&buf, pass)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	t.Run("a plain archive goes through untouched", func(t *testing.T) {
		r, err := s.unsealIfNeeded(ctx, bytes.NewReader(plain))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(r)
		if !bytes.Equal(got, plain) {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("a very short upload is left to the usual error", func(t *testing.T) {
		r, err := s.unsealIfNeeded(ctx, strings.NewReader("ab"))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(r)
		if string(got) != "ab" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("a sealed backup without a passphrase says so", func(t *testing.T) {
		if _, err := s.unsealIfNeeded(ctx, bytes.NewReader(seal("the passphrase of the backups"))); err == nil {
			t.Fatal("a sealed file was accepted although no passphrase is set")
		}
	})

	t.Run("a sealed backup is opened with the passphrase of the backups", func(t *testing.T) {
		b := s.backupSettings(ctx)
		b.Passphrase = st.SealSecret(sealBackupKey, "the passphrase of the backups")
		if err := st.SetSetting(ctx, settingBackup, b); err != nil {
			t.Fatal(err)
		}
		if got, perr := s.backupPassphrase(s.backupSettings(ctx)); got != "the passphrase of the backups" {
			t.Fatalf("the passphrase reads back as %q (%v)", got, perr)
		}
		r, err := s.unsealIfNeeded(ctx, bytes.NewReader(seal("the passphrase of the backups")))
		if err != nil {
			t.Fatal(err)
		}
		got, rerr := io.ReadAll(r)
		if rerr != nil {
			t.Fatalf("reading the sealed backup: %v", rerr)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("the archive did not come back: %q", got)
		}
	})

	t.Run("another passphrase does not open it", func(t *testing.T) {
		r, err := s.unsealIfNeeded(ctx, bytes.NewReader(seal("something else entirely")))
		if err != nil {
			return // refused already at the header
		}
		if _, err := io.ReadAll(r); err == nil {
			t.Fatal("a backup opened with the wrong passphrase")
		}
	})

	t.Run("every customer gets its own name on the target", func(t *testing.T) {
		at := time.Date(2026, 11, 18, 2, 30, 0, 0, time.UTC)
		a := mailBackupName("5d26365a-3214-4a9a-8c66-c7b8acba3f13", at)
		b := mailBackupName("11111111-2222-3333-4444-555555555555", at)
		if a == b || !strings.HasPrefix(a, mailBackupPrefix) || !strings.HasSuffix(a, "20261118-023000.ezm") {
			t.Fatalf("names %q and %q", a, b)
		}
	})
}
