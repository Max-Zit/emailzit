package mailhelper

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Sanesecurity's free signatures for ClamAV (spam, phishing, scams,
// malware links and macros), switched on in the panel together with the
// virus scan. Every file is checked against Sanesecurity's signing key
// (embedded here) with gpgv before clamd sees it; a file that does not
// verify is never installed. Downloaded every six hours (their mirrors ask
// for restraint).

//go:embed sanesecurity.asc
var sanesecurityKey string

// SaneFiles are Sanesecurity's own databases with a low false positive
// rate, plus their macro and "shelter" rules (medium, but they catch the
// malware documents that matter).
var SaneFiles = []string{
	"sanesecurity.ftm", "sigwhitelist.ign2", "junk.ndb", "jurlbl.ndb", "phish.ndb", "rogue.hdb", "scam.ndb", "spamimg.hdb",
	"spamattach.hdb", "blurl.ndb", "foxhole_generic.cdb", "foxhole_filename.cdb", "malwarehash.hsb", "hackingteam.hsb",
	"badmacro.ndb", "shelter.ldb",
}

var saneMirrors = []string{"https://mirror.rollernet.us/sanesecurity/", "https://ftp.swin.edu.au/sanesecurity/"}

const (
	saneDir      = "/var/lib/emailzit/sanesecurity"
	clamDBDir    = "/var/lib/clamav"
	saneInterval = 6 * time.Hour
	saneMaxSize  = 64 << 20
)

var saneMu sync.Mutex

// extraSignatures records the wish of the last apply; the usage loop
// downloads.
func (s *Server) extraSignatures(ctx context.Context, on bool) {
	s.saneOn.Store(on)
	if !on {
		s.removeSignatures(ctx)
		return
	}
	go s.updateSignatures(context.WithoutCancel(ctx))
}

// updateSignatures downloads the signatures when they are due.
func (s *Server) updateSignatures(ctx context.Context) {
	if !s.saneOn.Load() || !clamdInstalled() {
		return
	}
	if !saneMu.TryLock() {
		return
	}
	defer saneMu.Unlock()
	stamp := filepath.Join(saneDir, "stamp")
	if fi, err := os.Stat(stamp); err == nil && time.Since(fi.ModTime()) < saneInterval {
		return
	}
	if err := os.MkdirAll(saneDir, 0o750); err != nil {
		s.Log.Warn("signatures", "err", err)
		return
	}
	keyring := filepath.Join(saneDir, "sanesecurity.gpg")
	key, err := dearmor(sanesecurityKey)
	if err != nil {
		s.Log.Error("signatures: the embedded key is broken", "err", err)
		return
	}
	if err := writeFile(keyring, key, 0o644); err != nil {
		s.Log.Warn("signatures", "err", err)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var installed []string
	var failed int
	for _, name := range SaneFiles {
		changed, err := s.fetchSignature(cctx, keyring, name)
		if err != nil {
			failed++
			s.Log.Warn("signatures: "+name, "err", err)
			continue
		}
		if changed {
			installed = append(installed, name)
		}
	}
	if failed < len(SaneFiles) {
		_ = writeFile(stamp, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
	}
	if len(installed) == 0 {
		return
	}
	s.Log.Info("Sanesecurity signatures updated", "files", len(installed))
	if _, err := s.Run(cctx, "systemctl", "reload", "clamav-daemon"); err != nil {
		_, _ = s.Run(cctx, "systemctl", "restart", "clamav-daemon")
	}
}

// fetchSignature downloads one file and its signature, checks it and puts
// it into ClamAV's directory when it changed.
func (s *Server) fetchSignature(ctx context.Context, keyring, name string) (bool, error) {
	var lastErr error
	for _, m := range saneMirrors {
		data, err := download(ctx, m+name)
		if err != nil {
			lastErr = err
			continue
		}
		sig, err := download(ctx, m+name+".sig")
		if err != nil {
			lastErr = err
			continue
		}
		tmp := filepath.Join(saneDir, name+".new")
		tmpSig := tmp + ".sig"
		if err := writeFile(tmp, data, 0o644); err != nil {
			return false, err
		}
		if err := writeFile(tmpSig, sig, 0o644); err != nil {
			_ = os.Remove(tmp)
			return false, err
		}
		out, err := s.Run(ctx, "gpgv", "--keyring", keyring, tmpSig, tmp)
		_ = os.Remove(tmpSig)
		if err != nil {
			_ = os.Remove(tmp)
			lastErr = fmt.Errorf("signature check failed (%s): %s", m, firstLine(out, err))
			continue
		}
		dst := filepath.Join(clamDBDir, name)
		// #nosec G304 -- fixed directory, name from SaneFiles
		if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, data) {
			_ = os.Remove(tmp)
			return false, nil
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return false, err
		}
		_ = os.Chown(dst, userID("clamav"), groupID("clamav"))
		return true, nil
	}
	return false, lastErr
}

// removeSignatures takes the files out of ClamAV's directory again.
func (s *Server) removeSignatures(ctx context.Context) {
	saneMu.Lock()
	defer saneMu.Unlock()
	removed := false
	for _, name := range SaneFiles {
		if err := os.Remove(filepath.Join(clamDBDir, name)); err == nil {
			removed = true
		}
	}
	_ = os.Remove(filepath.Join(saneDir, "stamp"))
	if removed {
		_, _ = s.Run(ctx, "systemctl", "reload", "clamav-daemon")
	}
}

var saneClient = &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
	if r.URL.Scheme != "https" || len(via) > 3 {
		return errors.New("redirect refused")
	}
	return nil
}}

func download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "EmailZit")
	resp, err := saneClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, saneMaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > saneMaxSize {
		return nil, errors.New("file too large")
	}
	return b, nil
}

// dearmor turns an ASCII-armored OpenPGP key into the binary form gpgv
// reads (base64 between the header block and the checksum line).
func dearmor(a string) ([]byte, error) {
	a = strings.ReplaceAll(a, "\r", "")
	start := strings.Index(a, "\n\n")
	end := strings.Index(a, "\n=")
	if !strings.HasPrefix(a, "-----BEGIN PGP PUBLIC KEY BLOCK-----") || start < 0 || end < start {
		return nil, errors.New("not an armored key")
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(a[start+2:end], "\n", ""))
}
