package mailhelper

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// syncPublicCert gives the panel a copy of the mail certificate and key
// (PublicCertDir/public.crt, public.key, owned by the panel user, 0600): the
// panel serves autoconfig, Autodiscover and MTA-STS on port 443 for the
// mail domains, whose names point at the mail host.
func (s *Server) syncPublicCert() error {
	chain, err := os.ReadFile(s.CertFile)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(s.KeyFile)
	if err != nil {
		return err
	}
	st, err := os.Lstat(PublicCertDir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(PublicCertDir, 0o700); err != nil {
			return err
		}
		if err := os.Chown(PublicCertDir, s.AllowUID, -1); err != nil {
			return err
		}
	} else if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", PublicCertDir)
	}
	for name, b := range map[string][]byte{"public.crt": chain, "public.key": key} {
		p := filepath.Join(PublicCertDir, name)
		if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, b) { // #nosec G304 -- fixed file in the panel's directory
			continue
		}
		tmp := p + ".tmp"
		_ = os.Remove(tmp)
		// the directory belongs to the panel user: never follow a link there
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- fixed name
		if err != nil {
			return err
		}
		_, werr := f.Write(b)
		if err := f.Chown(s.AllowUID, -1); werr == nil {
			werr = err
		}
		if err := f.Close(); werr == nil {
			werr = err
		}
		if werr != nil {
			_ = os.Remove(tmp)
			return werr
		}
		if err := os.Rename(tmp, p); err != nil {
			return err
		}
	}
	return nil
}
