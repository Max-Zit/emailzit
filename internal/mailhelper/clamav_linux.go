package mailhelper

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/max-zit/emailzit/internal/mailconf"
)

// ClamAV: switched on in the panel, installed by the helper in the
// background (apt, then the virus signatures), then Rspamd sends every
// message to it. Switched off: the scan stops and ClamAV stops too (it
// needs about a gigabyte of memory).

var clamInstalling atomic.Bool

func clamdInstalled() bool {
	_, err := os.Stat("/usr/sbin/clamd")
	return err == nil
}

// clamAV prepares ClamAV for apply and tells whether the scan can be
// switched on now.
func (s *Server) clamAV(ctx context.Context, r Request) bool {
	if !r.ClamAV {
		if _, err := os.Stat(mailconf.RspamdAntivirus); err == nil {
			_ = os.Remove(mailconf.RspamdAntivirus)
			_, _ = s.Run(ctx, "systemctl", "reload-or-restart", "rspamd")
		}
		if clamdInstalled() {
			_, _ = s.Run(ctx, "systemctl", "disable", "--now", "clamav-daemon", "clamav-freshclam")
		}
		return false
	}
	if clamdInstalled() {
		_, _ = s.Run(ctx, "systemctl", "enable", "--now", "clamav-freshclam", "clamav-daemon")
		return true
	}
	if clamInstalling.CompareAndSwap(false, true) {
		go func() {
			defer clamInstalling.Store(false)
			ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
			defer cancel()
			s.Log.Info("installing ClamAV")
			out, err := s.Run(ictx, "sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get -q update && DEBIAN_FRONTEND=noninteractive apt-get -yq install --no-install-recommends clamav-daemon clamav-freshclam")
			if err != nil {
				s.Log.Error("installing ClamAV failed", "err", firstLine(out, err))
				return
			}
			_, _ = s.Run(ictx, "systemctl", "enable", "--now", "clamav-freshclam", "clamav-daemon")
			// clamd starts only once freshclam has its signatures
			for i := 0; i < 90 && !clamSignatures(); i++ {
				select {
				case <-ictx.Done():
					return
				case <-time.After(10 * time.Second):
				}
			}
			_, _ = s.Run(ictx, "systemctl", "start", "clamav-daemon")
			s.mu.Lock()
			defer s.mu.Unlock()
			if err := s.apply(ictx, r); err != nil {
				s.Log.Error("switching the virus scan on", "err", err)
				return
			}
			s.Log.Info("ClamAV installed, virus scan on")
		}()
	}
	return false
}

// clamSignatures tells whether freshclam has downloaded the main
// signatures (clamd does not start without them).
func clamSignatures() bool {
	for _, p := range []string{"/var/lib/clamav/main.cvd", "/var/lib/clamav/main.cld"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// keepClamd starts clamd again while the scan is on (after the signatures
// arrived later, or after a crash).
func (s *Server) keepClamd(ctx context.Context) {
	if _, err := os.Stat(mailconf.RspamdAntivirus); err != nil || !clamdInstalled() || !clamSignatures() {
		return
	}
	if _, err := s.Run(ctx, "systemctl", "is-active", "--quiet", "clamav-daemon"); err != nil {
		_, _ = s.Run(ctx, "systemctl", "start", "clamav-daemon")
	}
}
