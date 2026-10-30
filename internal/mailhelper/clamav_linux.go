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
