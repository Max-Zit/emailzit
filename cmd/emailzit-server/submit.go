package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/store"
	"github.com/max-zit/emailzit/internal/submit"
	"github.com/max-zit/emailzit/internal/web"
)

// submitListener is the socket for mail from websites. systemd holds it
// (emailzit-submit.socket), so it stays the same file across restarts of
// the server and the bind mounts in HostZit's cages keep reaching it; nil
// when the server was not started with it.
func submitListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, nil
	}
	n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	for _, v := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(v)
	}
	var found net.Listener
	for i := 0; i < n && i < 16; i++ {
		f := os.NewFile(uintptr(3+i), "listen")
		l, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		if found == nil && (l.Addr().String() == submit.Socket || (i < len(names) && names[i] == "submit")) {
			found = l
			continue
		}
		_ = l.Close()
	}
	return found, nil
}

// startSubmit takes mail from websites when systemd passes the socket.
func startSubmit(ctx context.Context, st *store.Store, srv *web.Server, log *slog.Logger) {
	sl, err := submitListener()
	if err != nil {
		log.Error("mail from websites not started", "err", err)
		return
	}
	if sl == nil {
		return
	}
	ss := &submit.Server{Store: st, Log: log, PeerUID: mailhelper.PeerUID,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", submit.PostfixService)
		},
		Hostname: func(ctx context.Context) string { return srv.MailConfig(ctx).Hostname },
		MaxBytes: func(ctx context.Context) int64 { return int64(srv.MailConfig(ctx).MaxMessageMB) << 20 },
		Blocked: func(uid int, reason string) {
			_ = st.Audit(context.Background(), "-", "local", "web.send.blocked", fmt.Sprintf("webuid:%d", uid), "mail from the hosting account blocked automatically: "+reason)
		},
	}
	go func() {
		if err := ss.Serve(ctx, sl); err != nil {
			log.Error("mail from websites stopped", "err", err)
		}
	}()
	log.Info("taking mail from websites", "socket", sl.Addr().String())
}
