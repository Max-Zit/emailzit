package mailhelper

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// With HostZit on the same server its nginx owns the ports 80 and 443 and
// includes EmailZit's drop-ins (INTEGRATION P5). EmailZit's drop-in answers
// for the names mail programs ask (autoconfig., autodiscover., mta-sts. of
// every domain) and only on the paths they use, proxied to the panel's
// listener; the panels themselves are never published this way.

const (
	nginxDropInDir  = "/etc/nginx/zit.d/emailzit"
	nginxDropIn     = nginxDropInDir + "/public.conf"
	nginxSharedLock = "/run/zit-nginx.lock"
)

func nginxConf(host, panelPort, cert, key string) []byte {
	locations := `    location = /mail/config-v1.1.xml { proxy_pass https://127.0.0.1:` + panelPort + `; include /etc/nginx/zit.d/emailzit/proxy.inc; }
    location ^~ /.well-known/autoconfig/ { proxy_pass https://127.0.0.1:` + panelPort + `; include /etc/nginx/zit.d/emailzit/proxy.inc; }
    location = /.well-known/mta-sts.txt { proxy_pass https://127.0.0.1:` + panelPort + `; include /etc/nginx/zit.d/emailzit/proxy.inc; }
    location ^~ /autodiscover/ { proxy_pass https://127.0.0.1:` + panelPort + `; include /etc/nginx/zit.d/emailzit/proxy.inc; }
    location ^~ /Autodiscover/ { proxy_pass https://127.0.0.1:` + panelPort + `; include /etc/nginx/zit.d/emailzit/proxy.inc; }
    location / { return 302 https://` + host + `:` + panelPort + `/mail; }
`
	names := `~^(autoconfig|autodiscover|mta-sts)\. ` + host
	return []byte(`# EmailZit: written by the mail helper; changes are overwritten.
# Automatic setup of mail programs and the MTA-STS policy for all mail
# domains (the names point at this server); everything else leads to webmail.
server {
    listen 80;
    listen [::]:80;
    server_name ` + names + `;
` + locations + `}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ` + names + `;
    ssl_certificate ` + cert + `;
    ssl_certificate_key ` + key + `;
` + locations + `}
`)
}

const nginxProxyInc = `# EmailZit: written by the mail helper.
proxy_ssl_verify off;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_connect_timeout 5s;
proxy_read_timeout 30s;
`

// writeNginx keeps EmailZit's nginx drop-in current when HostZit's nginx
// includes the folder; it changes nothing when the folder is missing.
func (s *Server) writeNginx(ctx context.Context, host string) {
	if st, err := os.Lstat(nginxDropInDir); err != nil || !st.IsDir() {
		return
	}
	want := map[string][]byte{
		nginxDropIn: nginxConf(host, "8444", s.CertFile, s.KeyFile),
		filepath.Join(nginxDropInDir, "proxy.inc"): []byte(nginxProxyInc),
	}
	changed := false
	for p, b := range want {
		if old, err := os.ReadFile(p); err != nil || !bytes.Equal(old, b) { // #nosec G304 -- fixed paths
			changed = true
		}
	}
	if !changed {
		return
	}
	// HostZit and EmailZit change nginx one at a time
	lf, err := os.OpenFile(nginxSharedLock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		s.Log.Warn("nginx lock", "err", err)
		return
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		s.Log.Warn("nginx lock", "err", err)
		return
	}
	defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }()
	old := map[string][]byte{}
	for p := range want {
		if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- fixed paths
			old[p] = b
		}
	}
	for p, b := range want {
		if err := writeFile(p, b, 0o644); err != nil {
			s.Log.Warn("nginx drop-in", "err", err)
			return
		}
	}
	restore := func() {
		for p := range want {
			if b, ok := old[p]; ok {
				_ = writeFile(p, b, 0o644)
			} else {
				_ = os.Remove(p)
			}
		}
	}
	if out, err := s.Run(ctx, "nginx", "-t"); err != nil {
		restore()
		s.Log.Warn("nginx refused EmailZit's drop-in; the previous one stays", "err", firstLine(out, err))
		return
	}
	if out, err := s.Run(ctx, "systemctl", "reload", "nginx"); err != nil {
		s.Log.Warn("nginx reload", "err", fmt.Sprint(firstLine(out, err)))
		return
	}
	s.Log.Info("nginx drop-in for autoconfig, Autodiscover and MTA-STS written")
}
