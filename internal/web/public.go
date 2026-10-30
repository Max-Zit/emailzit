package web

import (
	"net"
	"net/http"
)

// PublicHandler serves what the mail domains' own names need on the
// standard web ports 443 and 80: autoconfig (Thunderbird and others),
// Autodiscover (Outlook), the MTA-STS policy; everything else leads to
// webmail on the panel's port. autoconfig.<domain>, autodiscover.<domain>,
// mta-sts.<domain> and the mail host point at this server.
func (s *Server) PublicHandler(panelPort string) http.Handler {
	auto := http.NewServeMux()
	s.autoconfigRoutes(auto)
	top := http.NewServeMux()
	for _, p := range []string{"/.well-known/autoconfig/", "/.well-known/mta-sts.txt", "/mail/config-v1.1.xml", "/autodiscover/", "/Autodiscover/"} {
		top.Handle(p, auto)
	}
	top.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// always the server's own mail host name, never the Host header
		host := s.MailConfig(r.Context()).Hostname
		if host == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Redirect(w, r, "https://"+net.JoinHostPort(host, panelPort)+"/mail", http.StatusFound)
	})
	return s.secure(top)
}
