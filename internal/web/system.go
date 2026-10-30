package web

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/helper"
	"github.com/max-zit/emailzit/internal/update"
)

// The parts of the server's own system the console manages through the
// root helper (Linux packages): the time zone, the appliance's network, a
// restart for new ports, and new EmailZit versions.

// helperOK reports whether this installation has the root helper.
func (s *Server) helperOK() bool {
	if s.HelperAvailable != nil {
		return s.HelperAvailable()
	}
	return helper.Available()
}

// submit hands a request to the root helper.
func (s *Server) submit(r *http.Request, req helper.Request) error {
	if !s.helperOK() || s.DataDir == "" {
		return uiErr("This installation has no EmailZit helper (it comes with the Linux packages). Change it on the server itself.")
	}
	if helper.Pending(s.DataDir) {
		return uiErr("The server is still busy with the previous request. Try again in a minute.")
	}
	req.RequestedBy = userFrom(r).Username
	return helper.Submit(s.DataDir, req)
}

// lastHelperResult is the result of the last request, if any.
func (s *Server) lastHelperResult() *helper.Result {
	if s.DataDir == "" {
		return nil
	}
	res, err := helper.ReadResult(s.DataDir)
	if err != nil {
		return nil
	}
	return res
}

// ---- time zone

// timeZones lists the zone names of the system (zone1970.tab), else a few.
func timeZones() []string {
	f, err := os.Open("/usr/share/zoneinfo/zone1970.tab")
	if err != nil {
		return []string{"UTC", "Europe/Belgrade", "Europe/Berlin", "Europe/London", "America/New_York"}
	}
	defer f.Close()
	set := map[string]bool{"UTC": true}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "#") {
			continue
		}
		if p := strings.Split(l, "\t"); len(p) >= 3 && helper.ValidTimeZone(p[2]) == nil {
			set[p[2]] = true
		}
	}
	out := make([]string, 0, len(set))
	for z := range set {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleTimeZone(w http.ResponseWriter, r *http.Request) {
	z := strings.TrimSpace(r.FormValue("timezone"))
	if err := helper.ValidTimeZone(z); err != nil {
		s.redirectErr(w, r, "/settings/version", "Choose a time zone from the list.")
		return
	}
	if err := s.submit(r, helper.Request{Action: helper.ActionTimeZone, TimeZone: z}); err != nil {
		s.redirectErr(w, r, "/settings/version", err.Error())
		return
	}
	s.audit(r, "settings.timezone", "settings", "time zone of the server set to %s", z)
	s.redirect(w, r, "/settings/version", "The time zone is being set; the console restarts and is back in a few seconds.")
}

// ---- restart (new ports)

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if err := s.submit(r, helper.Request{Action: helper.ActionRestart}); err != nil {
		s.redirectErr(w, r, "/settings/version", err.Error())
		return
	}
	s.audit(r, "server.restart", "settings", "panel service restarted from the panel (listen address %s)", s.RunningMgmt)
	s.redirect(w, r, "/settings/version", "The panel restarts and is back in a few seconds; if you changed its port, open it on the new port.")
}

// ---- network of the appliance

// serverNetwork is the current network of the server (for the page).
type serverNetwork struct {
	Appliance bool
	Interface string
	Addresses []string
	Hostname  string
	Config    helper.NetworkConfig
	Saved     bool // EmailZit's network file exists
}

func readServerNetwork() serverNetwork {
	n := serverNetwork{Appliance: helper.IsAppliance("")}
	n.Hostname, _ = os.Hostname()
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				if n.Interface == "" {
					n.Interface = i.Name
				}
				n.Addresses = append(n.Addresses, ipn.String())
			}
		}
	}
	n.Config.DHCP = true
	if b, err := os.ReadFile(helper.NetworkFile); err == nil {
		n.Saved = true
		for _, l := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
			switch k {
			case "Address":
				n.Config.DHCP, n.Config.Address = false, v
			case "Gateway":
				n.Config.Gateway = v
			case "DNS":
				n.Config.DNS = append(n.Config.DNS, v)
			}
		}
	}
	n.Config.Hostname = n.Hostname
	return n
}

func (s *Server) handleServerNetwork(w http.ResponseWriter, r *http.Request) {
	if !helper.IsAppliance("") {
		s.redirectErr(w, r, "/settings/version", "The network of this server is managed by its operating system; it can be changed here only on the EmailZit appliance.")
		return
	}
	c := helper.NetworkConfig{DHCP: r.FormValue("ipmode") == "dhcp", Hostname: strings.TrimSpace(r.FormValue("hostname"))}
	if !c.DHCP {
		c.Address = strings.TrimSpace(r.FormValue("address"))
		c.Gateway = strings.TrimSpace(r.FormValue("gateway"))
		for _, d := range strings.FieldsFunc(r.FormValue("dns"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
			c.DNS = append(c.DNS, strings.TrimSpace(d))
		}
	}
	if err := c.Validate(); err != nil {
		s.redirectErr(w, r, "/settings/version", sentence(err.Error()))
		return
	}
	if err := s.submit(r, helper.Request{Action: helper.ActionNetwork, Network: &c}); err != nil {
		s.redirectErr(w, r, "/settings/version", err.Error())
		return
	}
	what := "DHCP"
	if !c.DHCP {
		what = c.Address + " via " + c.Gateway + ", DNS " + strings.Join(c.DNS, " ")
	}
	s.audit(r, "settings.server-network", "settings", "server network: %s, name %s", what, c.Hostname)
	s.redirect(w, r, "/settings/version", "The network settings are being applied. If the address changed, open the console on the new address; settings that cut the server off are undone after 30 seconds.")
}

// sentence makes a helper message ("enter …") a sentence for the page.
func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

// ---- EmailZit updates

const settingUpdates = "server_updates"

// UpdateSettings: automatic installation of new versions.
type UpdateSettings struct {
	Auto bool `json:"auto"`
	Hour int  `json:"hour"` // server time, 0–23
}

// updateState is the last check for a new version.
type updateState struct {
	mu      sync.Mutex
	checked time.Time
	latest  *update.Manifest
	err     string
}

func (s *Server) updateSource() string {
	if v := os.Getenv("EMAILZIT_UPDATE_SOURCE"); v != "" {
		return v
	}
	return update.DefaultSource
}

// CheckUpdate looks for a newer signed release.
func (s *Server) CheckUpdate(ctx context.Context) {
	m, _, _, err := update.Fetch(ctx, &http.Client{Timeout: 30 * time.Second}, s.updateSource(), "")
	s.upd.mu.Lock()
	defer s.upd.mu.Unlock()
	s.upd.checked = s.now()
	if err != nil {
		s.upd.err = err.Error()
		return
	}
	s.upd.err, s.upd.latest = "", m
}

// RunUpdates checks for new versions every six hours and installs them in
// the chosen hour when automatic updates are on.
func (s *Server) RunUpdates(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	hourly := time.NewTicker(time.Hour)
	defer hourly.Stop()
	s.CheckUpdate(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.CheckUpdate(ctx)
		case <-hourly.C:
			var u UpdateSettings
			_ = s.store.GetSetting(ctx, settingUpdates, &u)
			s.upd.mu.Lock()
			latest := s.upd.latest
			s.upd.mu.Unlock()
			if !u.Auto || latest == nil || s.now().Hour() != u.Hour || !update.Newer(latest.Version, s.Version) || !s.helperOK() || helper.Pending(s.DataDir) {
				continue
			}
			if err := helper.Submit(s.DataDir, helper.Request{Action: helper.ActionUpdate, Version: latest.Version, RequestedBy: "automatic"}); err == nil {
				_ = s.store.Audit(ctx, "-", "local", "server.update", "settings", "automatic installation of EmailZit "+latest.Version+" started")
			}
		}
	}
}

type versionData struct {
	Version    string
	Latest     *update.Manifest
	Newer      bool
	Checked    time.Time
	CheckErr   string
	S          UpdateSettings
	Hours      []int
	HelperOK   bool
	Pending    bool
	Last       *helper.Result
	Source     string
	Unofficial bool
	Zones      []string
	Zone       string
	Net        serverNetwork
	OS         *helper.OSStatus // operating system updates (from the helper)
	OSLast     *helper.Result   // the last SSH, OS or reboot request
	SSH        helper.SSHConfig
	Appliance  bool
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	d := &versionData{Version: s.Version, HelperOK: s.helperOK(), Source: s.updateSource()}
	if d.HelperOK {
		d.Zones, d.Zone, d.Net = timeZones(), helper.SystemTimeZone(""), readServerNetwork()
		d.SSH, d.Appliance = helper.ReadSSH(""), helper.IsAppliance("")
		if s.DataDir != "" {
			d.OS, _ = helper.ReadOSStatus(s.DataDir)
			// the status is refreshed by itself when it is older than half a day
			if (d.OS == nil || time.Since(d.OS.Checked) > 12*time.Hour) && !helper.Pending(s.DataDir) {
				_ = helper.Submit(s.DataDir, helper.Request{Action: helper.ActionOSStatus, RequestedBy: "panel"})
			}
			if d.OS != nil {
				d.SSH.Enabled = d.OS.SSHRunning
			}
		}
	}
	d.Unofficial = d.Source != update.DefaultSource
	_ = s.store.GetSetting(r.Context(), settingUpdates, &d.S)
	for h := 0; h < 24; h++ {
		d.Hours = append(d.Hours, h)
	}
	s.upd.mu.Lock()
	d.Latest, d.Checked, d.CheckErr = s.upd.latest, s.upd.checked, s.upd.err
	s.upd.mu.Unlock()
	d.Newer = d.Latest != nil && update.Newer(d.Latest.Version, s.Version)
	if s.DataDir != "" {
		d.Pending = helper.Pending(s.DataDir)
	}
	if res := s.lastHelperResult(); res != nil {
		switch res.Action {
		case helper.ActionUpdate:
			d.Last = res
		case helper.ActionSSH, helper.ActionOSStatus, helper.ActionOSAuto, helper.ActionOSUpgrade, helper.ActionReboot:
			d.OSLast = res
		}
	}
	s.render(w, r, http.StatusOK, "version", &Page{Title: "Updates and server", Nav: "settings", Data: d})
}

func (s *Server) handleVersionCheck(w http.ResponseWriter, r *http.Request) {
	s.CheckUpdate(r.Context())
	s.upd.mu.Lock()
	err := s.upd.err
	s.upd.mu.Unlock()
	if err != "" {
		s.redirectErr(w, r, "/settings/version", translate(s.lang(r, userFrom(r)), "The check for a new version failed: %s", err))
		return
	}
	s.redirect(w, r, "/settings/version", "Checked.")
}

func (s *Server) handleVersionInstall(w http.ResponseWriter, r *http.Request) {
	s.upd.mu.Lock()
	latest := s.upd.latest
	s.upd.mu.Unlock()
	v := r.FormValue("version")
	if latest == nil || latest.Version != v || !update.Newer(v, s.Version) {
		s.redirectErr(w, r, "/settings/version", "There is no newer version to install.")
		return
	}
	if err := s.submit(r, helper.Request{Action: helper.ActionUpdate, Version: v}); err != nil {
		s.redirectErr(w, r, "/settings/version", err.Error())
		return
	}
	s.audit(r, "server.update", "settings", "installation of EmailZit %s started (running %s)", v, s.Version)
	s.redirect(w, r, "/settings/version", "The installation has started. The console restarts in a minute or two; reload this page then.")
}

func (s *Server) handleVersionSettings(w http.ResponseWriter, r *http.Request) {
	u := UpdateSettings{Auto: r.FormValue("auto") == "1"}
	u.Hour, _ = strconv.Atoi(r.FormValue("hour"))
	if u.Hour < 0 || u.Hour > 23 {
		u.Hour = 3
	}
	if err := s.store.SetSetting(r.Context(), settingUpdates, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.server-updates", "settings", "automatic EmailZit updates: %v at %02d:00", u.Auto, u.Hour)
	s.redirect(w, r, "/settings/version", "Saved.")
}

// ---- operating system updates, server restart and SSH

// handleOS asks the helper for an operating system task: refresh the
// status, automatic security updates on or off, install all updates, or
// restart the server.
func (s *Server) handleOS(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/version#os"
	req := helper.Request{}
	lang := s.lang(r, userFrom(r))
	msg := ""
	switch r.FormValue("do") {
	case "status":
		req.Action, msg = helper.ActionOSStatus, translate(lang, "Looking for operating system updates; reload the page in a minute.")
	case "auto-on", "auto-off":
		req.Action, req.Enable = helper.ActionOSAuto, r.FormValue("do") == "auto-on"
		msg = translate(lang, "Saved; reload the page in a minute.")
	case "upgrade":
		req.Action, msg = helper.ActionOSUpgrade, translate(lang, "The operating system updates are being installed; reload the page in a few minutes.")
	case "reboot":
		req.Action, msg = helper.ActionReboot, translate(lang, "The server restarts; the panel is back in a minute or two.")
	default:
		s.redirectErr(w, r, back, "Unknown action.")
		return
	}
	if err := s.submit(r, req); err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	s.audit(r, "server."+req.Action, "settings", "operating system: %s requested", req.Action)
	s.redirect(w, r, back, msg)
}

// handleSSH switches the appliance's SSH server on or off and sets its port.
func (s *Server) handleSSH(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/version#ssh"
	if !helper.IsAppliance("") {
		s.redirectErr(w, r, back, "SSH of this server is managed by its operating system; it can be changed here only on the EmailZit appliance.")
		return
	}
	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	c := helper.SSHConfig{Enabled: r.FormValue("enabled") == "1", Port: port}
	if err == nil {
		err = c.Validate()
	}
	if err != nil {
		s.redirectErr(w, r, back, "Enter an SSH port between 1 and 65535 that EmailZit does not use.")
		return
	}
	if err := s.submit(r, helper.Request{Action: helper.ActionSSH, SSH: &c}); err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	state := "off"
	if c.Enabled {
		state = "on, port " + strconv.Itoa(c.Port)
	}
	s.audit(r, "settings.ssh", "settings", "SSH of the server: %s", state)
	s.redirect(w, r, back, "The SSH setting is being applied; reload the page in a few seconds.")
}
