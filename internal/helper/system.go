package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata" // check zone names also where the system lacks zoneinfo
)

// ---- time zone

var zoneRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)

// ValidTimeZone checks an IANA time zone name such as Europe/Belgrade.
func ValidTimeZone(name string) error {
	if name == "" || name == "Local" || !zoneRe.MatchString(name) {
		return errors.New("unknown time zone")
	}
	if _, err := time.LoadLocation(name); err != nil {
		return errors.New("unknown time zone")
	}
	return nil
}

// SystemTimeZone is the zone of /etc/localtime (UTC when not set).
func SystemTimeZone(root string) string {
	t, err := os.Readlink(filepath.Join(root, "/etc/localtime"))
	if err != nil {
		return "UTC"
	}
	if _, z, ok := strings.Cut(t, "zoneinfo/"); ok && ValidTimeZone(z) == nil {
		return z
	}
	return "UTC"
}

func (h *Helper) timeZone(ctx context.Context, req Request, res Result) Result {
	if err := ValidTimeZone(req.TimeZone); err != nil {
		res.Status, res.Message = "failed", err.Error()
		return res
	}
	if _, err := h.Run(ctx, "timedatectl", "set-timezone", req.TimeZone); err != nil {
		res.Status, res.Message = "failed", err.Error()
		return res
	}
	res.Status, res.Message, res.restart = "done", "time zone set to "+req.TimeZone, true
	return res
}

// ---- network (the EmailZit appliance only)

// ApplianceMarker exists on the EmailZit appliance (written at its first
// start). Elsewhere the server's network belongs to its administrator.
const ApplianceMarker = "/var/lib/emailzit/.appliance"

// NetworkFile is the systemd-networkd file the appliance uses.
const NetworkFile = "/etc/systemd/network/50-emailzit.network"

// NetworkConfig is the wanted network configuration.
type NetworkConfig struct {
	DHCP     bool     `json:"dhcp"`
	Address  string   `json:"address,omitempty"` // with prefix, e.g. 192.168.1.20/24
	Gateway  string   `json:"gateway,omitempty"`
	DNS      []string `json:"dns,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
}

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// Validate checks a configuration.
func (c *NetworkConfig) Validate() error {
	if c.Hostname != "" && !hostRe.MatchString(c.Hostname) {
		return errors.New("the server name may contain letters, digits and hyphens")
	}
	if c.DHCP {
		return nil
	}
	p, err := netip.ParsePrefix(c.Address)
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 30 {
		return errors.New("enter the address with its network size, e.g. 192.168.1.20/24")
	}
	g, err := netip.ParseAddr(c.Gateway)
	if err != nil || !g.Is4() || !p.Contains(g) || g == p.Addr() {
		return errors.New("the gateway must be another address in the same network")
	}
	if len(c.DNS) == 0 || len(c.DNS) > 3 {
		return errors.New("enter one to three DNS servers")
	}
	for _, d := range c.DNS {
		if a, err := netip.ParseAddr(d); err != nil || !a.Is4() {
			return errors.New("enter the DNS servers as IPv4 addresses")
		}
	}
	return nil
}

// IsAppliance reports whether this is the EmailZit appliance.
func IsAppliance(root string) bool {
	_, err := os.Stat(filepath.Join(root, ApplianceMarker))
	return err == nil
}

// networkFile renders the systemd-networkd file.
func networkFile(iface string, c NetworkConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by EmailZit (Settings → Network).\n[Match]\nName=%s\n\n[Network]\n", iface)
	if c.DHCP {
		b.WriteString("DHCP=ipv4\n")
	} else {
		fmt.Fprintf(&b, "Address=%s\nGateway=%s\n", c.Address, c.Gateway)
		for _, d := range c.DNS {
			fmt.Fprintf(&b, "DNS=%s\n", d)
		}
	}
	return b.String()
}

// mainInterface is the interface of the default route, else the first
// Ethernet interface.
func (h *Helper) mainInterface(ctx context.Context) (string, error) {
	out, err := h.Run(ctx, "ip", "-j", "route", "show", "default")
	if err == nil {
		var routes []struct{ Dev string }
		if json.Unmarshal(out, &routes) == nil && len(routes) > 0 && routes[0].Dev != "" {
			return routes[0].Dev, nil
		}
	}
	out, err = h.Run(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return "", err
	}
	var links []struct {
		Ifname   string `json:"ifname"`
		LinkType string `json:"link_type"`
	}
	_ = json.Unmarshal(out, &links)
	for _, l := range links {
		if l.LinkType == "ether" {
			return l.Ifname, nil
		}
	}
	return "", errors.New("no network interface found")
}

func (h *Helper) network(ctx context.Context, req Request, res Result) Result {
	fail := func(err error) Result {
		res.Status, res.Message = "failed", err.Error()
		return res
	}
	if !IsAppliance(h.Root) {
		return fail(errors.New("the network can only be changed on the EmailZit appliance"))
	}
	if req.Network == nil {
		return fail(errors.New("incomplete request"))
	}
	c := *req.Network
	if err := c.Validate(); err != nil {
		return fail(err)
	}
	iface, err := h.mainInterface(ctx)
	if err != nil {
		return fail(err)
	}
	path := h.path(NetworkFile)
	old, oldErr := os.ReadFile(path)                               // #nosec G304 -- fixed path
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- /etc/systemd/network
		return fail(err)
	}
	if err := os.WriteFile(path, []byte(networkFile(iface, c)), 0o644); err != nil { // #nosec G306 -- a network file
		return fail(err)
	}
	if c.Hostname != "" {
		if _, err := h.Run(ctx, "hostnamectl", "set-hostname", c.Hostname); err != nil {
			return fail(err)
		}
	}
	_, _ = h.Run(ctx, "networkctl", "reload")
	_, rerr := h.Run(ctx, "networkctl", "reconfigure", iface)
	// A static address whose gateway does not answer would cut the
	// appliance off: go back to the old settings.
	if rerr == nil && !c.DHCP {
		rerr = h.waitGateway(ctx, c.Gateway)
	}
	if rerr != nil {
		if oldErr == nil {
			_ = os.WriteFile(path, old, 0o644) // #nosec G306 G703 -- the fixed network file
		} else {
			_ = os.Remove(path)
		}
		_, _ = h.Run(ctx, "networkctl", "reload")
		_, _ = h.Run(ctx, "networkctl", "reconfigure", iface)
		return fail(fmt.Errorf("the new settings did not work (%v); the previous ones are back", rerr))
	}
	res.Status = "done"
	if c.DHCP {
		res.Message = "network: DHCP on " + iface
	} else {
		res.Message = "network: " + c.Address + " via " + c.Gateway + " on " + iface
	}
	return res
}

func (h *Helper) waitGateway(ctx context.Context, gw string) error {
	for i := 0; i < 15; i++ {
		if _, err := h.Run(ctx, "ping", "-c", "1", "-W", "2", gw); err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("the gateway " + gw + " does not answer")
}
