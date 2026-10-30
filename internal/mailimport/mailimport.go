// Package mailimport reads the archives EmailZit takes in: its own export
// (manifest.json + mail/<domain>/<local>/Maildir/…) and a cPanel account
// backup (cpmove-USER.tar.gz: homedir/mail/<domain>/<user>/ Maildirs,
// homedir/etc/<domain>/passwd and quota, va/<domain> forwarders). Scan
// collects what must be created in the database; MailPath tells the root
// helper where a mail file of the archive goes. Nothing here trusts the
// archive: names are checked, links and odd entries are skipped.
package mailimport

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Formats.
const (
	FormatEmailZit = "emailzit"
	FormatCPanel   = "cpanel"
)

// Plan is what an archive holds besides the mail files.
type Plan struct {
	Domains   []string  `json:"domains"`
	Mailboxes []Mailbox `json:"mailboxes"`
	Aliases   []Alias   `json:"aliases"`
	SpamLevel string    `json:"spam_level,omitempty"`
	Notes     []string  `json:"notes"`
	MailFiles int       `json:"mail_files"`
}

// Mailbox is a mailbox to create.
type Mailbox struct {
	Address     string          `json:"address"`
	DisplayName string          `json:"display_name,omitempty"`
	QuotaMB     int             `json:"quota_mb,omitempty"`
	Disabled    bool            `json:"disabled,omitempty"`
	SpamLevel   string          `json:"spam_level,omitempty"`
	SpamAllow   []string        `json:"spam_allow,omitempty"`
	SpamBlock   []string        `json:"spam_block,omitempty"`
	Filters     json.RawMessage `json:"filters,omitempty"`
}

// Alias is a forwarder to create.
type Alias struct {
	Address      string   `json:"address"`
	Destinations []string `json:"destinations"`
	SendAs       bool     `json:"send_as,omitempty"`
}

var (
	domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	localRE  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_+-]|\.[a-z0-9_+-]){0,63}$`)
	addrRE   = regexp.MustCompile(`^[a-z0-9._%+'=-]{1,64}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// ValidAddress tells a mailbox address EmailZit can create.
func ValidAddress(a string) bool {
	l, d, ok := strings.Cut(a, "@")
	return ok && localRE.MatchString(l) && domainRE.MatchString(d) && len(a) <= 254
}

// Limits of what Scan reads into memory.
const (
	maxManifest = 8 << 20
	maxConfig   = 4 << 20
	maxEntries  = 5_000_000
)

// open reads a gzip-compressed tar.
func open(r io.Reader) (*tar.Reader, error) {
	zr, err := gzip.NewReader(bufio.NewReaderSize(r, 1<<20))
	if err != nil {
		return nil, errors.New("not a .tar.gz archive")
	}
	return tar.NewReader(zr), nil
}

// clean splits a tar name into checked path parts ("" parts and "."
// dropped); nil when the name tries to leave the archive.
func clean(name string) []string {
	var out []string
	for _, p := range strings.Split(strings.ReplaceAll(name, "\\", "/"), "/") {
		switch p {
		case "", ".":
			continue
		case "..":
			return nil
		}
		out = append(out, p)
	}
	return out
}

// MailPath maps an archive entry to a mailbox and the path inside its
// Maildir; ok is false for entries that are not mail of a mailbox.
func MailPath(format, name string) (address, rel string, ok bool) {
	parts := clean(name)
	switch format {
	case FormatEmailZit:
		// mail/<domain>/<local>/Maildir/…
		if len(parts) < 5 || parts[0] != "mail" || parts[3] != "Maildir" {
			return "", "", false
		}
		address, parts = parts[2]+"@"+parts[1], parts[4:]
	case FormatCPanel:
		// [cpmove-USER/]homedir/mail/<domain>/<user>/…
		i := index(parts, "homedir")
		if i < 0 || len(parts) < i+5 || parts[i+1] != "mail" || !strings.Contains(parts[i+2], ".") {
			return "", "", false
		}
		address, parts = parts[i+3]+"@"+parts[i+2], parts[i+4:]
	default:
		return "", "", false
	}
	address = strings.ToLower(address)
	if !ValidAddress(address) || len(parts) == 0 {
		return "", "", false
	}
	for _, p := range parts {
		if len(p) > 255 || strings.ContainsAny(p, "\x00") {
			return "", "", false
		}
	}
	return address, path.Join(parts...), true
}

func index(parts []string, s string) int {
	for i, p := range parts {
		if p == s {
			return i
		}
	}
	return -1
}

// Scan reads an archive once and collects its plan.
func Scan(r io.Reader, format string) (*Plan, error) {
	tr, err := open(r)
	if err != nil {
		return nil, err
	}
	p := &Plan{}
	boxes := map[string]*Mailbox{}
	var order []string
	domains := map[string]bool{}
	addBox := func(addr string) *Mailbox {
		if b := boxes[addr]; b != nil {
			return b
		}
		b := &Mailbox{Address: addr}
		boxes[addr], order = b, append(order, addr)
		return b
	}
	var manifest []byte
	quotas := map[string]int{} // address → MB (cPanel)
	for n := 0; ; n++ {
		if n > maxEntries {
			return nil, errors.New("the archive has too many entries")
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the archive is damaged: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if addr, _, ok := MailPath(format, h.Name); ok {
			addBox(addr)
			domains[addr[strings.IndexByte(addr, '@')+1:]] = true
			p.MailFiles++
			continue
		}
		parts := clean(h.Name)
		switch {
		case format == FormatEmailZit && len(parts) == 1 && parts[0] == "manifest.json":
			if manifest, err = io.ReadAll(io.LimitReader(tr, maxManifest+1)); err != nil || len(manifest) > maxManifest {
				return nil, errors.New("the manifest is too large or damaged")
			}
		case format == FormatCPanel:
			i := index(parts, "homedir")
			if i >= 0 && len(parts) == i+4 && parts[i+1] == "etc" && domainRE.MatchString(strings.ToLower(parts[i+2])) {
				dom := strings.ToLower(parts[i+2])
				b, err := io.ReadAll(io.LimitReader(tr, maxConfig))
				if err != nil {
					return nil, err
				}
				switch parts[i+3] {
				case "passwd":
					for _, l := range strings.Split(string(b), "\n") {
						user, _, _ := strings.Cut(strings.TrimSpace(l), ":")
						if addr := strings.ToLower(user) + "@" + dom; user != "" && ValidAddress(addr) {
							addBox(addr)
							domains[dom] = true
						}
					}
				case "quota":
					for _, l := range strings.Split(string(b), "\n") {
						user, v, ok := strings.Cut(strings.TrimSpace(l), ":")
						if bytes, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); ok && err == nil && bytes > 0 {
							quotas[strings.ToLower(user)+"@"+dom] = int(min(bytes>>20, 1<<20))
						}
					}
				}
				continue
			}
			if j := index(parts, "va"); j >= 0 && len(parts) == j+2 && domainRE.MatchString(strings.ToLower(parts[j+1])) {
				b, err := io.ReadAll(io.LimitReader(tr, maxConfig))
				if err != nil {
					return nil, err
				}
				p.Aliases = append(p.Aliases, parseValiases(strings.ToLower(parts[j+1]), string(b), p)...)
			}
		}
	}
	switch format {
	case FormatEmailZit:
		if manifest == nil {
			return nil, errors.New("this is not an EmailZit export (no manifest.json)")
		}
		var m struct {
			Format    string                  `json:"format"`
			SpamLevel string                  `json:"spam_level"`
			Domains   []struct{ Name string } `json:"domains"`
			Mailboxes []Mailbox               `json:"mailboxes"`
			Aliases   []Alias                 `json:"aliases"`
		}
		if err := json.Unmarshal(manifest, &m); err != nil || m.Format != "emailzit-export/1" {
			return nil, errors.New("the manifest is not an EmailZit export of a known version")
		}
		p.SpamLevel = m.SpamLevel
		for _, d := range m.Domains {
			if d := strings.ToLower(d.Name); domainRE.MatchString(d) {
				domains[d] = true
			}
		}
		for _, mb := range m.Mailboxes {
			mb.Address = strings.ToLower(mb.Address)
			if !ValidAddress(mb.Address) {
				p.Notes = append(p.Notes, "skipped mailbox "+trim(mb.Address))
				continue
			}
			b := addBox(mb.Address)
			files := b.Address // keep the address, take the settings
			*b = mb
			b.Address = files
		}
		for _, a := range m.Aliases {
			a.Address = strings.ToLower(a.Address)
			if okAlias(&a) {
				p.Aliases = append(p.Aliases, a)
			} else {
				p.Notes = append(p.Notes, "skipped alias "+trim(a.Address))
			}
		}
	case FormatCPanel:
		if len(order) == 0 && len(p.Aliases) == 0 {
			return nil, errors.New("no mail found: is this a cPanel account backup (cpmove-USER.tar.gz)?")
		}
		for addr, q := range quotas {
			if b := boxes[addr]; b != nil {
				b.QuotaMB = q
			}
		}
		p.Notes = append(p.Notes, "cPanel passwords are not taken over: set a password for each mailbox; mail programs then use app passwords")
	default:
		return nil, errors.New("unknown format")
	}
	for _, a := range p.Aliases {
		domains[a.Address[strings.IndexByte(a.Address, '@')+1:]] = true
	}
	for d := range domains {
		p.Domains = append(p.Domains, d)
	}
	sort.Strings(p.Domains)
	for _, a := range order {
		p.Mailboxes = append(p.Mailboxes, *boxes[a])
	}
	return p, nil
}

// parseValiases reads a cPanel forwarder file ("alias@domain: dest, dest").
// Pipes, files, :fail: / :blackhole: and the catch-all are left out.
func parseValiases(dom, text string, p *Plan) []Alias {
	var out []Alias
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok {
			continue
		}
		if k == "*" {
			p.Notes = append(p.Notes, "catch-all of "+dom+" not taken over (set it on the domain page if wanted)")
			continue
		}
		if !strings.Contains(k, "@") {
			k += "@" + dom
		}
		a := Alias{Address: k}
		for _, d := range strings.Split(v, ",") {
			d = strings.ToLower(strings.Trim(strings.TrimSpace(d), `"`))
			if d == "" {
				continue
			}
			if strings.HasPrefix(d, "|") || strings.HasPrefix(d, "/") || strings.HasPrefix(d, ":") {
				p.Notes = append(p.Notes, "skipped forwarder target of "+trim(k)+" (program, file or :fail:)")
				continue
			}
			a.Destinations = append(a.Destinations, d)
		}
		if okAlias(&a) {
			out = append(out, a)
		}
	}
	return out
}

func okAlias(a *Alias) bool {
	if !addrRE.MatchString(a.Address) || len(a.Destinations) == 0 || len(a.Destinations) > 50 {
		return false
	}
	for _, d := range a.Destinations {
		if !addrRE.MatchString(d) {
			return false
		}
	}
	return true
}

func trim(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

// Each calls fn for every mail file of the archive (regular files only),
// with the mailbox address and the path inside the Maildir.
func Each(r io.Reader, format string, fn func(address, rel string, h *tar.Header, body io.Reader) error) error {
	tr, err := open(r)
	if err != nil {
		return err
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("the archive is damaged: %w", err)
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 {
			continue
		}
		if addr, rel, ok := MailPath(format, h.Name); ok {
			if err := fn(addr, rel, h, tr); err != nil {
				return err
			}
		}
	}
}
