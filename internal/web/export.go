package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/auth"
	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/store"
)

// Export of a customer (INTEGRATION P8): the mail helper packs the
// customer's mail directory and a manifest of the settings (no passwords,
// second factors or keys) into exports/<customer>/<time>.tar.gz in the data
// directory; BackupZit or a move to another server fetches it through the
// API (or the agent backs up the folder). Exports run as jobs; the newest
// three of a customer are kept. WatchZit reads the server status.

// job is a running or finished export (kept in memory for a day).
type job struct {
	ID         string                   `json:"id"`
	Kind       string                   `json:"kind"`
	CustomerID string                   `json:"customer_id"`
	Status     string                   `json:"status"` // running, done, failed
	Error      string                   `json:"error,omitempty"`
	Result     *mailhelper.ExportResult `json:"result,omitempty"`
	Started    time.Time                `json:"started_at"`
	Finished   *time.Time               `json:"finished_at,omitempty"`
}

type jobList struct {
	sync.Mutex
	m map[string]*job
}

func (l *jobList) get(id string) *job {
	l.Lock()
	defer l.Unlock()
	if j := l.m[id]; j != nil {
		c := *j
		return &c
	}
	return nil
}

// exportManifest describes the settings of an exported customer.
type exportManifest struct {
	Format    string           `json:"format"` // emailzit-export/1
	Version   string           `json:"version"`
	CreatedAt time.Time        `json:"created_at"`
	Customer  apiCustomer      `json:"customer"`
	SpamLevel string           `json:"spam_level"`
	Domains   []exportDomain   `json:"domains"`
	Mailboxes []exportMailbox  `json:"mailboxes"`
	Aliases   []exportAlias    `json:"aliases"`
	Notes     []string         `json:"notes"`
	Extra     map[string]int64 `json:"counts"`
}

type exportDomain struct {
	Name     string `json:"name"`
	CatchAll string `json:"catch_all,omitempty"`
	Verified bool   `json:"verified"`
	Disabled bool   `json:"disabled"`
}

type exportMailbox struct {
	Address     string          `json:"address"`
	DisplayName string          `json:"display_name,omitempty"`
	QuotaMB     int             `json:"quota_mb"`
	Disabled    bool            `json:"disabled"`
	SpamLevel   string          `json:"spam_level,omitempty"`
	SpamAllow   []string        `json:"spam_allow,omitempty"`
	SpamBlock   []string        `json:"spam_block,omitempty"`
	Filters     json.RawMessage `json:"filters,omitempty"` // auto-reply and filters
	Folder      string          `json:"folder"`            // mail/<domain>/<local>
}

type exportAlias struct {
	Address      string   `json:"address"`
	Destinations []string `json:"destinations"`
	SendAs       bool     `json:"send_as"`
}

func (s *Server) exportManifest(ctx context.Context, c *store.Customer) (*exportManifest, error) {
	m := &exportManifest{Format: "emailzit-export/1", Version: s.Version, CreatedAt: time.Now().UTC(), Customer: s.toAPICustomer(ctx, c),
		Notes: []string{"Passwords, app passwords, second factors and DKIM keys are not exported: users set new ones on the new server."},
		Extra: map[string]int64{}}
	m.SpamLevel, _ = s.store.CustomerSpamLevel(ctx, c.ID)
	doms, err := s.store.Domains(ctx, store.Staff, c.ID)
	if err != nil {
		return nil, err
	}
	for _, d := range doms {
		m.Domains = append(m.Domains, exportDomain{Name: d.Name, CatchAll: d.CatchAll, Verified: d.Verified, Disabled: d.Disabled})
	}
	boxes, err := s.store.Mailboxes(ctx, store.Staff, store.MailboxFilter{CustomerID: c.ID, Limit: 100000})
	if err != nil {
		return nil, err
	}
	for _, b := range boxes {
		local, dom, _ := cutAt(b.Address)
		e := exportMailbox{Address: b.Address, DisplayName: b.DisplayName, QuotaMB: b.QuotaMB, Disabled: b.Disabled, Folder: "mail/" + dom + "/" + local}
		if sp, err := s.store.MailboxSpamSettings(ctx, store.Staff, b.ID); err == nil {
			e.SpamLevel, e.SpamAllow, e.SpamBlock = sp.Level, sp.Allow, sp.Block
		}
		if raw, err := s.store.MailboxSieve(ctx, b.ID); err == nil && len(raw) > 0 && string(raw) != "null" && string(raw) != "{}" {
			e.Filters = raw
		}
		m.Mailboxes = append(m.Mailboxes, e)
		m.Extra["used_bytes"] += b.UsedBytes
	}
	aliases, err := s.store.Aliases(ctx, store.Staff, c.ID, "")
	if err != nil {
		return nil, err
	}
	for _, a := range aliases {
		m.Aliases = append(m.Aliases, exportAlias{Address: a.Address, Destinations: a.Destinations, SendAs: a.SendAs})
	}
	return m, nil
}

var errExportRunning = errors.New("an export of this customer is already running")

// startExport begins an export job of a customer.
func (s *Server) startExport(c *store.Customer, by string) (*job, error) {
	s.jobs.Lock()
	if s.jobs.m == nil {
		s.jobs.m = map[string]*job{}
	}
	for id, j := range s.jobs.m {
		if j.Finished != nil && time.Since(*j.Finished) > 24*time.Hour {
			delete(s.jobs.m, id)
		} else if j.CustomerID == c.ID && j.Status == "running" {
			s.jobs.Unlock()
			return nil, errExportRunning
		}
	}
	j := &job{ID: "job_" + auth.RandomToken(12), Kind: "export", CustomerID: c.ID, Status: "running", Started: time.Now().UTC()}
	s.jobs.m[j.ID] = j
	s.jobs.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mailhelper.ExportTimeout)
		defer cancel()
		res, err := s.runExport(ctx, c, by)
		now := time.Now().UTC()
		s.jobs.Lock()
		j.Finished, j.Result = &now, res
		if err != nil {
			j.Status, j.Error = "failed", err.Error()
		} else {
			j.Status = "done"
		}
		s.jobs.Unlock()
		target := "customer:" + c.ID
		if err != nil {
			s.log.Error("export", "customer", c.ID, "err", err)
			_ = s.store.Audit(context.Background(), by, "local", "customer.export.failed", target, err.Error())
			return
		}
		_ = s.store.Audit(context.Background(), by, "local", "customer.export", target, fmt.Sprintf("%s: %d files, %d bytes", res.File, res.Files, res.Size))
	}()
	return j, nil
}

func (s *Server) runExport(ctx context.Context, c *store.Customer, by string) (*mailhelper.ExportResult, error) {
	m, err := s.exportManifest(ctx, c)
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return nil, err
	}
	var res mailhelper.ExportResult
	req := mailhelper.Request{Action: mailhelper.ActionExport, Customer: c.ID, Name: time.Now().UTC().Format("20060102-150405"), Manifest: string(b), By: by}
	if err := (&mailhelper.Client{Socket: mailhelper.Socket}).CallData(ctx, req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

var exportFileRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}\.tar\.gz$`)

type exportFile struct {
	Name string    `json:"name"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

func (s *Server) exportDir(customerID string) string {
	return filepath.Join(s.DataDir, "exports", customerID)
}

// Human is the size for people.
func (e exportFile) Human() string { return formatBytes(uint64(max(e.Size, 0))) }

// exportFiles lists the finished exports of a customer, newest first.
func (s *Server) exportFiles(customerID string) []exportFile {
	out := []exportFile{}
	if s.DataDir == "" {
		return out
	}
	ents, _ := os.ReadDir(s.exportDir(customerID))
	for _, e := range ents {
		if !exportFileRE.MatchString(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() {
			out = append(out, exportFile{Name: e.Name(), Size: fi.Size(), Time: fi.ModTime().UTC()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

// sendExport streams one export file.
func (s *Server) sendExport(w http.ResponseWriter, r *http.Request, customerID, name string) bool {
	if !exportFileRE.MatchString(name) || s.DataDir == "" {
		return false
	}
	// #nosec G304 -- the name matched exportFileRE, the customer was loaded from the database
	f, err := os.Open(filepath.Join(s.exportDir(customerID), name))
	if err != nil {
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="emailzit-`+customerID[:8]+`-`+name+`"`)
	w.Header().Set("Content-Length", fmt.Sprint(fi.Size()))
	_, _ = io.Copy(w, f)
	return true
}

// ---- API

func (s *Server) apiExport(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoadCustomer(w, r)
	if c == nil {
		return
	}
	j, err := s.startExport(c, "api:"+apiToken(r).Name)
	if errors.Is(err, errExportRunning) {
		apiError(w, http.StatusConflict, "conflict", err.Error(), "")
		return
	}
	s.apiAudit(r, "customer.export.start", "customer:"+c.ID, "export started (%s)", j.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.ID, "status": j.Status})
}

func (s *Server) apiJob(w http.ResponseWriter, r *http.Request) {
	j := s.jobs.get(r.PathValue("id"))
	if j == nil {
		apiError(w, http.StatusNotFound, "not_found", "no such job (jobs are kept for a day)", "")
		return
	}
	writeJSON(w, http.StatusOK, j)
}

func (s *Server) apiExports(w http.ResponseWriter, r *http.Request) {
	if c := s.apiLoadCustomer(w, r); c != nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": s.exportFiles(c.ID)})
	}
}

func (s *Server) apiExportDownload(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoadCustomer(w, r)
	if c == nil {
		return
	}
	if !s.sendExport(w, r, c.ID, r.PathValue("name")) {
		apiError(w, http.StatusNotFound, "not_found", "no such export", "")
		return
	}
	s.apiAudit(r, "customer.export.download", "customer:"+c.ID, "%s", r.PathValue("name"))
}

// apiServerStatus is the health of the server for WatchZit.
func (s *Server) apiServerStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"product": "emailzit", "version": s.Version}
	if counts, err := s.store.CustomerCounts(r.Context()); err == nil {
		out["customers"] = counts
	}
	var st mailhelper.Status
	if s.Mail == nil {
		out["helper_error"] = "the mail system is not installed"
	} else if err := (&mailhelper.Client{Socket: mailhelper.Socket}).CallData(r.Context(), mailhelper.Request{Action: mailhelper.ActionStatus}, &st); err != nil {
		out["helper_error"] = "the mail helper is not reachable"
	} else {
		out["services"], out["queue"], out["deferred"] = st.Services, st.Queue, st.Deferred
		out["disk"] = map[string]int64{"total_mb": st.DiskTotalMB, "free_mb": st.DiskFreeMB}
		if st.CertNotAfter != nil {
			out["certificate_not_after"] = st.CertNotAfter
			out["certificate_days_left"] = int(time.Until(*st.CertNotAfter).Hours() / 24)
		}
		ok := true
		for _, v := range st.Services {
			ok = ok && v == "active"
		}
		out["ok"] = ok
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- panel (staff, customer page)

func (s *Server) handleCustomerExport(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + c.ID + "#export"
	j, err := s.startExport(c, userFrom(r).Username)
	if err != nil {
		s.redirectErr(w, r, back, "An export of this customer is already running.")
		return
	}
	s.audit(r, "customer.export.start", "customer:"+c.ID, "export started (%s)", j.ID)
	s.redirect(w, r, back, "The export was started; reload the page to see it when it is ready.")
}

func (s *Server) handleCustomerExportDownload(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	if !s.sendExport(w, r, c.ID, r.PathValue("name")) {
		s.notFound(w, r)
		return
	}
	s.audit(r, "customer.export.download", "customer:"+c.ID, "%s", r.PathValue("name"))
}

// exportRunning tells whether an export of the customer is running.
func (s *Server) exportRunning(customerID string) bool {
	s.jobs.Lock()
	defer s.jobs.Unlock()
	for _, j := range s.jobs.m {
		if j.CustomerID == customerID && j.Status == "running" {
			return true
		}
	}
	return false
}
