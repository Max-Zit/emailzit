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
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/auth"
	"github.com/max-zit/emailzit/internal/mailhelper"
	"github.com/max-zit/emailzit/internal/mailimport"
	"github.com/max-zit/emailzit/internal/sieve"
	"github.com/max-zit/emailzit/internal/store"
)

// Import of an archive into a customer: an EmailZit export (a move from
// another EmailZit server) or a cPanel account backup (cpmove-USER.tar.gz;
// HostZit hands over the mail part of its cPanel import this way). The
// archive is uploaded into imports/<customer>/, the panel creates the
// missing domains, mailboxes (with a random password: users set a new one)
// and forwarders, and the root helper writes the mail into the Maildirs.

// maxImport is the largest archive taken.
const maxImport = 200 << 30

// importReport is the result of an import job.
type importReport struct {
	Domains   int                      `json:"domains_created"`
	Mailboxes int                      `json:"mailboxes_created"`
	Aliases   int                      `json:"aliases_created"`
	Mail      *mailhelper.ImportResult `json:"mail,omitempty"`
	Notes     []string                 `json:"notes"`
}

func (s *Server) importDir(customerID string) string {
	return filepath.Join(s.DataDir, "imports", customerID)
}

// saveUpload stores an archive for a customer; the name is the time.
func (s *Server) saveUpload(customerID string, body io.Reader) (string, error) {
	if s.DataDir == "" {
		return "", errors.New("no data directory")
	}
	dir := s.importDir(customerID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := time.Now().UTC().Format("20060102-150405")
	p := filepath.Join(dir, name+".tar.gz")
	// #nosec G304 -- customer UUID from the database and a time as the name
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(body, maxImport+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxImport {
		err = errors.New("the archive is too large")
	}
	if err == nil && n == 0 {
		err = errors.New("the archive is empty")
	}
	if err != nil {
		_ = os.Remove(p)
		return "", err
	}
	return name, nil
}

// startImport begins the import job of an uploaded archive.
func (s *Server) startImport(c *store.Customer, name, format, by string) (*job, error) {
	s.jobs.Lock()
	if s.jobs.m == nil {
		s.jobs.m = map[string]*job{}
	}
	for _, j := range s.jobs.m {
		if j.CustomerID == c.ID && j.Status == "running" {
			s.jobs.Unlock()
			return nil, errExportRunning
		}
	}
	j := &job{ID: "job_" + auth.RandomToken(12), Kind: "import", CustomerID: c.ID, Status: "running", Started: time.Now().UTC()}
	s.jobs.m[j.ID] = j
	s.jobs.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mailhelper.ExportTimeout)
		defer cancel()
		rep, err := s.runArchiveImport(ctx, c, name, format, by)
		now := time.Now().UTC()
		s.jobs.Lock()
		j.Finished, j.Report = &now, rep
		if err != nil {
			j.Status, j.Error = "failed", err.Error()
		} else {
			j.Status = "done"
		}
		s.jobs.Unlock()
		target := "customer:" + c.ID
		if err != nil {
			s.log.Error("import", "customer", c.ID, "err", err)
			_ = s.store.Audit(context.Background(), by, "local", "customer.import.failed", target, err.Error())
			return
		}
		files := 0
		if rep.Mail != nil {
			files = rep.Mail.Files
		}
		_ = s.store.Audit(context.Background(), by, "local", "customer.import", target,
			fmt.Sprintf("%s archive: %d domains, %d mailboxes, %d forwarders created, %d mail files", format, rep.Domains, rep.Mailboxes, rep.Aliases, files))
	}()
	return j, nil
}

func (s *Server) runArchiveImport(ctx context.Context, c *store.Customer, name, format, by string) (*importReport, error) {
	file := filepath.Join(s.importDir(c.ID), name+".tar.gz")
	// #nosec G304 -- the name was made by saveUpload
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	plan, err := mailimport.Scan(f, format)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(file)
		return nil, err
	}
	rep := &importReport{Notes: plan.Notes}
	note := func(format string, a ...any) { rep.Notes = append(rep.Notes, fmt.Sprintf(format, a...)) }
	m := s.MailConfig(ctx)
	doms := map[string]*store.Domain{}
	for _, name := range plan.Domains {
		d, err := s.store.DomainByName(ctx, store.Staff, name)
		switch {
		case err == nil && d.CustomerID != c.ID:
			note("domain %s belongs to another customer: skipped with its mailboxes", name)
			continue
		case err == nil:
		case errors.Is(err, store.ErrNotFound):
			if d, err = s.store.CreateDomain(ctx, store.Staff, c.ID, name, !m.RequireVerification || m.Dedicated); err != nil {
				note("domain %s not created: %s", name, mailErr(err))
				continue
			}
			rep.Domains++
			s.installDKIM(ctx, d.ID)
			s.publishDNS(ctx, d.ID, false, nil)
		default:
			return rep, err
		}
		doms[name] = d
	}
	for _, mb := range plan.Mailboxes {
		local, dom, _ := strings.Cut(mb.Address, "@")
		d := doms[dom]
		if d == nil {
			continue
		}
		box, err := s.store.MailboxByAddress(ctx, mb.Address)
		if err == nil && box.CustomerID != c.ID {
			note("mailbox %s belongs to another customer: skipped", mb.Address)
			continue
		}
		if errors.Is(err, store.ErrNotFound) {
			n := store.NewMailbox{DomainID: d.ID, LocalPart: local, DisplayName: mb.DisplayName, Password: auth.RandomToken(24), QuotaMB: mb.QuotaMB}
			if box, err = s.store.CreateMailbox(ctx, store.Staff, n); err != nil && mb.QuotaMB > 0 {
				n.QuotaMB = 0 // the package's default when the old size does not fit
				box, err = s.store.CreateMailbox(ctx, store.Staff, n)
			}
			if err != nil {
				note("mailbox %s not created: %s", mb.Address, mailErr(err))
				continue
			}
			rep.Mailboxes++
		} else if err != nil {
			return rep, err
		}
		if mb.SpamLevel != "" || len(mb.SpamAllow) > 0 || len(mb.SpamBlock) > 0 {
			allow, _ := sieve.CleanSenders(strings.Join(mb.SpamAllow, "\n"))
			block, _ := sieve.CleanSenders(strings.Join(mb.SpamBlock, "\n"))
			level := mb.SpamLevel
			if !sieve.ValidSpamLevel(level, true) {
				level = ""
			}
			_ = s.store.SetMailboxSpam(ctx, store.Staff, box.ID, level, allow, block)
		}
		if len(mb.Filters) > 0 {
			var st sieve.Settings
			if json.Unmarshal(mb.Filters, &st) == nil && st.Validate() == nil {
				if raw, err := json.Marshal(st); err == nil {
					_ = s.store.SetMailboxSieve(ctx, box.ID, raw)
					note("auto-reply and filters of %s are stored; they start working when the user opens and saves them once", mb.Address)
				}
			}
		}
	}
	for _, a := range plan.Aliases {
		local, dom, _ := strings.Cut(a.Address, "@")
		d := doms[dom]
		if d == nil {
			continue
		}
		if _, err := s.store.CreateAlias(ctx, store.Staff, d.ID, local, a.Destinations, a.SendAs); err != nil {
			if !errors.Is(err, store.ErrConflict) {
				note("forwarder %s not created: %s", a.Address, mailErr(err))
			}
			continue
		}
		rep.Aliases++
	}
	if sieve.ValidSpamLevel(plan.SpamLevel, false) {
		_ = s.store.SetCustomerSpamLevel(ctx, c.ID, plan.SpamLevel)
	}
	if s.Mail != nil {
		var res mailhelper.ImportResult
		req := mailhelper.Request{Action: mailhelper.ActionImport, Customer: c.ID, Name: name, Format: format, By: by}
		if err := (&mailhelper.Client{Socket: mailhelper.Socket}).CallData(ctx, req, &res); err != nil {
			return rep, err
		}
		rep.Mail = &res
		s.syncSpam(ctx, c.ID, "")
	} else {
		note("the mail system is not installed: no mail written")
	}
	_ = os.Remove(file)
	return rep, nil
}

// readImport takes the request body (API) or the uploaded file (panel).
func (s *Server) readImport(w http.ResponseWriter, r *http.Request, c *store.Customer) (name, format string, err error) {
	// large archives: no read deadline of the server for this request
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(mailhelper.ExportTimeout))
	format = r.URL.Query().Get("format")
	body := io.Reader(r.Body)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			return "", "", err
		}
		body = nil
	parts:
		for {
			part, err := mr.NextPart()
			if err != nil {
				return "", "", errors.New("no archive in the form")
			}
			switch part.FormName() {
			case "format":
				b, _ := io.ReadAll(io.LimitReader(part, 20))
				format = string(b)
			case "archive":
				body = part
				break parts
			}
		}
	}
	if format != mailimport.FormatEmailZit && format != mailimport.FormatCPanel {
		return "", "", errors.New("format must be emailzit or cpanel")
	}
	name, err = s.saveUpload(c.ID, body)
	return name, format, err
}

func (s *Server) apiImport(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoadCustomer(w, r)
	if c == nil {
		return
	}
	if c.Status != store.CustomerActive {
		apiError(w, http.StatusConflict, "customer_inactive", "the customer is not active", "")
		return
	}
	name, format, err := s.readImport(w, r, c)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid", err.Error(), "")
		return
	}
	j, err := s.startImport(c, name, format, "api:"+apiToken(r).Name)
	if err != nil {
		_ = os.Remove(filepath.Join(s.importDir(c.ID), name+".tar.gz"))
		apiError(w, http.StatusConflict, "conflict", err.Error(), "")
		return
	}
	s.apiAudit(r, "customer.import.start", "customer:"+c.ID, "%s archive uploaded, import started (%s)", format, j.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.ID, "status": j.Status})
}

func (s *Server) handleCustomerImport(w http.ResponseWriter, r *http.Request) {
	c := s.loadCustomer(w, r)
	if c == nil {
		return
	}
	back := "/customers/" + c.ID + "#import"
	if c.Status != store.CustomerActive {
		s.redirectErr(w, r, back, "The customer is suspended or terminated; nothing can be added.")
		return
	}
	name, format, err := s.readImport(w, r, c)
	if err != nil {
		s.log.Warn("import upload", "customer", c.ID, "err", err)
		s.redirectErr(w, r, back, "The archive could not be taken (choose the kind and a .tar.gz file).")
		return
	}
	j, err := s.startImport(c, name, format, userFrom(r).Username)
	if err != nil {
		_ = os.Remove(filepath.Join(s.importDir(c.ID), name+".tar.gz"))
		s.redirectErr(w, r, back, "An export or import of this customer is already running.")
		return
	}
	s.audit(r, "customer.import.start", "customer:"+c.ID, "%s archive uploaded, import started (%s)", format, j.ID)
	s.redirect(w, r, back, "The import was started; the result appears here and in the audit log.")
}

// lastImport is the newest import job of a customer (for its page).
func (s *Server) lastImport(customerID string) *job {
	s.jobs.Lock()
	defer s.jobs.Unlock()
	var last *job
	for _, j := range s.jobs.m {
		if j.CustomerID == customerID && j.Kind == "import" && (last == nil || j.Started.After(last.Started)) {
			c := *j
			last = &c
		}
	}
	return last
}
