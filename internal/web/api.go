package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/emailzit/internal/store"
)

// The REST API for billing systems (the MaxZit portal) and HostZit, with
// the conventions agreed with HostZit: /api/v1, JSON with snake_case,
// Bearer tokens with scopes, errors {"error":{"code","message","field"}},
// cursor pages, Idempotency-Key on creates, ids as UUID or ext:<external_id>.

type apiCtxKey struct{}

func apiToken(r *http.Request) *store.APIToken {
	t, _ := r.Context().Value(apiCtxKey{}).(*store.APIToken)
	return t
}

// apiError writes an error answer.
func apiError(w http.ResponseWriter, status int, code, msg, field string) {
	e := map[string]string{"code": code, "message": msg}
	if field != "" {
		e["field"] = field
	}
	writeJSON(w, status, map[string]any{"error": e})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// apiRate limits each token to 600 calls a minute.
type apiRate struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (a *apiRate) allow(id string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hits == nil {
		a.hits = map[string][]time.Time{}
	}
	l := prune(a.hits[id], now.Add(-time.Minute))
	if len(l) >= 600 {
		a.hits[id] = l
		return false
	}
	a.hits[id] = append(l, now)
	return true
}

func (s *Server) apiHandler() http.Handler {
	mux := http.NewServeMux()
	need := func(scope string, h http.HandlerFunc) http.Handler {
		return s.apiAuth(scope, h)
	}
	mux.HandleFunc("GET /api/v1/zit/info", s.apiInfo)
	mux.Handle("GET /api/v1/packages", need(store.ScopeCustomersRead, s.apiPackages))
	mux.Handle("GET /api/v1/customers", need(store.ScopeCustomersRead, s.apiCustomers))
	mux.Handle("POST /api/v1/customers", need(store.ScopeCustomersWrite, s.apiCustomerCreate))
	mux.Handle("GET /api/v1/customers/{id}", need(store.ScopeCustomersRead, s.apiCustomer))
	mux.Handle("PATCH /api/v1/customers/{id}", need(store.ScopeCustomersWrite, s.apiCustomerUpdate))
	mux.Handle("POST /api/v1/customers/{id}/suspend", need(store.ScopeCustomersWrite, s.apiCustomerStatus(store.CustomerSuspended)))
	mux.Handle("POST /api/v1/customers/{id}/unsuspend", need(store.ScopeCustomersWrite, s.apiCustomerStatus(store.CustomerActive)))
	mux.Handle("POST /api/v1/customers/{id}/terminate", need(store.ScopeCustomersWrite, s.apiCustomerStatus(store.CustomerTerminated)))
	mux.Handle("PUT /api/v1/customers/{id}/package", need(store.ScopeCustomersWrite, s.apiCustomerPackage))
	mux.Handle("GET /api/v1/customers/{id}/usage", need(store.ScopeUsage, s.apiCustomerUsage))
	mux.Handle("PUT /api/v1/customers/{id}/web-uids", need(store.ScopeCustomersWrite, s.apiWebUIDs))
	mux.Handle("POST /api/v1/customers/{id}/export", need(store.ScopeCustomersWrite, s.apiExport))
	mux.Handle("POST /api/v1/customers/{id}/import", need(store.ScopeCustomersWrite, s.apiImport))
	mux.Handle("GET /api/v1/customers/{id}/exports", need(store.ScopeCustomersRead, s.apiExports))
	mux.Handle("GET /api/v1/customers/{id}/exports/{name}", need(store.ScopeCustomersWrite, s.apiExportDownload))
	mux.Handle("GET /api/v1/jobs/{id}", need(store.ScopeCustomersRead, s.apiJob))
	mux.Handle("GET /api/v1/server/status", need(store.ScopeCustomersRead, s.apiServerStatus))
	mux.Handle("POST /api/v1/customers/{id}/sso", need(store.ScopeSSO, s.apiCustomerSSO))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "unknown API path", "")
	})
	return mux
}

// apiAuth checks the token, its address list, scope and rate.
func (s *Server) apiAuth(scope string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		h := r.Header.Get("Authorization")
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || tok == "" {
			apiError(w, http.StatusUnauthorized, "unauthorized", "an API token is required", "")
			return
		}
		if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
			apiError(w, http.StatusTooManyRequests, "rate_limited", "too many failed attempts from this address", "")
			return
		}
		t, err := s.store.APITokenBySecret(r.Context(), strings.TrimSpace(tok), ip)
		if err != nil {
			s.guard.fail(r.Context(), ip, "", "API token")
			apiError(w, http.StatusUnauthorized, "unauthorized", "the API token is not valid", "")
			return
		}
		if !t.AllowsIP(ip) {
			apiError(w, http.StatusForbidden, "forbidden", "the token may not be used from this address", "")
			return
		}
		if !t.Has(scope) {
			apiError(w, http.StatusForbidden, "forbidden", "the token lacks the permission "+scope, "")
			return
		}
		if !s.apiRate.allow(t.ID, s.now()) {
			w.Header().Set("Retry-After", "60")
			apiError(w, http.StatusTooManyRequests, "rate_limited", "too many calls; try again in a minute", "")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), apiCtxKey{}, t)))
	})
}

func (s *Server) apiAudit(r *http.Request, action, target, format string, args ...any) {
	s.auditAs(r, "api:"+apiToken(r).Name, action, target, format, args...)
}

func (s *Server) apiInfo(w http.ResponseWriter, r *http.Request) {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	writeJSON(w, http.StatusOK, map[string]string{"product": "emailzit", "version": s.Version, "panel_url": scheme + "://" + r.Host + "/"})
}

// ---- JSON shapes

type apiPackage struct {
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	MaxDomains      int    `json:"max_domains"`
	MaxMailboxes    int    `json:"max_mailboxes"`
	MaxAliases      int    `json:"max_aliases"`
	StorageMB       int    `json:"storage_mb"`
	MailboxMB       int    `json:"mailbox_mb"`
	MaxMailboxMB    int    `json:"max_mailbox_mb"`
	SendPerHour     int    `json:"send_per_hour"`
	SendPerDay      int    `json:"send_per_day"`
	CustomerPerHour int    `json:"customer_per_hour"`
}

type apiCustomer struct {
	ID         string    `json:"id"`
	ExternalID string    `json:"external_id,omitempty"`
	Username   string    `json:"username,omitempty"`
	Name       string    `json:"name"`
	Email      string    `json:"email,omitempty"`
	Package    string    `json:"package"`
	Status     string    `json:"status"`
	Reason     string    `json:"status_reason,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	StatusAt   time.Time `json:"status_at"`
}

func (s *Server) toAPICustomer(ctx context.Context, c *store.Customer) apiCustomer {
	slug := ""
	if p, err := s.store.PackageByID(ctx, c.PackageID); err == nil {
		slug = p.Slug
	}
	return apiCustomer{ID: c.ID, ExternalID: c.ExternalID, Username: c.Username, Name: c.Name, Email: c.Email, Package: slug,
		Status: c.Status, Reason: c.StatusReason, CreatedAt: c.CreatedAt.UTC(), StatusAt: c.StatusAt.UTC()}
}

func (s *Server) apiPackages(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Packages(r.Context())
	if err != nil {
		s.apiInternal(w, r, err)
		return
	}
	out := []apiPackage{}
	for _, p := range list {
		out = append(out, apiPackage{p.Slug, p.Name, p.MaxDomains, p.MaxMailboxes, p.MaxAliases, p.StorageMB, p.MailboxMB, p.MaxMailboxMB, p.SendPerHour, p.SendPerDay, p.CustomerPerHour})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) apiInternal(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("api", "path", r.URL.Path, "err", err)
	apiError(w, http.StatusInternalServerError, "internal", "internal error", "")
}

// apiLoadCustomer finds the customer of {id} (UUID or ext:<external_id>).
func (s *Server) apiLoadCustomer(w http.ResponseWriter, r *http.Request) *store.Customer {
	id := r.PathValue("id")
	var c *store.Customer
	var err error
	if ext, ok := strings.CutPrefix(id, "ext:"); ok {
		c, err = s.store.CustomerByExternalID(r.Context(), ext)
	} else {
		c, err = s.store.CustomerByID(r.Context(), strings.ToLower(id))
	}
	if err != nil {
		apiError(w, http.StatusNotFound, "customer_not_found", "no such customer", "")
		return nil
	}
	return c
}

func (s *Server) apiCustomers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	list, err := s.store.Customers(r.Context(), store.CustomerFilter{Query: r.URL.Query().Get("q"), Status: r.URL.Query().Get("status"),
		Limit: limit, After: r.URL.Query().Get("cursor")})
	if err != nil {
		s.apiInternal(w, r, err)
		return
	}
	out := []apiCustomer{}
	for _, c := range list {
		out = append(out, s.toAPICustomer(r.Context(), c))
	}
	res := map[string]any{"items": out}
	if len(list) == limit {
		last := list[len(list)-1]
		res["next_cursor"] = strings.ToLower(last.Name) + "|" + last.ID
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) apiCustomer(w http.ResponseWriter, r *http.Request) {
	if c := s.apiLoadCustomer(w, r); c != nil {
		writeJSON(w, http.StatusOK, s.toAPICustomer(r.Context(), c))
	}
}

// decodeJSON reads a JSON body (unknown fields refused).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apiError(w, http.StatusBadRequest, "invalid", "the body is not valid JSON for this call: "+err.Error(), "")
		return false
	}
	return true
}

// storeAPIError maps store errors to API errors.
func storeAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrConflict):
		apiError(w, http.StatusConflict, "conflict", "already exists", "")
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, "not_found", "not found", "")
	case errors.Is(err, store.ErrLimit):
		apiError(w, http.StatusConflict, "limit_reached", err.Error(), "")
	default:
		apiError(w, http.StatusBadRequest, "invalid", err.Error(), "")
	}
}

// idempotent replays the stored answer of a repeated create call.
func (s *Server) idempotent(w http.ResponseWriter, r *http.Request) (key string, done bool) {
	key = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		return "", false
	}
	if st, body, ok := s.store.IdempotentAnswer(r.Context(), apiToken(r).ID, key); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Idempotent-Replayed", "true")
		w.WriteHeader(st)
		_, _ = w.Write([]byte(body)) // #nosec G705 -- our own stored JSON answer, sent as application/json with nosniff
		return key, true
	}
	return key, false
}

func (s *Server) apiCustomerCreate(w http.ResponseWriter, r *http.Request) {
	key, done := s.idempotent(w, r)
	if done {
		return
	}
	var in struct {
		ID         string `json:"id"`
		ExternalID string `json:"external_id"`
		Username   string `json:"username"`
		Name       string `json:"name"`
		Email      string `json:"email"`
		Package    string `json:"package"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	p, err := s.store.PackageBySlug(r.Context(), in.Package)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid", "unknown package", "package")
		return
	}
	c, err := s.store.CreateCustomer(r.Context(), store.NewCustomer{ID: in.ID, ExternalID: in.ExternalID, Name: in.Name, Email: in.Email, PackageID: p.ID})
	if err != nil {
		storeAPIError(w, err)
		return
	}
	if in.Username != "" {
		if err := s.store.SetCustomerUsername(r.Context(), c.ID, in.Username); err != nil {
			_ = s.store.SetCustomerStatus(r.Context(), c.ID, store.CustomerTerminated, "username refused")
			storeAPIError(w, err)
			return
		}
		c, _ = s.store.CustomerByID(r.Context(), c.ID)
	}
	if s.Mail != nil {
		if err := s.Mail.CustomerCreated(r.Context(), c); err != nil {
			s.log.Error("customer mail directory", "customer", c.ID, "err", err)
		}
	}
	s.apiAudit(r, "customer.create", "customer:"+c.ID, "%s (package %s) via API", c.Name, p.Slug)
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(s.toAPICustomer(r.Context(), c))
	if key != "" {
		s.store.SaveIdempotentAnswer(r.Context(), apiToken(r).ID, key, http.StatusCreated, buf.String())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) apiCustomerUpdate(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoadCustomer(w, r)
	if c == nil {
		return
	}
	var in struct {
		Name       *string `json:"name"`
		Email      *string `json:"email"`
		ExternalID *string `json:"external_id"`
		Username   *string `json:"username"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	name, email, ext := c.Name, c.Email, c.ExternalID
	if in.Name != nil {
		name = *in.Name
	}
	if in.Email != nil {
		email = *in.Email
	}
	if in.ExternalID != nil {
		ext = *in.ExternalID
	}
	if err := s.store.UpdateCustomer(r.Context(), c.ID, name, email, ext); err != nil {
		storeAPIError(w, err)
		return
	}
	if in.Username != nil {
		if err := s.store.SetCustomerUsername(r.Context(), c.ID, *in.Username); err != nil {
			storeAPIError(w, err)
			return
		}
	}
	s.apiAudit(r, "customer.update", "customer:"+c.ID, "updated via API")
	c, _ = s.store.CustomerByID(r.Context(), c.ID)
	writeJSON(w, http.StatusOK, s.toAPICustomer(r.Context(), c))
}

func (s *Server) apiCustomerStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := s.apiLoadCustomer(w, r)
		if c == nil {
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		if r.ContentLength != 0 && !decodeJSON(w, r, &in) {
			return
		}
		if err := s.store.SetCustomerStatus(r.Context(), c.ID, status, in.Reason); err != nil {
			storeAPIError(w, err)
			return
		}
		s.apiAudit(r, "customer.status", "customer:"+c.ID, "%s → %s via API (%s)", c.Status, status, in.Reason)
		c, _ = s.store.CustomerByID(r.Context(), c.ID)
		writeJSON(w, http.StatusOK, s.toAPICustomer(r.Context(), c))
	}
}

func (s *Server) apiCustomerPackage(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoadCustomer(w, r)
	if c == nil {
		return
	}
	var in struct {
		Package string `json:"package"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	p, err := s.store.PackageBySlug(r.Context(), in.Package)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid", "unknown package", "package")
		return
	}
	if err := s.store.SetCustomerPackage(r.Context(), c.ID, p.ID); err != nil {
		storeAPIError(w, err)
		return
	}
	s.apiAudit(r, "customer.package", "customer:"+c.ID, "package %s via API", p.Slug)
	c, _ = s.store.CustomerByID(r.Context(), c.ID)
	writeJSON(w, http.StatusOK, s.toAPICustomer(r.Context(), c))
}

func (s *Server) apiCustomerUsage(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoadCustomer(w, r)
	if c == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"customer_id": c.ID, "domains": c.Domains, "mailboxes": c.Mailboxes, "aliases": c.Aliases,
		"storage_quota_mb": c.QuotaMB, "storage_used_bytes": c.UsedBytes})
}

// apiCustomerSSO gives a one-time link into the customer panel (60 s) for
// the customer's first enabled panel login.
func (s *Server) apiCustomerSSO(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoadCustomer(w, r)
	if c == nil {
		return
	}
	if !c.Active() {
		apiError(w, http.StatusConflict, "customer_inactive", "the customer is suspended or terminated", "")
		return
	}
	logins, err := s.store.CustomerUsers(r.Context(), c.ID)
	if err != nil {
		s.apiInternal(w, r, err)
		return
	}
	var uid int64
	for _, u := range logins {
		if !u.Disabled {
			uid = u.ID
			break
		}
	}
	if uid == 0 {
		apiError(w, http.StatusConflict, "no_login", "the customer has no enabled panel login", "")
		return
	}
	tok, exp, err := s.store.CreateSSOTicket(r.Context(), uid)
	if err != nil {
		s.apiInternal(w, r, err)
		return
	}
	s.apiAudit(r, "customer.sso", "customer:"+c.ID, "one-time sign-in link created via API")
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	writeJSON(w, http.StatusOK, map[string]any{"url": scheme + "://" + r.Host + "/sso/" + tok, "expires_at": exp.UTC()})
}

// handleSSO signs a customer in with a one-time link from the API.
func (s *Server) handleSSO(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	uid, err := s.store.UseSSOTicket(r.Context(), r.PathValue("token"))
	if err != nil {
		s.guard.fail(r.Context(), ip, "", "sso link")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u, err := s.store.UserByID(r.Context(), uid)
	if err != nil || u.Disabled || !s.customerActive(r.Context(), u) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	x := &store.Session{UserID: u.ID, IP: ip, UserAgent: r.UserAgent()}
	if s.finishLogin(w, r, x, u, "one-time link from the billing system") {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}
