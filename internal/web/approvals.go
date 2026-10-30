package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/max-zit/emailzit/internal/store"
)

// Four-eyes approval: when it is on, a risky change by staff (terminating a
// customer, deleting a domain or mailbox, resetting a second factor, staff
// accounts, sign-in and network settings) is stored instead of done, and
// runs only when another administrator approves it. Customers changing
// their own mail are not affected.

const settingFourEyes = "four_eyes"

func (s *Server) fourEyesOn(ctx context.Context) bool {
	var on bool
	_ = s.store.GetSetting(ctx, settingFourEyes, &on)
	return on
}

type approvedKey struct{}

// formSkip are form fields not kept with a request.
var formSkip = map[string]bool{"csrf": true}

// summaryFields are shown in the list of requests (never passwords).
var summaryFields = []string{"status", "reason", "role", "username", "display_name", "disabled", "on"}

// fourEyes wraps a risky handler.
func (s *Server) fourEyes(action string, h http.HandlerFunc) http.HandlerFunc {
	if s.approvalHandlers == nil {
		s.approvalHandlers = map[string]http.HandlerFunc{}
	}
	s.approvalHandlers[action] = h
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r)
		if u == nil || !u.IsStaff() || r.Context().Value(approvedKey{}) != nil || !s.fourEyesOn(r.Context()) {
			h(w, r)
			return
		}
		_ = r.ParseForm()
		form := url.Values{}
		for k, v := range r.PostForm {
			if !formSkip[k] {
				form[k] = v
			}
		}
		pv := map[string]string{}
		for _, k := range []string{"id", "pid"} {
			if v := r.PathValue(k); v != "" {
				pv[k] = v
			}
		}
		var sum []string
		for _, k := range summaryFields {
			if v := form.Get(k); v != "" {
				sum = append(sum, k+"="+trimLen(v, 60))
			}
		}
		b, _ := json.Marshal(form)
		a := &store.Approval{Action: action, Path: r.URL.Path, PathValues: pv, Form: s.store.SealSecret("approval", string(b)),
			Summary: strings.Join(sum, ", "), RequestedBy: u.ID}
		if err := s.store.CreateApproval(r.Context(), a); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "approval.request", fmt.Sprintf("approval:%d", a.ID), "%s %s %s", action, r.URL.Path, a.Summary)
		s.redirect(w, r, "/approvals", "Waiting for another administrator to approve this change.")
	}
}

type approvalsData struct {
	List []*store.Approval
	On   bool
	Me   int64
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Approvals(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "approvals", &Page{Title: "Approvals", Nav: "approvals",
		Data: &approvalsData{List: list, On: s.fourEyesOn(r.Context()), Me: userFrom(r).ID}})
}

// handleApprovalDecide approves (and then runs) or rejects a request.
func (s *Server) handleApprovalDecide(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	approve := r.FormValue("decision") == "approve"
	if approve && !u.IsAdmin() {
		s.redirectErr(w, r, "/approvals", "Only an administrator can approve.")
		return
	}
	if !approve && !u.IsAdmin() {
		// others may only withdraw their own request
		if list, err := s.store.Approvals(r.Context()); err == nil {
			mine := false
			for _, a := range list {
				mine = mine || (a.ID == id && a.RequestedBy == u.ID)
			}
			if !mine {
				s.redirectErr(w, r, "/approvals", "Only an administrator can approve.")
				return
			}
		}
	}
	a, err := s.store.DecideApproval(r.Context(), id, u.ID, approve)
	switch {
	case errors.Is(err, store.ErrSelfApproval):
		s.redirectErr(w, r, "/approvals", "Another administrator must approve your own request.")
		return
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
		s.redirectErr(w, r, "/approvals", "The request is no longer waiting.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	target := fmt.Sprintf("approval:%d", a.ID)
	if !approve {
		s.audit(r, "approval.reject", target, "%s %s requested by %s", a.Action, a.Path, a.Requester)
		s.redirect(w, r, "/approvals", "Rejected.")
		return
	}
	h := s.approvalHandlers[a.Action]
	raw, err := s.store.OpenSecret("approval", a.Form)
	var form url.Values
	if h == nil || err != nil || json.Unmarshal([]byte(raw), &form) != nil {
		s.audit(r, "approval.failed", target, "%s %s could not be run", a.Action, a.Path)
		s.redirectErr(w, r, "/approvals", "The approved change could not be run.")
		return
	}
	s.audit(r, "approval.approve", target, "%s %s requested by %s, approved by %s", a.Action, a.Path, a.Requester, u.Username)
	// run the stored request as the approving administrator
	r2 := r.Clone(context.WithValue(r.Context(), approvedKey{}, a.ID))
	r2.URL.Path = a.Path
	r2.Form, r2.PostForm = form, form
	keys := make([]string, 0, len(a.PathValues))
	for k := range a.PathValues {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r2.SetPathValue(k, a.PathValues[k])
	}
	h(w, r2)
}

// handleFourEyes turns the approval rule on or off (off goes through an
// approval itself while it is on).
func (s *Server) handleFourEyes(w http.ResponseWriter, r *http.Request) {
	on := r.FormValue("on") == "1"
	if on {
		if n, err := s.store.ActiveAdmins(r.Context()); err != nil || n < 2 {
			s.redirectErr(w, r, "/settings/security", "Four-eyes approval needs at least two active administrators.")
			return
		}
	}
	if err := s.store.SetSetting(r.Context(), settingFourEyes, on); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.four-eyes", "settings", "four-eyes approval %v", on)
	s.redirect(w, r, "/settings/security", "Saved.")
}
