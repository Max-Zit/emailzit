package web

import (
	"net/http"

	"github.com/max-zit/emailzit/internal/netacl"
	"github.com/max-zit/emailzit/internal/store"
)

type apiTokensData struct {
	List     []*store.APIToken
	Scopes   []string
	NewToken string
	NewName  string
}

func (s *Server) handleAPITokens(w http.ResponseWriter, r *http.Request) {
	s.showAPITokens(w, r, &apiTokensData{}, "")
}

func (s *Server) showAPITokens(w http.ResponseWriter, r *http.Request, d *apiTokensData, errMsg string) {
	var err error
	if d.List, err = s.store.APITokens(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Scopes = store.Scopes
	p := &Page{Title: "REST API", Nav: "settings", Data: d}
	status := http.StatusOK
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
		status = http.StatusBadRequest
	}
	s.render(w, r, status, "apitokens", p)
}

func (s *Server) handleAPITokenCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tok, t, err := s.store.CreateAPIToken(r.Context(), r.FormValue("name"), r.Form["scope"], netacl.Split(r.FormValue("ips")), formInt(r, "days"), userFrom(r).Username)
	if err != nil {
		s.showAPITokens(w, r, &apiTokensData{}, err.Error())
		return
	}
	s.audit(r, "api.token.create", "token:"+t.ID, "%s with %v", t.Name, t.Scopes)
	s.showAPITokens(w, r, &apiTokensData{NewToken: tok, NewName: t.Name}, "")
}

func (s *Server) handleAPITokenDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAPIToken(r.Context(), r.PathValue("id")); err != nil {
		s.redirectErr(w, r, "/settings/api", mailErr(err))
		return
	}
	s.audit(r, "api.token.delete", "token:"+r.PathValue("id"), "revoked")
	s.redirect(w, r, "/settings/api", "Token revoked.")
}
