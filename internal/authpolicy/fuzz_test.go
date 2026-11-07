package authpolicy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func FuzzGuard(f *testing.F) {
	f.Add("report", `{"remote":"192.0.2.1","login":"ana@acme.test","success":false,"fail_type":"credentials"}`)
	f.Add("allow", `{"remote":"::1","login":""}`)
	f.Fuzz(func(t *testing.T, command, body string) {
		g := &Guard{Token: "t"}
		r := httptest.NewRequest(http.MethodPost, "/?command="+url.QueryEscape(command), strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer t")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
			t.Fatalf("status %d", w.Code)
		}
	})
}
