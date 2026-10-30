package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The static text files go out gzip-compressed when the browser accepts it.
func TestStaticGzip(t *testing.T) {
	h := gzipStatic(os.DirFS("static"), http.FileServer(http.Dir("static")))
	r := httptest.NewRequest("GET", "/app.css", nil)
	r.Header.Set("Accept-Encoding", "gzip, deflate")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Content-Encoding") != "gzip" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("headers %v", w.Header())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil || !strings.Contains(string(raw), "--accent") {
		t.Fatalf("body: %v", err)
	}
	// without gzip the file server answers as before
	r = httptest.NewRequest("GET", "/app.css", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Content-Encoding") != "" || !strings.Contains(w.Body.String(), "--accent") {
		t.Fatal("plain request was compressed")
	}
}
