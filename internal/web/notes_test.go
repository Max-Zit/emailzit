package web

import (
	"fmt"
	"strings"
	"testing"
)

// The note of a domain is shown in the language of the user: the sentence
// is a text of the console, and what HostZit said follows it as data. A
// conflict names the records HostZit kept, out of the list it sends with
// the 409 — before, its message was glued to the sentence, so the whole
// note stayed English (HostZit's proposal of 2026-11-16).
func TestTheNoteOfAConflictNamesTheRecordsAndIsTranslated(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"a list of records", `{"error":{"code":"record_conflict","conflicts":[{"name":"@","type":"MX"},{"name":"@","type":"TXT"}]}}`, "@ MX, @ TXT"},
		{"a list of names", `{"error":{"code":"record_conflict","conflicts":["@ MX","www A"]}}`, "@ MX, www A"},
		{"the same record twice", `{"error":{"code":"record_conflict","conflicts":[{"name":"@","type":"MX"},{"name":"@","type":"MX"}]}}`, "@ MX"},
		{"no list, so the message", `{"error":{"code":"record_conflict","message":"the customer has own records"}}`, "the customer has own records"},
		{"not JSON at all", `<html>`, "<html>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := conflictNames([]byte(c.body), apiMessage([]byte(c.body))); got != c.want {
				t.Fatalf("conflictNames = %q, want %q", got, c.want)
			}
		})
	}

	t.Run("a long list is cut", func(t *testing.T) {
		var many []string
		for i := 0; i < 12; i++ {
			many = append(many, fmt.Sprintf(`{"name":"n%d","type":"A"}`, i))
		}
		got := conflictNames([]byte(`{"error":{"conflicts":[`+strings.Join(many, ",")+`]}}`), "")
		if strings.Count(got, ",") != 8 || !strings.HasSuffix(got, "…") {
			t.Fatalf("conflictNames = %q", got)
		}
	})

	t.Run("the sentence is translated, the names are not", func(t *testing.T) {
		sr := translate("sr", noteWith(conflictNote, "@ MX"))
		if !strings.HasSuffix(sr, "@ MX") || strings.Contains(sr, conflictNote) || strings.Contains(sr, noteData) {
			t.Fatalf("the note in Serbian is %q", sr)
		}
		if got := translate("sr", unreachableNote); got == unreachableNote {
			t.Fatalf("a note without data is not translated: %q", got)
		}
		if got := translate("en", noteWith(unreachableNote, "")); got != unreachableNote {
			t.Fatalf("a note with no data to show is %q", got)
		}
	})
}
