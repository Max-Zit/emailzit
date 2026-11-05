package dmarc

import (
	"strings"
	"testing"
)

func FuzzParseMessage(f *testing.F) {
	f.Add(message("text/xml", "r.xml", []byte(sampleXML)))
	f.Add("Subject: x\r\n\r\nbody")
	f.Add("Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/zip\r\nContent-Transfer-Encoding: base64\r\n\r\nUEsDBA==\r\n--b--")
	f.Fuzz(func(t *testing.T, msg string) {
		reps, err := ParseMessage(strings.NewReader(msg))
		if err == nil && len(reps) == 0 {
			t.Fatal("no error and no report")
		}
		for _, r := range reps {
			if r.ID == "" || r.Domain == "" || r.End.Before(r.Begin) || len(r.Records) > maxRecords {
				t.Fatalf("invalid report accepted: %+v", r)
			}
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add(sampleXML)
	f.Add("<feedback></feedback>")
	f.Fuzz(func(t *testing.T, x string) {
		r, err := Parse(strings.NewReader(x))
		if err != nil {
			return
		}
		for _, s := range []string{r.Org, r.Email, r.ID, r.Domain, r.Policy} {
			if strings.ContainsAny(s, "\x00\r\n") {
				t.Fatalf("control character kept: %q", s)
			}
		}
	})
}
