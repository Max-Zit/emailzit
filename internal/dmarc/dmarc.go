// Package dmarc reads DMARC aggregate reports (RFC 7489, appendix C): the
// XML files receivers such as Google and Microsoft mail every day to the
// address in a domain's rua= tag, usually zipped or gzipped and attached.
package dmarc

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/netip"
	"path"
	"strings"
	"time"
)

// Limits: a report bigger than this is not read.
const (
	MaxMessage = 25 << 20
	maxXML     = 20 << 20
	maxRecords = 20000
	maxParts   = 20
)

// Report is one aggregate report.
type Report struct {
	Org     string
	Email   string
	ID      string
	Begin   time.Time
	End     time.Time
	Domain  string // the policy's domain (policy_published)
	Policy  string
	Records []Record
}

// Record is a row: mail from one address with one result.
type Record struct {
	SourceIP    netip.Addr
	Count       int
	Disposition string // none, quarantine, reject
	DKIM        bool   // DMARC-aligned DKIM pass
	SPF         bool   // DMARC-aligned SPF pass
	HeaderFrom  string
}

// Pass is true when the mail passed DMARC.
func (r Record) Pass() bool { return r.DKIM || r.SPF }

// ErrNoReport means the message holds no aggregate report.
var ErrNoReport = errors.New("no DMARC aggregate report in the message")

// ParseMessage finds the reports in a mail message (attached or as the body).
func ParseMessage(r io.Reader) ([]*Report, error) {
	msg, err := mail.ReadMessage(io.LimitReader(r, MaxMessage))
	if err != nil {
		return nil, err
	}
	var out []*Report
	parts := 0
	var walk func(h textHeader, body io.Reader, depth int) error
	walk = func(h textHeader, body io.Reader, depth int) error {
		ct, params, _ := mime.ParseMediaType(h.Get("Content-Type"))
		if strings.HasPrefix(ct, "multipart/") {
			if depth > 3 || params["boundary"] == "" {
				return nil
			}
			mr := multipart.NewReader(body, params["boundary"])
			for {
				p, err := mr.NextPart()
				if err != nil {
					return nil // end or a broken part: what was found stays
				}
				if parts++; parts > maxParts {
					return nil
				}
				if err := walk(p.Header, p, depth+1); err != nil {
					return err
				}
			}
		}
		name := filename(h, params)
		kind := kindOf(ct, name)
		if kind == "" {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(decode(h.Get("Content-Transfer-Encoding"), body), MaxMessage))
		if err != nil {
			return nil
		}
		for _, x := range unpack(kind, data) {
			if rep, err := Parse(bytes.NewReader(x)); err == nil {
				out = append(out, rep)
			}
		}
		return nil
	}
	if err := walk(msg.Header, msg.Body, 0); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNoReport
	}
	return out, nil
}

type textHeader interface{ Get(string) string }

func filename(h textHeader, params map[string]string) string {
	if n := params["name"]; n != "" {
		return n
	}
	if _, p, err := mime.ParseMediaType(h.Get("Content-Disposition")); err == nil {
		return p["filename"]
	}
	return ""
}

// kindOf says how a part is packed: zip, gzip, xml or "" (not a report).
func kindOf(ct, name string) string {
	name = strings.ToLower(name)
	switch {
	case ct == "application/zip" || ct == "application/x-zip-compressed" || strings.HasSuffix(name, ".zip"):
		return "zip"
	case ct == "application/gzip" || ct == "application/x-gzip" || strings.HasSuffix(name, ".gz"):
		return "gzip"
	case ct == "text/xml" || ct == "application/xml" || strings.HasSuffix(name, ".xml"):
		return "xml"
	}
	return ""
}

func decode(enc string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, &skipSpace{r: r})
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}

// skipSpace drops the line breaks of base64 text.
type skipSpace struct{ r io.Reader }

func (s *skipSpace) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	j := 0
	for _, c := range p[:n] {
		if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			p[j] = c
			j++
		}
	}
	return j, err
}

// unpack returns the XML files of a part (a zip may hold several).
func unpack(kind string, data []byte) [][]byte {
	switch kind {
	case "xml":
		return [][]byte{data}
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil
		}
		x, err := io.ReadAll(io.LimitReader(zr, maxXML))
		if err != nil {
			return nil
		}
		return [][]byte{x}
	case "zip":
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil
		}
		var out [][]byte
		for i, f := range zr.File {
			if i >= maxParts || !strings.EqualFold(path.Ext(f.Name), ".xml") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			x, err := io.ReadAll(io.LimitReader(rc, maxXML))
			_ = rc.Close()
			if err == nil {
				out = append(out, x)
			}
		}
		return out
	}
	return nil
}

type xmlFeedback struct {
	XMLName  xml.Name `xml:"feedback"`
	Metadata struct {
		Org   string `xml:"org_name"`
		Email string `xml:"email"`
		ID    string `xml:"report_id"`
		Range struct {
			Begin int64 `xml:"begin"`
			End   int64 `xml:"end"`
		} `xml:"date_range"`
	} `xml:"report_metadata"`
	Policy struct {
		Domain string `xml:"domain"`
		P      string `xml:"p"`
	} `xml:"policy_published"`
	Records []struct {
		Row struct {
			SourceIP  string `xml:"source_ip"`
			Count     int    `xml:"count"`
			Evaluated struct {
				Disposition string `xml:"disposition"`
				DKIM        string `xml:"dkim"`
				SPF         string `xml:"spf"`
			} `xml:"policy_evaluated"`
		} `xml:"row"`
		Identifiers struct {
			HeaderFrom string `xml:"header_from"`
		} `xml:"identifiers"`
	} `xml:"record"`
}

// Parse reads the XML of one report.
func Parse(r io.Reader) (*Report, error) {
	var f xmlFeedback
	d := xml.NewDecoder(io.LimitReader(r, maxXML))
	d.Strict = false
	if err := d.Decode(&f); err != nil {
		return nil, err
	}
	rep := &Report{Org: clean(f.Metadata.Org, 200), Email: clean(f.Metadata.Email, 200), ID: clean(f.Metadata.ID, 200),
		Domain: strings.ToLower(clean(f.Policy.Domain, 253)), Policy: clean(f.Policy.P, 20)}
	if rep.ID == "" || rep.Domain == "" || f.Metadata.Range.Begin <= 0 || f.Metadata.Range.End < f.Metadata.Range.Begin {
		return nil, errors.New("not a DMARC aggregate report")
	}
	rep.Begin, rep.End = time.Unix(f.Metadata.Range.Begin, 0).UTC(), time.Unix(f.Metadata.Range.End, 0).UTC()
	for i, x := range f.Records {
		if i >= maxRecords {
			break
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(x.Row.SourceIP))
		if err != nil || x.Row.Count < 0 {
			continue
		}
		rep.Records = append(rep.Records, Record{SourceIP: ip.Unmap(), Count: x.Row.Count,
			Disposition: strings.ToLower(clean(x.Row.Evaluated.Disposition, 20)),
			DKIM:        strings.EqualFold(strings.TrimSpace(x.Row.Evaluated.DKIM), "pass"),
			SPF:         strings.EqualFold(strings.TrimSpace(x.Row.Evaluated.SPF), "pass"),
			HeaderFrom:  strings.ToLower(clean(x.Identifiers.HeaderFrom, 253))})
	}
	return rep, nil
}

// clean trims a text of a report and drops control characters.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > max {
		s = s[:max]
	}
	return strings.ToValidUTF8(s, "")
}
