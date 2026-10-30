package dmarc

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

const sampleXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>1793318400</begin><end>1793404799</end></date_range>
  </report_metadata>
  <policy_published><domain>shop.test</domain><adkim>s</adkim><aspf>s</aspf><p>none</p></policy_published>
  <record>
    <row><source_ip>192.0.2.10</source_ip><count>12</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>shop.test</header_from></identifiers>
  </record>
  <record>
    <row><source_ip>2001:db8::25</source_ip><count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>shop.test</header_from></identifiers>
  </record>
</feedback>`

func message(ct, name string, body []byte) string {
	return "From: noreply-dmarc-support@google.com\r\nTo: dmarc-reports@shop.test\r\nSubject: Report domain: shop.test\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nThis is an aggregate report.\r\n" +
		"--b1\r\nContent-Type: " + ct + "; name=\"" + name + "\"\r\nContent-Disposition: attachment; filename=\"" + name + "\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		wrap(base64.StdEncoding.EncodeToString(body)) + "\r\n--b1--\r\n"
}

func wrap(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}

func TestParseMessage(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(sampleXML))
	_ = zw.Close()
	var zb bytes.Buffer
	z := zip.NewWriter(&zb)
	w, _ := z.Create("google.com!shop.test!1793318400!1793404799.xml")
	_, _ = w.Write([]byte(sampleXML))
	_ = z.Close()
	for name, msg := range map[string]string{
		"gzip": message("application/gzip", "report.xml.gz", gz.Bytes()),
		"zip":  message("application/zip", "report.zip", zb.Bytes()),
		"xml":  message("text/xml", "report.xml", []byte(sampleXML)),
	} {
		reps, err := ParseMessage(strings.NewReader(msg))
		if err != nil || len(reps) != 1 {
			t.Fatalf("%s: %v %v", name, reps, err)
		}
		r := reps[0]
		if r.Org != "google.com" || r.ID != "1234567890" || r.Domain != "shop.test" || len(r.Records) != 2 {
			t.Fatalf("%s: %+v", name, r)
		}
		if !r.Records[0].Pass() || r.Records[1].Pass() || r.Records[0].Count != 12 || r.Records[1].SourceIP.String() != "2001:db8::25" {
			t.Fatalf("%s records: %+v", name, r.Records)
		}
	}
	if _, err := ParseMessage(strings.NewReader("Subject: hi\r\n\r\nplain text\r\n")); err != ErrNoReport {
		t.Fatalf("plain message: %v", err)
	}
}
