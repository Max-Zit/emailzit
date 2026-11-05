package policy

import (
	"bufio"
	"strings"
	"testing"
)

func FuzzReadRequest(f *testing.F) {
	f.Add("request=smtpd_access_policy\nprotocol_state=RCPT\nsasl_username=ana@acme.test\n\n")
	f.Add("x\n=\n\n")
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = readRequest(bufio.NewReader(strings.NewReader(in)))
	})
}
