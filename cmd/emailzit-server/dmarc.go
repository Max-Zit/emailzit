package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/max-zit/emailzit/internal/dmarc"
	"github.com/max-zit/emailzit/internal/store"
)

// exTempFail makes Postfix try the delivery again later (sysexits.h).
const exTempFail = 75

// runDMARCReport stores the DMARC aggregate reports of the message on
// standard input; Postfix's pipe service emailzit-dmarc starts it (as the
// user emailzit) for mail to dmarc-reports@<domain>. Messages without a
// report are dropped: bouncing them to report senders helps nobody.
func runDMARCReport(dbURL, recipient string) int {
	_, domain, ok := strings.Cut(recipient, "@")
	if !ok || domain == "" {
		fmt.Fprintln(os.Stderr, "dmarc-report: recipient missing")
		return 0
	}
	reps, err := dmarc.ParseMessage(bufio.NewReader(os.Stdin))
	if err != nil {
		fmt.Fprintln(os.Stderr, "dmarc-report:", err)
		return 0
	}
	if dbURL == "" {
		dbURL = envFileValue("/etc/emailzit/server.env", "EMAILZIT_DB")
	}
	if dbURL == "" {
		dbURL = "postgres:///emailzit?host=/var/run/postgresql"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dmarc-report:", err)
		return exTempFail
	}
	defer st.Close()
	for _, r := range reps {
		ok, err := st.SaveDMARCReport(ctx, domain, r)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dmarc-report:", err)
			return exTempFail
		}
		state := "stored"
		if !ok {
			state = "skipped (stored before or about another domain)"
		}
		fmt.Fprintf(os.Stderr, "dmarc-report: %s report %q of %s about %s: %d rows %s\n", domain, r.ID, r.Org, r.Domain, len(r.Records), state)
	}
	return 0
}

// envFileValue reads one variable of a systemd environment file.
func envFileValue(path, name string) string {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed path
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), name+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}
