// Package sieve turns a mail user's auto-reply and filter settings into a
// Sieve script and installs it through ManageSieve on the server itself.
// The settings in the database are the source; the script is generated, so
// user text only ever appears inside escaped Sieve strings.
package sieve

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// AutoReply is the vacation message.
type AutoReply struct {
	On      bool   `json:"on"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	From    string `json:"from,omitempty"`  // YYYY-MM-DD, optional
	Until   string `json:"until,omitempty"` // YYYY-MM-DD, optional
	Days    int    `json:"days"`            // one reply per sender within this many days
}

// Rule is one filter: if Field contains Value, do Action.
type Rule struct {
	Field  string `json:"field"`  // from, to, subject
	Value  string `json:"value"`  // text to look for
	Action string `json:"action"` // move, read, delete
	Folder string `json:"folder,omitempty"`
}

// Settings are everything of one mailbox.
type Settings struct {
	AutoReply AutoReply `json:"auto_reply"`
	Rules     []Rule    `json:"rules"`
}

var dateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// Validate checks and normalizes the settings.
func (s *Settings) Validate() error {
	a := &s.AutoReply
	a.Subject = strings.TrimSpace(a.Subject)
	if len(a.Subject) > 200 || len(a.Body) > 10000 {
		return errors.New("the auto-reply is too long")
	}
	if a.On && strings.TrimSpace(a.Body) == "" {
		return errors.New("write the text of the auto-reply")
	}
	for _, d := range []string{a.From, a.Until} {
		if d != "" {
			if _, err := time.Parse("2006-01-02", d); err != nil || !dateRE.MatchString(d) {
				return errors.New("invalid date")
			}
		}
	}
	if a.Days < 1 || a.Days > 30 {
		a.Days = 1
	}
	if len(s.Rules) > 50 {
		return errors.New("at most 50 filters")
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		r.Value = strings.TrimSpace(r.Value)
		r.Folder = strings.TrimSpace(r.Folder)
		switch {
		case r.Field != "from" && r.Field != "to" && r.Field != "subject":
			return errors.New("unknown filter field")
		case r.Value == "" || len(r.Value) > 200:
			return errors.New("each filter needs a text to look for (up to 200 characters)")
		case r.Action != "move" && r.Action != "read" && r.Action != "delete":
			return errors.New("unknown filter action")
		case r.Action == "move" && (r.Folder == "" || len(r.Folder) > 100 || strings.ContainsAny(r.Folder, "\x00\r\n*%")):
			return errors.New("choose the folder of the filter")
		}
	}
	return nil
}

// quote makes a Sieve quoted string.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	return `"` + s + `"`
}

// Script renders the Sieve script ("" = nothing to do).
func (s *Settings) Script(address string) string {
	var b strings.Builder
	var body strings.Builder
	need := map[string]bool{}
	for _, r := range s.Rules {
		hdr := map[string]string{"from": `"from"`, "to": `["to","cc"]`, "subject": `"subject"`}[r.Field]
		fmt.Fprintf(&body, "if header :contains %s %s {\r\n", hdr, quote(r.Value))
		switch r.Action {
		case "move":
			need["fileinto"], need["mailbox"] = true, true
			fmt.Fprintf(&body, "  fileinto :create %s;\r\n  stop;\r\n", quote(r.Folder))
		case "read":
			need["imap4flags"] = true
			body.WriteString("  addflag \"\\\\Seen\";\r\n")
		case "delete":
			body.WriteString("  discard;\r\n  stop;\r\n")
		}
		body.WriteString("}\r\n")
	}
	a := s.AutoReply
	if a.On {
		need["vacation"] = true
		cond := ""
		if a.From != "" || a.Until != "" {
			need["date"], need["relational"] = true, true
			var parts []string
			if a.From != "" {
				parts = append(parts, fmt.Sprintf(`currentdate :value "ge" "date" %s`, quote(a.From)))
			}
			if a.Until != "" {
				parts = append(parts, fmt.Sprintf(`currentdate :value "le" "date" %s`, quote(a.Until)))
			}
			cond = "allof(" + strings.Join(parts, ", ") + ")"
		}
		subj := a.Subject
		v := fmt.Sprintf("vacation :days %d :addresses [%s] :subject %s %s;\r\n", a.Days, quote(address), quote(subj), quote(a.Body))
		if subj == "" {
			v = fmt.Sprintf("vacation :days %d :addresses [%s] %s;\r\n", a.Days, quote(address), quote(a.Body))
		}
		if cond != "" {
			fmt.Fprintf(&body, "if %s {\r\n  %s}\r\n", cond, v)
		} else {
			body.WriteString(v)
		}
	}
	if body.Len() == 0 {
		return ""
	}
	var req []string
	for _, k := range []string{"fileinto", "mailbox", "imap4flags", "vacation", "date", "relational"} {
		if need[k] {
			req = append(req, `"`+k+`"`)
		}
	}
	b.WriteString("# EmailZit: written from the settings of the mailbox; changes here are overwritten.\r\n")
	if len(req) > 0 {
		b.WriteString("require [" + strings.Join(req, ", ") + "];\r\n")
	}
	b.WriteString(body.String())
	return b.String()
}

// ScriptName is the name of EmailZit's script on the server.
const ScriptName = "emailzit"

// Install puts the script on the server through ManageSieve and makes it
// active ("" deactivates and removes it).
func Install(addr, user, password, script string) error {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(c)
	if err := expectOK(r); err != nil {
		return err
	}
	auth := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + password))
	if _, err := fmt.Fprintf(c, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", auth); err != nil {
		return err
	}
	if err := expectOK(r); err != nil {
		return fmt.Errorf("managesieve sign-in: %w", err)
	}
	if script == "" {
		fmt.Fprintf(c, "SETACTIVE \"\"\r\n")
		_ = expectOK(r)
		fmt.Fprintf(c, "DELETESCRIPT \"%s\"\r\n", ScriptName)
		_ = expectOK(r) // may not exist
		fmt.Fprintf(c, "LOGOUT\r\n")
		return nil
	}
	if _, err := fmt.Fprintf(c, "PUTSCRIPT \"%s\" {%d+}\r\n%s\r\n", ScriptName, len(script), script); err != nil {
		return err
	}
	if err := expectOK(r); err != nil {
		return fmt.Errorf("the filter was refused: %w", err)
	}
	fmt.Fprintf(c, "SETACTIVE \"%s\"\r\n", ScriptName)
	if err := expectOK(r); err != nil {
		return err
	}
	fmt.Fprintf(c, "LOGOUT\r\n")
	return nil
}

// expectOK reads lines up to OK / NO / BYE.
func expectOK(r *bufio.Reader) error {
	for i := 0; i < 200; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "OK"):
			return nil
		case strings.HasPrefix(up, "NO"), strings.HasPrefix(up, "BYE"):
			return errors.New(strings.TrimSpace(line))
		}
		// a literal {n} in an error: read it and keep going
		if m := regexp.MustCompile(`\{(\d+)\}$`).FindStringSubmatch(line); m != nil {
			var n int
			_, _ = fmt.Sscan(m[1], &n)
			buf := make([]byte, min(n, 1<<16))
			if _, err := io.ReadFull(r, buf); err != nil {
				return err
			}
		}
	}
	return errors.New("no answer from the sieve service")
}
