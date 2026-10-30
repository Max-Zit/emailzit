// Command emailzit-sendmail is the sendmail of websites on a HostZit server
// with EmailZit (PHP's sendmail_path): it reads a message from standard
// input and hands it to the EmailZit server, which applies the customer's
// sending limits. It understands the sendmail options websites use.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/max-zit/emailzit/internal/submit"
)

// exit codes of sysexits.h, as sendmail
const (
	exUsage    = 64
	exNoPerm   = 77
	exTempFail = 75
)

func main() {
	req, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "emailzit-sendmail:", err)
		os.Exit(exUsage)
	}
	sock := submit.Socket
	if v := os.Getenv("EMAILZIT_SUBMIT_SOCKET"); v != "" {
		sock = v
	}
	r, err := submit.Send(sock, *req, os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "emailzit-sendmail: the mail server is not reachable:", err)
		os.Exit(exTempFail)
	}
	if r.Error != "" {
		fmt.Fprintln(os.Stderr, "emailzit-sendmail:", r.Error)
		if r.Temp {
			os.Exit(exTempFail)
		}
		os.Exit(exNoPerm)
	}
}

// parseArgs reads the sendmail command line. Options that only change how
// sendmail itself behaves are accepted and ignored; modes other than
// sending a message are refused.
func parseArgs(args []string) (*submit.Request, error) {
	req := &submit.Request{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			req.Rcpts = append(req.Rcpts, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			req.Rcpts = append(req.Rcpts, a)
			continue
		}
		// value of an option written as -fADDR or -f ADDR
		val := func() (string, error) {
			if len(a) > 2 {
				return a[2:], nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("option %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		switch a[1] {
		case 't':
			req.Extract = true
		case 'i':
			// a single dot does not end the message: always so here
		case 'f', 'r':
			v, err := val()
			if err != nil {
				return nil, err
			}
			req.Sender = strings.Trim(v, "<>")
		case 'F':
			v, err := val()
			if err != nil {
				return nil, err
			}
			req.Name = v
		case 'o':
			if a == "-o" { // -o option value
				i++
			}
		case 'B', 'N', 'R', 'V', 'X', 'C', 'h', 'L', 'O':
			if len(a) == 2 {
				i++ // takes a value
			}
		case 'b':
			if a != "-bm" {
				return nil, fmt.Errorf("mode %s is not supported (only sending a message)", a)
			}
		case 'U', 'v', 'm', 'n', 'G', 'e', 'x', 'A', 'd':
			// ignored
		default:
			return nil, fmt.Errorf("unknown option %s", a)
		}
	}
	if !req.Extract && len(req.Rcpts) == 0 {
		return nil, fmt.Errorf("no recipients (give them on the command line or use -t)")
	}
	return req, nil
}
