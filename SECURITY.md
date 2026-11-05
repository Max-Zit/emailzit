# Security policy

## Supported versions

Security fixes are released for the newest version.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Open the [Security tab](https://github.com/Max-Zit/emailzit/security) of this repository.
2. Click **Report a vulnerability** and describe the problem, the affected version and how to reproduce it.

We confirm reports within a few working days, fix confirmed problems in a new release and credit the reporter in the release notes unless they prefer otherwise.

## How EmailZit is tested

**On every change** (GitHub Actions):

- go vet, the test suite, and the whole suite again with the Go **race detector**;
- **fuzzing** of every parser that reads untrusted input — DMARC aggregate reports (mail, zip, gzip, XML), the HTML of received messages shown in webmail, uploaded cPanel and EmailZit mail archives, mail from websites (emailzit-sendmail), Postfix policy requests and log lines, spam sender lists and network allow-lists;
- CodeQL, govulncheck, staticcheck, Dependabot, secret scanning with push protection and OpenSSF Scorecard.

**Before every release**, in a test lab:

- source code: gosec, Semgrep, Trivy and Gitleaks;
- the running server: an OWASP ZAP scan of the panels, an OpenVAS scan of all mail and web ports, and end-to-end tests with Outlook, Thunderbird and phones (Autodiscover, autoconfig, IMAP, SMTP), with HostZit and with mail from websites;
- the appliance image: Trivy over its operating-system packages, a Lynis hardening audit, testssl.sh on the panel (8444) and mail ports (25, 465, 587, 993, 995), and Nuclei.

Findings are fixed before the release or listed in its notes.
