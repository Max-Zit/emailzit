# Security policy

## Supported versions

Security fixes are released for the newest version.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Open the [Security tab](https://github.com/Max-Zit/emailzit/security) of this repository.
2. Click **Report a vulnerability** and describe the problem, the affected version and how to reproduce it.

We confirm reports within a few working days, fix confirmed problems in a new release and credit the reporter in the release notes unless they prefer otherwise.

## How EmailZit is tested

**On every change** (GitHub Actions, one workflow per push):

- go vet, the test suite, and the whole suite again with the Go **race detector**;
- a **role test** that sends every route of the panels to every role (administrator, operator, viewer, customer, mail user, anonymous) and checks that each role that may not use it is refused and every page a role may open loads; every REST API route is tried with tokens of every other scope;
- **fuzzing** of every parser that reads untrusted input — received messages (MIME, headers, attachments) and their HTML shown in webmail, DMARC aggregate reports (mail, zip, gzip, XML), the SPF/DMARC/DKIM records read back from the DNS, Autodiscover requests, folder names of an old IMAP server during an import, uploaded cPanel and EmailZit mail archives, mail from websites (emailzit-sendmail) and the envelope of the relay for the websites of a linked HostZit, Postfix policy and Dovecot authentication-policy requests, Postfix log lines, MTA-STS policies of other domains and Postfix's socketmap requests, redirect targets after sign-in, spam sender lists and network allow-lists;
- staticcheck, gosec, govulncheck and Gitleaks (the whole history), CodeQL, Dependabot, secret scanning with push protection and OpenSSF Scorecard; govulncheck and Gitleaks again weekly for new CVEs.

The main branch is protected: changes reach it only when the build, the tests, the race detector, the fuzzing and the security checks have passed.

**Before every release**, in a test lab:

- source code: gosec, Semgrep, Trivy and Gitleaks;
- the running server: an authenticated OWASP ZAP scan of the panels, testssl.sh on the panel (8444) and every mail port (25 and 587 with STARTTLS, 465, 993, 995, and 2587 when the relay for a linked HostZit is open), an OpenVAS scan of all ports when the network-facing parts change, and end-to-end tests with Outlook, Thunderbird and phones (Autodiscover, autoconfig, IMAP, SMTP), with HostZit and with mail from websites;
- the appliance image: Trivy over its operating-system packages, a Lynis hardening audit, testssl.sh and Nuclei.

Findings are fixed before the release or listed in its notes.
