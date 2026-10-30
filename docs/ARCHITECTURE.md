# EmailZit — architecture proposal (draft, 2026-10-30)

Status: **proposal, waiting for Stefan's ok**. Nothing here is built yet.
Model: the mail part of cPanel/WHM — the same scope and ease of use, but
modern, more secure, with stronger isolation between customers and 14
languages. Shared decisions with HostZit live in `zit-hosting/INTEGRATION.md`
(local), the agreed parts are copied here once they are final.

## 1. Components

| Part | Runs as | What it does |
|---|---|---|
| `emailzit-server` | user `emailzit` (no root, hardened systemd unit like PassZit) | admin panel (WHM part), customer panel (cPanel part), mail-user self-service, REST API, autoconfig/autodiscover/MTA-STS policy pages, Rspamd settings maps over localhost HTTP |
| `emailzit-server --policyd` | user `emailzit-policy` | Postfix policy service (sender check, outgoing limits, abuse detection) and Dovecot auth policy (brute-force) on Unix sockets |
| `emailzit-server --helper` | root, started per request | the only privileged part: small allow-list of typed actions (below), every call in the audit log |
| PostgreSQL (Debian package) | postgres | database `emailzit`; Postfix and Dovecot read it through read-only views |
| Postfix | Debian package | SMTP in (25), submission (465 implicit TLS, 587 STARTTLS required), no open relay |
| Dovecot 2.4 | Debian package | IMAP (993), POP3 (995, can be switched off), LMTP, quotas, Sieve/ManageSieve |
| Rspamd + Valkey/Redis | Debian/Rspamd packages | spam, greylisting, DNSBLs, DKIM signing, ARC, DMARC checks, rate data; ClamAV optional |
| Webmail | PHP-FPM pool as its own user | Roundcube from Debian (proposed) or SnappyMail — see 6 |
| nginx | Debian package | front for webmail, autoconfig, MTA-STS, ACME HTTP-01; shared with HostZit when both are installed |

Target OS: **Debian 13** (amd64/arm64) for packages and appliance images
(Dovecot 2.4 config syntax only; Debian 12 not supported, to keep one
configuration).

One Go binary like the other products (server, policyd, helper modes). Code
is written in this repo; the well-tested building blocks from WatchZit /
PassZit (auth, store, sessions, audit, render/i18n, netacl, tlsutil, logfile,
testdb, update, relsign, helper pattern, packaging, appliance builder,
tools) are taken over and adapted — Stefan's own code, same license, no
shared runtime.

## 2. Data flow without root

Adding a domain, mailbox, alias or forwarder **only writes PostgreSQL**:

- Postfix `pgsql:` maps and Dovecot `sql` passdb/userdb read **views**
  (`mta_domains`, `mta_mailboxes`, `mta_aliases`, `mta_sender_logins`,
  `mda_users`) with separate read-only roles `emailzit_mta` / `emailzit_mda`
  (peer authentication on the local socket). The views already hide
  suspended customers, domains and mailboxes, so suspension is one UPDATE.
- Rspamd settings (per customer/domain/mailbox spam scores, greylisting,
  white/blacklists) are **maps fetched by Rspamd from emailzit-server over
  localhost HTTP**; no config file is written for a customer change.
- Sieve scripts (auto-reply, filters) are stored in the database and
  read by Dovecot's Sieve dict driver (verify with Dovecot 2.4) — no files written by
  the panel.

Customer input therefore never reaches a config file. The few generated
files (main.cf, dovecot.conf, rspamd local.d) are written only by the helper
from fixed templates with server-wide settings, validated before reload.

### Root helper allow-list (first version)
`customer.create|delete` (mail directory owned by the customer's UID),
`dkim.write|delete` (key file 0640 root:_rspamd), `tls.install` (certificate
per mail host name), `mta.apply` (server-wide settings → templates →
`postfix check` / `doveconf` / `rspamadm configtest` → reload, rollback on
error), `queue.action` (hold/release/delete by queue ID), `ban.add|remove`
(nftables set), `update`, `timezone`, `network`. Requests go over a root-only
Unix socket with peer-credential check (`SO_PEERCRED` = emailzit) instead of
PassZit's request.json + path unit, because mail needs many small calls;
arguments are typed and validated again in the helper (domain names, UUIDs,
queue IDs — never free text into a shell or file).

## 3. Isolation between customers

1. **Own system UID per customer for mail** (UID 2 000 000 + the customer's number; never the
   same UID as the customer's web account in HostZit, so a hacked website
   cannot read the customer's mail). Mail in `/var/vmail/<customer-uuid>/`,
   mode 0700; Dovecot runs IMAP/POP3/LMTP processes with that UID, so even a
   bug in one IMAP process cannot open another customer's files.
2. **Sending as someone else is impossible:** `smtpd_sender_login_maps` +
   `reject_sender_login_mismatch` — a login may send only from its own
   address and aliases explicitly allowed for it; policyd checks it again
   (also for the header From via Rspamd).
3. **The panel enforces ownership in one place:** every customer-panel and
   API query goes through a store layer that takes the customer ID from the
   session/token, never from the request; tests try every endpoint with
   another customer's IDs (isolation test suite, also on real VMs).
4. Domains are verified before mail for them is accepted when the server is
   shared (TXT token or HostZit owning the zone) — no "claiming" a domain
   another customer will use.
5. Secrets (DKIM private keys, app/API tokens, IMAP import passwords) are
   encrypted at rest with the server key (like PassZit `secret.key`); mailbox
   passwords are argon2id (Dovecot `ARGON2ID` scheme, verify in the lab).
6. **Dedicated mode:** install flag/setting for one customer — the same
   software, the customer panel becomes the main view, no cross-customer
   features shown.

## 4. Anti-abuse (a compromised mailbox must not ruin the server IP)

- **Outgoing limits** per mailbox, per customer and per server: messages
  and recipients per hour/day, recipients per message — from the package,
  overridable per customer/mailbox. Over the limit: `DEFER` (not lost),
  notification to the customer and admin.
- **Automatic detection:** sudden spike against the mailbox's normal volume,
  many unknown/bouncing recipients, sending from a new country/IP shortly
  after sign-in from elsewhere, many failed logins followed by success,
  outgoing spam score from Rspamd. Action (configurable): hold the mailbox's
  queue + block sending + force password change + notify; admin releases.
- **Brute-force:** Dovecot auth policy → policyd counts failures per IP and
  per account (IMAP, POP3, SMTP AUTH share it), slows down then bans in an
  nftables set via the helper; panel logins like the other products
  (rate limits, lockouts, `--unblock-ip`).
- **App passwords** for mail clients; customer can require them (then the
  main password works only in webmail/panel with 2FA). Leaked app password =
  revoke one device.
- Websites on the same server (HostZit) send through EmailZit with limits
  per hosting account (to agree, see INTEGRATION).
- Blacklist checks of the server IPs (and later WatchZit alerts).

## 5. Deliverability and DNS

DKIM per domain (2048-bit RSA by default, Ed25519 added as second
signature), rotation with two selectors (publish new → wait → switch →
remove old). SPF, DMARC (start `p=none` with reports to an EmailZit address,
then advise stricter), MTA-STS (policy served by EmailZit), TLS-RPT,
autoconfig/autodiscover + SRV records (RFC 6186/8314).
- **With HostZit:** records are written into HostZit's DNS automatically
  through its API (interface in INTEGRATION.md).
- **On its own:** "Email deliverability" page shows the records to set at
  the customer's DNS provider and checks them (DNS lookups with own
  resolver, status per record, like cPanel but with DKIM/MTA-STS/TLS-RPT).
- Certificates: own ACME client (golang.org/x/crypto/acme) for the server
  host name and per domain `mail.`, `autoconfig.`, `mta-sts.` (SNI in
  Postfix and Dovecot); HTTP-01, DNS-01 through HostZit when available.
- DMARC aggregate reports received and shown per domain (later).

## 6. Webmail (to decide)

- **Roundcube (GPLv3+) — proposed.** In Debian, so security updates come
  with `apt`; known to every cPanel user; plugins for ManageSieve and
  password change; we add a small plugin for sign-in from the panel (SSO
  link). Runs in its own PHP-FPM pool/user, database in the same PostgreSQL.
- SnappyMail (AGPL): lighter and faster, no database, but not in Debian —
  we would have to ship and update its release ourselves.
- Own webmail later (after the panels are mature), if wanted.

## 7. How it compares to cPanel/WHM mail

| cPanel / WHM | EmailZit |
|---|---|
| Email Accounts, quotas, Email Disk Usage | yes; quota per mailbox and per customer, usage graphs |
| Forwarders, Default Address (catch-all), Email Routing | yes; catch-all off by default (reject), local/remote/backup MX |
| Autoresponders, Email Filters, Global Email Filters | yes, Sieve (users and customer-wide), ManageSieve |
| Spam Filters (SpamAssassin), Greylisting | Rspamd (faster, better), per customer and per user, quarantine later |
| Email Deliverability, Manage DKIM | yes + DKIM rotation, MTA-STS, TLS-RPT, DMARC reports, auto DNS with HostZit |
| Track Delivery, Mail Delivery Reports, Mail Queue Manager | yes (delivery log per customer, queue for admin) |
| Max hourly emails per domain, View Relayers/Sent Summary | finer limits (mailbox/customer/server) + automatic abuse detection and hold |
| Configure Mail Client | autoconfig/autodiscover, Apple profile, QR for phones |
| Address Importer | CSV import of mailboxes/forwarders; IMAP migration from any server; cPanel account import |
| Webmail (Roundcube) | Roundcube with sign-in from the panel |
| Calendars and Contacts, Mailing Lists | later (to decide) |
| BoxTrapper, GPG Encryption | no (BoxTrapper causes backscatter) |
| Resellers | no (Stefan's decision) |
| — | 2FA everywhere, app passwords, per-customer UID, hash-chained audit, signed updates, 14 languages, REST API for billing, appliance images |

## 8. Version order (proposal)

- **0.1 Core mail:** server skeleton (auth, 2FA, roles, audit, sessions,
  i18n, theme); packages, customers, domains, mailboxes, aliases,
  forwarders, catch-all; PostgreSQL views; helper; installer that sets up
  Postfix + Dovecot on Debian 13; IMAP/SMTP with TLS; open-relay and
  spoofing tests; lab servers on ESXi + Mailpit.
- **0.2 Filtering and sending safely:** Rspamd (+ optional ClamAV), DKIM +
  deliverability page with DNS check, policyd (sender check, outgoing
  limits, brute-force bans).
- **0.3 Customer and user panels complete:** auto-reply, filters, spam
  settings, app passwords, webmail with panel sign-in,
  autoconfig/autodiscover.
- **0.4 Billing API:** tokens, create/suspend/unsuspend/terminate, change
  package, usage, SSO links; notifications.
- **0.5 Operations:** queue view, delivery log/tracking, abuse detection
  with hold, ACME certificates, MTA-STS/TLS-RPT, blacklist checks, DMARC
  reports.
- **0.6 Release tooling:** Debian packages, install.sh, signed self-update
  with channels, appliance ISO/OVA/qcow2/VHDX, console backup; IMAP
  migration and cPanel import.
- **0.7 Together:** HostZit one sign-in + automatic DNS + product switcher,
  BackupZit mailbox backup, WatchZit monitoring, LDAP/SSO for admins,
  four-eyes approval.
- Later: quarantine with release, shared mailboxes, mailing lists,
  CalDAV/CardDAV, own webmail.

## 9. Tests

Unit tests, go vet, staticcheck, govulncheck, gosec; CI (`ci.yml`,
`security.yml`) on `main` and `develop`. Real tests in the lab: two Debian 13
VMs on ESXi (`ez-mail1` 2 GB, `ez-mail2` 1–2 GB as a second mail server /
attacker), test zones `*.emailzit.test` with own DNS, Mailpit on bz-storage
as sink; never mail to the internet. Open-relay tests (own Go tool + swaks),
spoofing (MAIL FROM / header From / other customer's domain), isolation
suite (every panel/API endpoint with another customer's IDs, IMAP with
another UID), brute-force, limits; Thunderbird and Outlook on bz-win11;
Semgrep, Trivy, Gitleaks, OpenVAS and ZAP from CT 270.
