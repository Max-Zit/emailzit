<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/emailzit-logo-on-dark.svg">
    <img src="brand/emailzit-logo-on-light.svg" alt="EmailZit" height="64">
  </picture>
</p>

# EmailZit

[![Latest release](https://img.shields.io/github/v/release/Max-Zit/emailzit?label=release)](https://github.com/Max-Zit/emailzit/releases/latest)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue)](LICENSE)
[![CI](https://github.com/Max-Zit/emailzit/actions/workflows/ci.yml/badge.svg)](https://github.com/Max-Zit/emailzit/actions/workflows/ci.yml)
[![Security scan](https://github.com/Max-Zit/emailzit/actions/workflows/security.yml/badge.svg)](https://github.com/Max-Zit/emailzit/actions/workflows/security.yml)

**Free, open-source, self-hosted mail hosting** — mailboxes for many domains and customers with a modern admin panel, a panel for every customer and webmail; on its own or together with [HostZit](https://github.com/Max-Zit/hostzit).

> **Status:** under active development; releases with VM images are on [Releases](https://github.com/Max-Zit/emailzit/releases). Tested in our lab with Outlook, Thunderbird, phones and HostZit; tell us how it works for you in [Discussions](https://github.com/Max-Zit/emailzit/discussions) or [Issues](https://github.com/Max-Zit/emailzit/issues).

## Features

- **Two panels and webmail:** the server administrator manages packages, customers, domains, limits and the server; every customer manages their own mailboxes, aliases, forwarders and spam settings; every mail user has webmail (with contacts and a signature), password and app passwords, auto-reply and filters.
- **Proven mail software underneath:** Postfix, Dovecot (IMAP/POP3, quotas, Sieve filters) and Rspamd (spam filtering, greylisting, optional ClamAV virus scan), configured and kept up to date by EmailZit.
- **Spam, virus and phishing protection:** spam levels and allowed/blocked senders per customer and per mailbox; postscreen and DNS block lists on port 25 (through a local Unbound resolver); risky attachments (programs, scripts, macro documents, also inside archives) refused; phishing warnings in the subject; optional ClamAV with Sanesecurity's signatures (GPG-checked); outgoing spam refused, and a mailbox that keeps sending it is blocked automatically.
- **Deliverability done right:** DKIM, SPF, DMARC (with the receivers' reports shown per domain), MTA-STS and TLS reporting set up automatically; a host name and PTR check for IPv4 and IPv6; a blacklist check of the server's addresses; sending over IPv4 only when IPv6 is not set up for mail; DANE and MTA-STS for outgoing mail; own outbound IP addresses per customer; outgoing limits per mailbox, customer and website, so one compromised account cannot ruin the server's reputation; a weekly report and block-list notices for the administrators; queue and delivery log; an optional smart host.
- **Easy setup for users:** Autodiscover and autoconfig for Outlook, Thunderbird, iOS and Android (also on ports 443/80 when no web server runs); mail programs use app passwords only, the web always asks for a second factor; quota warnings in the Inbox.
- **Moving in:** import from other IMAP servers, from cPanel account backups and from another EmailZit server; export per customer.
- **Server from the panel:** operating system updates, reboot and SSH port; upload of the server's certificate; encrypted backups of the panel, also to SFTP.
- **Security:** isolation between customers, brute-force protection, two-factor sign-in, company sign-in (OIDC) for staff, four-eyes approval for risky changes, hash-chained audit log, signed updates; TLS for mail programs offers post-quantum key exchange first and signs with SHA-2 only.
- **Works with the other MaxZit products:** [HostZit](https://github.com/Max-Zit/hostzit) writes the DNS records and sends the websites' mail through EmailZit; a status API (`GET /api/v1/server/status`) that [WatchZit](https://github.com/Max-Zit/watchzit) can watch with a JSON/HTTP check; REST API for billing systems.
- **Self-hosted:** Debian 13 package or appliance image (ISO, OVA, qcow2, VHDX), 14 languages, user guide in all 14 languages.

## Install

On a fresh **Debian 13** server with a public address (ports 25, 465, 587, 993, 995 and 8444 open):

```sh
curl -fsSLO https://github.com/Max-Zit/emailzit/releases/latest/download/install.sh
sudo sh install.sh --hostname mail.example.com
```

Or download the **appliance image** from the [newest release](https://github.com/Max-Zit/emailzit/releases/latest) (Proxmox: qcow2, VMware: OVA, Hyper-V: VHDX, or the installer ISO). The console of the appliance shows the panel's address and a setup token.

Open `https://<server>:8444`, create the first administrator and set the server's host name; the panel then shows every DNS record a domain needs. The host name must point at the server and the server's address back at the host name (PTR record at your provider).

After the installation only private networks may reach port 8444. On a server with a public address, sign in the first time through an SSH tunnel (`ssh -L 8444:127.0.0.1:8444 root@<server>`, then `https://127.0.0.1:8444`) and add `0.0.0.0/0` and `::/0` under **Network and access**: customers and mail users (webmail) need the port too. Staff accounts stay protected by the second factor and the blocking after failed sign-ins.

Requirements: 2 vCPU, 2 GB RAM (4 GB with the virus scan), 20 GB disk plus the mail itself.

The appliance image is checked before every release with Trivy, Lynis, testssl.sh and Nuclei; see [SECURITY.md](SECURITY.md).

EmailZit is made by [MaxZit](https://maxzit.com), like [BackupZit](https://github.com/Max-Zit/backupzit), [RMMZit](https://github.com/Max-Zit/rmmzit), [WatchZit](https://github.com/Max-Zit/watchzit) and [PassZit](https://github.com/Max-Zit/passzit).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE). Third-party components and their licenses: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Paid support is offered by MaxZit.
