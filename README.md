<p align="center"><img src="brand/emailzit-logo-on-light.svg" alt="EmailZit" height="64"></p>

# EmailZit

**Free, open-source, self-hosted mail hosting** — mailboxes for many domains and customers with a modern admin panel, a panel for every customer and webmail; on its own or together with [HostZit](https://github.com/Max-Zit/hostzit).

> **Status:** in development. There is no release yet; follow the repository or [Discussions](https://github.com/Max-Zit/emailzit/discussions) for news.

## Planned

- **Two panels:** the server administrator manages packages, domains, limits and the server; every customer manages their own mailboxes, aliases, forwarders and spam settings; every mail user can change their own password, auto-reply and filters.
- **Proven mail software underneath:** Postfix, Dovecot (IMAP/POP3, quotas, Sieve filters) and Rspamd (spam and virus filtering), configured and kept up to date by EmailZit.
- **Deliverability done right:** DKIM, SPF, DMARC, MTA-STS and TLS reporting set up automatically, outgoing limits per account so one compromised mailbox cannot ruin the server's reputation, queue and delivery logs.
- **Easy setup for users:** autoconfig/autodiscover for Outlook, Thunderbird, iOS and Android; webmail; import from other IMAP servers.
- **Security:** isolation between customers, brute-force protection, two-factor sign-in for the panels, roles, hash-chained audit log, signed updates.
- **Works with the other MaxZit products:** [HostZit](https://github.com/Max-Zit/hostzit) with one sign-in, [BackupZit](https://github.com/Max-Zit/backupzit) for mailbox backups, [WatchZit](https://github.com/Max-Zit/watchzit) for monitoring; REST API for billing systems.
- **Self-hosted:** Debian package or appliance image, 14 languages.

EmailZit is made by [MaxZit](https://maxzit.com), like [BackupZit](https://github.com/Max-Zit/backupzit), [RMMZit](https://github.com/Max-Zit/rmmzit), [WatchZit](https://github.com/Max-Zit/watchzit) and [PassZit](https://github.com/Max-Zit/passzit).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE). Paid support will be offered by MaxZit.
