#!/bin/sh
# EmailZit: set up the mail server on Debian 13 (idempotent; run as root).
# Installs Postfix, Dovecot and PostgreSQL from Debian, creates the
# database and its roles, a first certificate, the services, and starts
# them. The binary must already be at /usr/bin/emailzit-server.
#
#   sh setup.sh [--hostname mail.example.com]
set -eu

HOSTNAME_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --hostname) HOSTNAME_ARG="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
. /etc/os-release
if [ "${ID:-}" != debian ] || [ "${VERSION_ID:-0}" -lt 13 ]; then
    echo "EmailZit needs Debian 13 or newer (found ${PRETTY_NAME:-unknown})." >&2
    exit 1
fi
[ -x /usr/bin/emailzit-server ] || { echo "/usr/bin/emailzit-server is missing" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
apt-get -q update
apt-get -yq install --no-install-recommends postfix postfix-pgsql dovecot-core dovecot-imapd dovecot-pop3d \
    dovecot-lmtpd dovecot-pgsql dovecot-sieve dovecot-managesieved postgresql openssl ca-certificates rspamd nftables
# Rspamd keeps greylisting and rate data in Valkey (Redis on older systems)
apt-get -yq install --no-install-recommends valkey-server 2>/dev/null || apt-get -yq install --no-install-recommends redis-server

# ---- users and directories
if ! getent passwd emailzit >/dev/null; then
    useradd --system --home-dir /var/lib/emailzit --shell /usr/sbin/nologin emailzit
fi
install -d -m 0700 -o emailzit -g emailzit /var/lib/emailzit
install -d -m 0755 -o root -g root /etc/emailzit /var/vmail
install -d -m 0700 -o root -g root /var/vmail/.trash
# the certificate is public (the panel shows it); the key stays 0600
install -d -m 0755 -o root -g root /etc/emailzit/tls
[ -f /etc/emailzit/server.env ] || install -m 0640 -o root -g emailzit /usr/share/emailzit/server.env /etc/emailzit/server.env 2>/dev/null \
    || printf 'EMAILZIT_DB=postgres:///emailzit?host=/var/run/postgresql\n' > /etc/emailzit/server.env
chown root:emailzit /etc/emailzit/server.env
chmod 640 /etc/emailzit/server.env

# ---- database: owner emailzit; postfix, dovecot and root (the mail helper)
# only read what the panel grants them (peer authentication, no passwords)
systemctl enable --now postgresql >/dev/null
for r in emailzit postfix dovecot root; do
    su postgres -c "psql -qtAc \"SELECT 1 FROM pg_roles WHERE rolname='$r'\"" | grep -q 1 \
        || su postgres -c "psql -qc 'CREATE ROLE \"$r\" LOGIN'"
done
su postgres -c "psql -qtAc \"SELECT 1 FROM pg_database WHERE datname='emailzit'\"" | grep -q 1 \
    || su postgres -c "createdb -O emailzit -E UTF8 emailzit"
su postgres -c "psql -qc 'REVOKE ALL ON DATABASE emailzit FROM PUBLIC'"
for r in emailzit postfix dovecot root; do
    su postgres -c "psql -qc 'GRANT CONNECT ON DATABASE emailzit TO \"$r\"'"
done

# ---- first certificate (self-signed; replace with a real one or use the
# panel's certificate page)
H="${HOSTNAME_ARG:-$(hostname -f)}"
if [ ! -f /etc/emailzit/tls/mail.crt ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
        -subj "/CN=$H" -addext "subjectAltName=DNS:$H" \
        -keyout /etc/emailzit/tls/mail.key -out /etc/emailzit/tls/mail.crt 2>/dev/null
    chmod 600 /etc/emailzit/tls/mail.key
fi

# ---- services
install -m 0644 /usr/share/emailzit/emailzit-server.service /etc/systemd/system/ 2>/dev/null || true
install -m 0644 /usr/share/emailzit/emailzit-mail-helper.service /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload
# the panel creates the tables and grants the read-only roles
systemctl enable --now emailzit-server
for _ in $(seq 1 30); do
    su postgres -c "psql -qtAd emailzit -c \"SELECT 1 FROM information_schema.views WHERE table_name='mda_users'\"" 2>/dev/null | grep -q 1 && break
    sleep 1
done
systemctl restart emailzit-server
systemctl enable --now emailzit-mail-helper
systemctl enable postfix dovecot >/dev/null
echo "EmailZit is running. Open https://$H:8444 and finish the setup (token in /var/lib/emailzit/setup-token.txt)."
