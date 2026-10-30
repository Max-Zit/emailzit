#!/bin/sh
# EmailZit installer for Debian 13: downloads the newest (or a given)
# release, checks it against the SHA256SUMS of the release, installs the
# package with its dependencies (Postfix, Dovecot, Rspamd, PostgreSQL …) and
# sets everything up.
#
#   curl -fsSLO https://github.com/Max-Zit/emailzit/releases/latest/download/install.sh
#   sudo sh install.sh [--version 0.6.0] [--hostname mail.example.com]
#
# The running server verifies later updates with the EmailZit release key
# (signed manifest) before it installs them.
set -eu

VERSION=""
HOSTNAME_ARG=""
SOURCE="${EMAILZIT_SOURCE:-https://github.com/Max-Zit/emailzit/releases}"
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --hostname) HOSTNAME_ARG="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (sudo sh install.sh)" >&2; exit 1; }
. /etc/os-release
if [ "${ID:-}" != debian ] || [ "${VERSION_ID:-0}" -lt 13 ]; then
    echo "EmailZit needs Debian 13 or newer (found ${PRETTY_NAME:-unknown})." >&2
    exit 1
fi
case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) echo "unsupported processor $(uname -m)" >&2; exit 1 ;;
esac
command -v curl >/dev/null || { apt-get -q update && apt-get -yq install curl ca-certificates; }

if [ -z "$VERSION" ]; then
    VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$SOURCE/latest" | sed 's|.*/tag/v\{0,1\}||')
fi
case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "could not find the newest version (got '$VERSION'); use --version" >&2; exit 1 ;;
esac
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
DEB="emailzit-server_${VERSION}_${ARCH}.deb"
echo "Downloading EmailZit $VERSION ($ARCH) …"
curl -fsSL -o "$TMP/$DEB" "$SOURCE/download/v$VERSION/$DEB"
curl -fsSL -o "$TMP/SHA256SUMS" "$SOURCE/download/v$VERSION/SHA256SUMS"
(cd "$TMP" && grep " $DEB\$" SHA256SUMS | sha256sum -c -) || { echo "the download does not match SHA256SUMS" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
apt-get -q update
apt-get -yq install --no-install-recommends "$TMP/$DEB"
if [ -n "$HOSTNAME_ARG" ]; then
    sh /usr/share/emailzit/setup.sh --from-package --hostname "$HOSTNAME_ARG"
fi
echo
echo "EmailZit $VERSION is installed. Open https://$(hostname -f):8444 and finish the setup."
echo "The setup token is in /var/lib/emailzit/setup-token.txt."
