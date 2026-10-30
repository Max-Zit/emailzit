#!/bin/sh
# EmailZit package: set up the database, users, certificate and services
# (setup.sh without apt: the package manager brought the dependencies).
set -e
sh /usr/share/emailzit/setup.sh --from-package
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now emailzit-helper.path >/dev/null 2>&1 || true
    # the socket for mail from websites (0.7): systemd starts it only while
    # the server is stopped
    if ! systemctl is-active --quiet emailzit-submit.socket; then
        systemctl enable emailzit-submit.socket >/dev/null 2>&1 || true
        systemctl stop emailzit-server.service >/dev/null 2>&1 || true
        systemctl start emailzit-submit.socket >/dev/null 2>&1 || true
        systemctl start emailzit-server.service >/dev/null 2>&1 || true
    fi
    # an upgrade by hand (dpkg -i) runs the new version right away
    systemctl try-restart emailzit-mail-helper.service emailzit-server.service >/dev/null 2>&1 || true
fi
