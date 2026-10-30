#!/bin/sh
# Runs inside the newly installed system (preseed late_command). The mail
# stack is installed already; EmailZit itself is installed at the first
# start (emailzit-firstboot), because its setup starts services.
set -e
cd /root/emailzit-install
mkdir -p /var/lib/emailzit
touch /var/lib/emailzit/.appliance
install -m 0755 emailzit-firstboot /usr/local/sbin/emailzit-firstboot
install -m 0644 emailzit-firstboot.service /etc/systemd/system/emailzit-firstboot.service
install -m 0755 emailzit-appliance-boot /usr/local/sbin/emailzit-appliance-boot
install -m 0644 emailzit-appliance-boot.service /etc/systemd/system/emailzit-appliance-boot.service
install -m 0755 emailzit-setup /usr/local/sbin/emailzit-setup
install -m 0644 emailzit-menu.sh /etc/profile.d/emailzit-menu.sh
install -m 0440 sudoers-emailzit-setup /etc/sudoers.d/emailzit-setup
install -m 0644 sshd-emailzit.conf /etc/ssh/sshd_config.d/50-emailzit.conf
install -m 0644 sysctl-emailzit.conf /etc/sysctl.d/50-emailzit.conf
systemctl enable emailzit-firstboot.service emailzit-appliance-boot.service
# Postfix and Dovecot stay off until EmailZit has written their
# configuration at the first start.
systemctl disable postfix dovecot rspamd >/dev/null 2>&1 || true
# Automatic security updates of Debian.
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
# Where to get the source code of the GPL software, and the exact Debian
# packages of this installation.
mkdir -p /usr/share/doc/emailzit
install -m 0644 SOURCE-CODE.txt /usr/share/doc/emailzit/SOURCE-CODE.txt
dpkg-query -W -f '${Package} ${Version}\n' > /usr/share/doc/emailzit/debian-packages.txt
# The administrator chooses its own password at the first sign-in.
chage -d 0 ezadmin
usermod -aG sudo ezadmin
# systemd-networkd with DHCP on whatever adapter the machine has, and DNS
# from the lease (systemd-resolved): the same on a server and in every copy
# of a VM image. The panel (Updates and server) or the setup menu change it.
mkdir -p /etc/systemd/network
printf '# Written by EmailZit (network settings).\n[Match]\nName=en* eth*\n\n[Network]\nDHCP=ipv4\n' > /etc/systemd/network/50-emailzit.network
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
systemctl enable systemd-networkd systemd-networkd-wait-online systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
# No name announcements on the network (LLMNR, mDNS).
mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nLLMNR=no\nMulticastDNS=no\n' > /etc/systemd/resolved.conf.d/50-emailzit.conf
if [ -f IMAGE ]; then
    # A VM image is copied many times: no host identity baked in (SSH keys
    # and the machine ID are created at the first start).
    rm -f /etc/ssh/ssh_host_*
    truncate -s 0 /etc/machine-id
    rm -f /var/lib/dbus/machine-id
    apt-get clean
fi
