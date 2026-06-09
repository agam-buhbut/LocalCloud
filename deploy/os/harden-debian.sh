#!/bin/sh
# Minimal-Debian hardening for the LocalCloud box (README.txt PART II §1).
# UNTESTED on your hardware — READ IT before running. Run as root from the
# console on a freshly-installed minimal Debian (no desktop task selected).
#
# It does NOT touch disk encryption (see deploy/os/DISKS.md) or networking
# (see deploy/wireguard, deploy/nftables). It strips attack surface and
# disables sleep so the box is "fully awake when online, fully offline
# otherwise" (PART II §1).
set -eu

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi

echo "== removing peripheral stacks (bluetooth/audio/camera/mic, GUI) =="
apt-get purge -y --auto-remove \
    bluez bluetooth pulseaudio pipewire alsa-utils \
    cups cups-daemon avahi-daemon \
    'xserver-xorg*' 'gnome*' 'kde*' task-desktop 2>/dev/null || true
# Block the kernel modules outright so nothing re-probes them.
cat > /etc/modprobe.d/localcloud-blacklist.conf <<'EOF'
install bluetooth /bin/false
install btusb     /bin/false
install snd       /bin/false
install uvcvideo  /bin/false
install firewire-core /bin/false
install thunderbolt   /bin/false
EOF

echo "== disabling sleep / suspend / hibernate (stay awake when online) =="
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

echo "== disabling remote admin (physical-console-only, PART II §1) =="
systemctl disable --now ssh.service 2>/dev/null || true
apt-get purge -y --auto-remove openssh-server 2>/dev/null || true

echo "== kernel / network sysctl hardening =="
cat > /etc/sysctl.d/99-localcloud.conf <<'EOF'
# No routing — this is an endpoint, not a router.
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
# Ignore redirects / source routing.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
# Reverse-path filtering + SYN cookies.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
# Restrict kernel pointer / dmesg exposure.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
# No core dumps system-wide (the daemon also sets LimitCORE=0).
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
# Restrict ptrace to direct children.
kernel.yama.ptrace_scope = 2
EOF
sysctl --system

echo "== enabling AppArmor + nftables at boot =="
apt-get install -y apparmor apparmor-utils apparmor-profiles nftables wireguard-tools
systemctl enable apparmor nftables

echo "== done. Next: DISKS.md, app install, wireguard/, nftables/, systemd/, apparmor/ =="
echo "== verify: 'ss -tulpn' should show NO listeners except wg after reboot. =="
