#!/bin/sh
# Operator kill-switch (README.txt PART II §2, §8): instantly take the box
# offline. In one command it (1) closes the firewall port, (2) severs active
# sessions by stopping the daemon and tearing down the tunnel, and (3)
# optionally rotates the session secret so any captured token is dead even if
# the service is later restarted.
#
# Install to /usr/local/sbin/localcloud-killswitch.sh (root:root 0750).
# Run from the physical console:  localcloud-killswitch.sh [--rotate-secret]
set -eu

SECRET_FILE="/etc/localcloud/session.secret"

echo "kill-switch: closing firewall port..."
/usr/local/sbin/localcloud-offline.sh || true

echo "kill-switch: stopping daemon and tunnel (severs live sessions)..."
systemctl stop localcloud.service || true
systemctl stop wg-quick@wg0.service || true

if [ "${1:-}" = "--rotate-secret" ]; then
    echo "kill-switch: rotating session secret (invalidates all tokens)..."
    umask 077
    python3 -c 'import os;print(os.urandom(48).hex())' > "$SECRET_FILE.new"
    chmod 600 "$SECRET_FILE.new"
    mv "$SECRET_FILE.new" "$SECRET_FILE"
fi

echo "kill-switch: DONE. Box is offline. Bring it back with:"
echo "  systemctl start wg-quick@wg0.service localcloud.service && localcloud-online.sh"
