#!/bin/sh
# Close the WireGuard port: remove it from the nftables wg_online set.
# Established sessions are left to drain; use the kill-switch to sever them.
# Install to /usr/local/sbin/localcloud-offline.sh (root:root 0755).
set -eu

TABLE="inet localcloud"
SET="wg_online"
WG_PORT="${LOCALCLOUD_WG_PORT:-51820}"

# Idempotent: deleting a non-member errors, so ignore that case.
nft delete element $TABLE $SET "{ $WG_PORT }" 2>/dev/null || true
echo "localcloud: OFFLINE (udp/$WG_PORT closed to new handshakes)"
