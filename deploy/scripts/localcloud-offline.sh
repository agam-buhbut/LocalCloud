#!/bin/sh
# Close the WireGuard port: remove it from the nftables wg_online set.
#
# LIMITATION (by design): this blocks only NEW handshakes. The input chain
# accepts `ct state established,related`, so a peer that is ALREADY up and keeps
# its conntrack entry warm (WireGuard PersistentKeepalive / steady traffic)
# stays connected until that flow goes idle and conntrack expires it — removing
# the port does not tear down live state. This is intentional for scheduled
# uptime windows (existing sessions drain gracefully). To sever established
# peers immediately use the kill-switch, which stops the daemon and the tunnel
# (see localcloud-killswitch.sh and deploy/README.md "Scheduled uptime vs.
# kill-switch").
#
# Install to /usr/local/sbin/localcloud-offline.sh (root:root 0755).
set -eu

TABLE="inet localcloud"
SET="wg_online"
WG_PORT="${LOCALCLOUD_WG_PORT:-51820}"

# Idempotent: deleting a non-member errors, so ignore that case.
nft delete element $TABLE $SET "{ $WG_PORT }" 2>/dev/null || true
echo "localcloud: OFFLINE (udp/$WG_PORT closed to new handshakes)"
