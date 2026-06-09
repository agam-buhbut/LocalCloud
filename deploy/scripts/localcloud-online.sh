#!/bin/sh
# Open the WireGuard port: add it to the nftables wg_online set.
# Install to /usr/local/sbin/localcloud-online.sh (root:root 0755).
set -eu

TABLE="inet localcloud"
SET="wg_online"
WG_PORT="${LOCALCLOUD_WG_PORT:-51820}"

if ! nft list set $TABLE $SET >/dev/null 2>&1; then
    echo "localcloud-online: nftables table/set missing — load deploy/nftables/localcloud.nft first" >&2
    exit 1
fi

nft add element $TABLE $SET "{ $WG_PORT }"
echo "localcloud: ONLINE (udp/$WG_PORT open)"
