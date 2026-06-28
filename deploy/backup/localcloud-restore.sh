#!/bin/sh
# Operator restore wrapper (README.txt PART II §7): stop the daemon, mount the
# offline LUKS2 backup HDD, restore ciphertext + metadata into the live data
# dir, re-lock the disk, fix ownership. UNTESTED (needs the real LUKS device).
# Run as root from the physical console.
#
#   localcloud-restore.sh
#
# Env overrides: LC_BACKUP_DEV, LC_DATA_DIR, LC_SERVICE_USER (default localcloud)
set -eu

BACKUP_DEV="${LC_BACKUP_DEV:-/dev/disk/by-label/lc-backup}"
DATA_DIR="${LC_DATA_DIR:-/srv/cloud}"
SVC_USER="${LC_SERVICE_USER:-localcloud}"
MAPPER="lc-backup"
MNT="/mnt/lc-backup"

# Resolve this script's own directory robustly so localcloud-restore-copy.sh is
# found next to us no matter how we were invoked. Bare `dirname "$0"` breaks when
# the script is run by bare name from PATH ($0 has no directory) or via a symlink
# ($0 points at the link). Locate on PATH if needed, then canonicalize.
SELF="$0"
case "$SELF" in
    */*) : ;;                            # $0 already contains a path component
    *) SELF="$(command -v "$SELF")" ;;   # bare name: resolve via PATH
esac
HERE="$(cd "$(dirname "$(readlink -f "$SELF")")" && pwd)"

cleanup() {
    umount "$MNT" 2>/dev/null || true
    cryptsetup close "$MAPPER" 2>/dev/null || true
    rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "restore: stopping the daemon..."
systemctl stop localcloud.service || true

echo "restore: unlocking $BACKUP_DEV (prompts for the disk passphrase)..."
cryptsetup open --type luks2 "$BACKUP_DEV" "$MAPPER"
mkdir -p "$MNT"
mount -o ro "/dev/mapper/$MAPPER" "$MNT"

echo "restore: copying $MNT/localcloud -> $DATA_DIR ..."
"$HERE/localcloud-restore-copy.sh" "$MNT/localcloud" "$DATA_DIR"

echo "restore: fixing ownership to $SVC_USER ..."
chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR"

echo "restore: done. Start the daemon with: systemctl start localcloud.service"
