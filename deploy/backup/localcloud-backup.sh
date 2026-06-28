#!/bin/sh
# Operator backup wrapper (README.txt PART II §7): mount the offline LUKS2
# backup HDD, copy ciphertext + metadata, unmount, and re-lock the disk.
# UNTESTED (needs the real LUKS device). Run as root from the physical console.
#
#   localcloud-backup.sh
#
# Env overrides:
#   LC_BACKUP_DEV   LUKS2 partition (default /dev/disk/by-label/lc-backup)
#   LC_DATA_DIR     live data dir   (default /srv/cloud)
set -eu

BACKUP_DEV="${LC_BACKUP_DEV:-/dev/disk/by-label/lc-backup}"
DATA_DIR="${LC_DATA_DIR:-/srv/cloud}"
MAPPER="lc-backup"
MNT="/mnt/lc-backup"

# Resolve this script's own directory robustly so localcloud-backup-copy.sh is
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

echo "backup: unlocking $BACKUP_DEV (prompts for the disk passphrase)..."
cryptsetup open --type luks2 "$BACKUP_DEV" "$MAPPER"
mkdir -p "$MNT"
mount "/dev/mapper/$MAPPER" "$MNT"

DEST="$MNT/localcloud"
echo "backup: copying $DATA_DIR -> $DEST ..."
"$HERE/localcloud-backup-copy.sh" "$DATA_DIR" "$DEST"
sync

# cleanup() unmounts + re-locks the disk on exit (offline-by-default).
echo "backup: done; disk re-locked. Store it offline."
