#!/bin/sh
# Core restore copy (NO LUKS, NO mount) — reverse of localcloud-backup-copy.sh.
# Restores a backup snapshot into a (fresh) data dir:
#
#   <SRC>/meta.db -> <DEST>/meta.db   (the snapshot is quiescent: plain copy ok)
#   <SRC>/blobs/  -> <DEST>/blobs/
#
# The caller (localcloud-restore.sh) is responsible for stopping the daemon
# first and for chowning DEST back to the service user afterwards.
#
# Usage:  localcloud-restore-copy.sh <SRC_BACKUP_DIR> <DEST_DATA_DIR>
set -eu

SRC="${1:?usage: localcloud-restore-copy.sh SRC DEST}"
DEST="${2:?usage: localcloud-restore-copy.sh SRC DEST}"

if [ ! -f "$SRC/meta.db" ]; then
    echo "restore: no meta.db under $SRC — not a backup snapshot" >&2
    exit 1
fi

mkdir -p "$DEST/blobs"
# The backup meta.db is a consistent, WAL-free snapshot, so a plain copy
# restores it faithfully (no -wal/-shm sidecars to worry about).
cp -a "$SRC/meta.db" "$DEST/meta.db"
cp -a "$SRC/blobs/." "$DEST/blobs/" 2>/dev/null || true

echo "restore-copy: meta.db + blobs/ restored to $DEST"
