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
# Clear any stale WAL/SHM sidecars at the destination BEFORE writing the db.
# The backup meta.db is a self-contained, WAL-free snapshot, but a leftover
# meta.db-wal / meta.db-shm from a *previous* database at this path would be
# silently re-applied by SQLite the next time the daemon opens meta.db, mixing
# old WAL frames into the freshly restored db (corruption / wrong data). Removing
# them makes the restored db stand alone. `rm -f` is a no-op when absent.
rm -f "$DEST/meta.db-wal" "$DEST/meta.db-shm"
# The backup meta.db is a consistent, WAL-free snapshot, so a plain copy
# restores it faithfully.
cp -a "$SRC/meta.db" "$DEST/meta.db"
# Fail LOUD on a copy error (a swallowed partial restore would silently
# drop ciphertext). The [ -d ] guard tolerates a legitimately-empty backup.
if [ -d "$SRC/blobs" ]; then
    cp -a "$SRC/blobs/." "$DEST/blobs/"
fi

echo "restore-copy: meta.db + blobs/ restored to $DEST"
