#!/bin/sh
# Core backup copy (NO LUKS, NO mount) — the testable heart of the backup flow.
# Copies ONLY server-side ciphertext + the metadata db from SRC to DEST:
#
#   <SRC>/meta.db   -> <DEST>/meta.db   (consistent online snapshot)
#   <SRC>/blobs/    -> <DEST>/blobs/    (immutable finalized ciphertext)
#
# It deliberately EXCLUDES <SRC>/staging/ (transient, possibly-inconsistent
# in-flight uploads) and never touches any client plaintext (there is none on
# the server). This script is exercised by tests/test_backup_restore.py.
#
# Usage:  localcloud-backup-copy.sh <SRC_DATA_DIR> <DEST_DIR>
set -eu

SRC="${1:?usage: localcloud-backup-copy.sh SRC DEST}"
DEST="${2:?usage: localcloud-backup-copy.sh SRC DEST}"

if [ ! -f "$SRC/meta.db" ]; then
    echo "backup: no meta.db under $SRC — not a LocalCloud data dir" >&2
    exit 1
fi

mkdir -p "$DEST"

# Consistent online snapshot of the live WAL database. A plain file copy of a
# WAL db can be torn (a checkpoint may be mid-flight); sqlite's backup API
# copies a transactionally-consistent image while the daemon keeps running.
python3 - "$SRC/meta.db" "$DEST/meta.db" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
s = sqlite3.connect(src)
try:
    d = sqlite3.connect(dst)
    try:
        s.backup(d)        # atomic, consistent snapshot
    finally:
        d.close()
finally:
    s.close()
PY

# Blobs are content-addressed and immutable once finalized, so a plain
# recursive copy is safe and consistent. On the real box, swap this line for
# `rsync -a --delete "$SRC/blobs/" "$DEST/blobs/"` for incremental backups.
mkdir -p "$DEST/blobs"
# Fail LOUD on a copy error: a swallowed partial copy would yield a
# meta.db-valid backup with MISSING ciphertext. set -e aborts on any cp
# failure; the [ -d ] guard handles a legitimately-absent blobs/ dir (the
# only reason the copy was previously made non-fatal).
if [ -d "$SRC/blobs" ]; then
    cp -a "$SRC/blobs/." "$DEST/blobs/"
fi

echo "backup-copy: meta.db + blobs/ copied to $DEST (staging/ excluded)"
