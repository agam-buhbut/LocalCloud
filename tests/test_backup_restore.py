"""Core backup/restore round-trip (Phase 6).

The LUKS mount/unmount wrappers can't run in CI, but the *risky* core — taking
a consistent snapshot of the live WAL metadata db and copying the immutable
blob tree — can. These tests run the actual shell scripts
(``deploy/backup/localcloud-{backup,restore}-copy.sh``) against temp dirs and
verify:

- a consistent snapshot is taken **while the daemon's connection is still open**
  and rows live in the ``-wal`` sidecar (a plain ``cp`` of meta.db would miss
  them; sqlite's backup API must not);
- blobs round-trip byte-for-byte, including nested dirs;
- the transient ``staging/`` dir is excluded from the backup;
- a restored data dir opens cleanly and yields the same rows.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from server.database import Database

_REPO = Path(__file__).resolve().parent.parent
_BACKUP_COPY = _REPO / "deploy" / "backup" / "localcloud-backup-copy.sh"
_RESTORE_COPY = _REPO / "deploy" / "backup" / "localcloud-restore-copy.sh"


def _sh(script: Path, src: Path, dest: Path) -> None:
    subprocess.run(
        ["sh", str(script), str(src), str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )


def _seed_live_data_dir(data_dir: Path) -> tuple[Database, set[str]]:
    """Create a realistic /srv/cloud: open WAL db + blobs + staging.

    Returns the STILL-OPEN db handle (so committed rows sit in -wal, emulating
    a running daemon) and the set of created usernames.
    """
    (data_dir / "blobs" / "ab").mkdir(parents=True)
    (data_dir / "staging").mkdir()
    (data_dir / "blobs" / "root.bin").write_bytes(b"ciphertext-root")
    (data_dir / "blobs" / "ab" / "chunk0.bin").write_bytes(b"\x01\x02\x03nested")
    # transient junk that must NOT be backed up
    (data_dir / "staging" / "inflight.bin").write_bytes(b"should-not-survive")

    db = Database(str(data_dir / "meta.db"))
    db.connect()
    users = {"alice", "bob"}
    for name in sorted(users):
        db.create_user(username=name, password_hash="$argon2id$x", quota_bytes=1 << 30)
    # Deliberately DO NOT close db / checkpoint — rows live in the -wal file.
    return db, users


def test_backup_restore_round_trip(tmp_path: Path) -> None:
    src = tmp_path / "srv-cloud"
    src.mkdir()
    db, users = _seed_live_data_dir(src)
    try:
        backup = tmp_path / "backup-media" / "localcloud"
        _sh(_BACKUP_COPY, src, backup)

        # Snapshot must contain the committed-but-uncheckpointed rows...
        snap = Database(str(backup / "meta.db"))
        snap.connect()
        try:
            got = {
                r["username"]
                for r in snap.conn.execute("SELECT username FROM users").fetchall()
            }
        finally:
            snap.close()
        assert got == users

        # ...and must NOT contain the transient staging dir.
        assert not (backup / "staging").exists()

        # blobs copied byte-for-byte, including the nested dir.
        assert (backup / "blobs" / "root.bin").read_bytes() == b"ciphertext-root"
        assert (
            backup / "blobs" / "ab" / "chunk0.bin"
        ).read_bytes() == b"\x01\x02\x03nested"
    finally:
        db.close()

    # Restore into a fresh data dir and confirm it opens with the same rows.
    restored = tmp_path / "restored-cloud"
    _sh(_RESTORE_COPY, backup, restored)
    rdb = Database(str(restored / "meta.db"))
    rdb.connect()
    try:
        got = {
            r["username"]
            for r in rdb.conn.execute("SELECT username FROM users").fetchall()
        }
    finally:
        rdb.close()
    assert got == users
    assert (
        restored / "blobs" / "ab" / "chunk0.bin"
    ).read_bytes() == b"\x01\x02\x03nested"


def test_backup_rejects_non_data_dir(tmp_path: Path) -> None:
    """A SRC without meta.db is refused (not a LocalCloud data dir)."""
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(subprocess.CalledProcessError):
        _sh(_BACKUP_COPY, empty, tmp_path / "out")
