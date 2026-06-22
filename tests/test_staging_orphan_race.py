"""F5: orphan-staging scanner must not reclaim a live upload's dir.

upload_init now inserts the DB row BEFORE creating the staging directory, so
cleanup_orphan_staging_dirs (which removes canonical-id dirs that have no row)
can never race a live upload. These tests pin both halves of the invariant.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from server import storage
from server.database import Database


def _create_user(db: Database) -> str:
    return db.create_user(
        username="alice",
        password_hash="$argon2id$dummy",
        quota_bytes=10 * 1024 * 1024,
    )


@pytest.fixture()
def wired(tmp_path: Path) -> Iterator[Database]:
    (tmp_path / "blobs").mkdir()
    (tmp_path / "staging").mkdir()
    db = Database(str(tmp_path / "meta.db"))
    db.connect()
    storage.init_storage(db, str(tmp_path / "blobs"), str(tmp_path / "staging"))
    try:
        yield db
    finally:
        db.close()
        storage._db = None  # avoid leaking a closed handle to other tests


def test_orphan_scan_keeps_dir_with_row(wired: Database) -> None:
    fid = "ab" * 16
    uid = _create_user(wired)
    wired.create_staging_upload(
        upload_id=fid,
        owner_id=uid,
        filename="x.bin",
        expected_chunks=1,
        expiry_seconds=3600,
    )
    d = Path(storage._staging_dir) / fid
    d.mkdir()
    assert storage.cleanup_orphan_staging_dirs() == 0
    assert d.exists(), "a staging dir with a live DB row must NOT be reclaimed"


def test_orphan_scan_removes_dir_without_row(wired: Database) -> None:
    fid = "cd" * 16
    d = Path(storage._staging_dir) / fid
    d.mkdir()
    assert storage.cleanup_orphan_staging_dirs() == 1
    assert not d.exists()
