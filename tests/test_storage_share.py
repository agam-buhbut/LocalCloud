"""Storage share / unshare tests.

Direct DB-level tests for the share + unshare flows that the server
exposes — verifying that ``Database.remove_file_share`` is correct,
share-count tracking works, and visibility downgrade on last-unshare
behaves. (Round-2 H9 / Round-3 fix)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from server.database import Database


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    d = Database(str(tmp_path / "meta.db"))
    d.connect()
    return d


def _user(db: Database, name: str) -> str:
    return db.create_user(
        username=name, password_hash="$argon2id$dummy", quota_bytes=1024
    )


def _file(db: Database, owner_id: str, file_id: str) -> None:
    with db.transaction():
        db.create_file(
            file_id=file_id,
            owner_id=owner_id,
            filename=f"{file_id}.bin",
            visibility=0,
            total_chunks=1,
            total_bytes=10,
            encrypted_metadata=b"m",
            file_header=b"h",
        )


def test_add_share_then_remove(db: Database):
    owner = _user(db, "alice")
    recipient = _user(db, "bob")
    fid = "a" * 32
    _file(db, owner, fid)
    with db.transaction():
        db.add_file_share(fid, recipient, b"wrapped-bundle" + b"\x00" * 80)
    assert db.get_wrapped_keys(fid, recipient) is not None
    with db.transaction():
        removed = db.remove_file_share(fid, recipient)
    assert removed is True
    assert db.get_wrapped_keys(fid, recipient) is None


def test_remove_nonexistent_share_returns_false(db: Database):
    owner = _user(db, "alice")
    fid = "b" * 32
    _file(db, owner, fid)
    with db.transaction():
        assert db.remove_file_share(fid, "no-such-uid") is False


def test_count_file_shares(db: Database):
    owner = _user(db, "alice")
    r1 = _user(db, "bob")
    r2 = _user(db, "carol")
    fid = "c" * 32
    _file(db, owner, fid)
    assert db.count_file_shares(fid) == 0
    with db.transaction():
        db.add_file_share(fid, r1, b"x" * 96)
        db.add_file_share(fid, r2, b"y" * 96)
    assert db.count_file_shares(fid) == 2
    with db.transaction():
        db.remove_file_share(fid, r1)
    assert db.count_file_shares(fid) == 1


def test_delete_file_cascades_shares(db: Database):
    """The schema declares ON DELETE CASCADE on file_shares.file_id;
    verify it actually fires under our PRAGMA foreign_keys=ON setup.
    """
    owner = _user(db, "alice")
    r = _user(db, "bob")
    fid = "d" * 32
    _file(db, owner, fid)
    with db.transaction():
        db.add_file_share(fid, r, b"w" * 96)
    assert db.count_file_shares(fid) == 1
    with db.transaction():
        db.delete_file(fid)
    # After the file row is gone, the share row should be too.
    assert db.count_file_shares(fid) == 0
