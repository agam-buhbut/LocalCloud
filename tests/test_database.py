"""Database layer tests.

Covers:
- Schema creation + migration idempotence
- disable_user atomically bumps session_version (#H1)
- get_user_status returns combined (sv, is_active) (#H6)
- delete_file returns total_bytes for the deleted row, None on miss (#5/#6)
- mark_upload_finalizing one-shot semantics (#H19)
- list_user_files pagination respects limit/offset
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


def _create_user(db: Database, username: str = "alice") -> str:
    return db.create_user(
        username=username,
        password_hash="$argon2id$dummy",
        quota_bytes=10 * 1024 * 1024,
    )


def test_create_and_lookup_user(db: Database):
    uid = _create_user(db)
    u = db.get_user_by_username("alice")
    assert u is not None
    assert u["user_id"] == uid
    assert u["is_active"] == 1
    assert u["session_version"] == 1


def test_disable_user_bumps_session_version(db: Database):
    uid = _create_user(db)
    before = db.get_user_status(uid)
    assert before == (1, True)

    assert db.disable_user("alice") is True

    after = db.get_user_status(uid)
    assert after is not None
    sv, active = after
    assert active is False
    assert sv == 2, "disable_user must atomically bump session_version"


def test_get_user_status_for_missing_user(db: Database):
    assert db.get_user_status("no-such-uid") is None


def test_delete_file_returns_bytes_on_first_call(db: Database):
    uid = _create_user(db)
    fid = "f" * 32
    with db.transaction():
        db.create_file(
            file_id=fid,
            owner_id=uid,
            filename="a.bin",
            visibility=0,
            total_chunks=1,
            total_bytes=4096,
            encrypted_metadata=b"meta",
            file_header=b"hdr",
        )
    with db.transaction():
        n = db.delete_file(fid)
    assert n == 4096


def test_delete_file_returns_none_on_second_call(db: Database):
    uid = _create_user(db)
    fid = "g" * 32
    with db.transaction():
        db.create_file(
            file_id=fid,
            owner_id=uid,
            filename="a.bin",
            visibility=0,
            total_chunks=1,
            total_bytes=4096,
            encrypted_metadata=b"meta",
            file_header=b"hdr",
        )
    with db.transaction():
        first = db.delete_file(fid)
        second = db.delete_file(fid)
    assert first == 4096
    assert second is None


def test_mark_upload_finalizing_is_one_shot(db: Database):
    uid = _create_user(db)
    db.create_staging_upload(
        upload_id="u1" * 16,
        owner_id=uid,
        filename="x.bin",
        expected_chunks=2,
        expiry_seconds=60,
    )
    with db.transaction():
        a = db.mark_upload_finalizing("u1" * 16)
    with db.transaction():
        b = db.mark_upload_finalizing("u1" * 16)
    assert a is True
    assert b is False, "second claim must fail — H19 race guard"


def test_cleanup_expired_skips_finalizing(db: Database):
    """The H19 race guard: a row mid-finalize must not be GC'd."""
    uid = _create_user(db)
    # Create a row, immediately expired (negative TTL).
    db.create_staging_upload(
        upload_id="z" * 32,
        owner_id=uid,
        filename="x.bin",
        expected_chunks=2,
        expiry_seconds=-60,  # already expired
    )
    # Claim finalizing.
    with db.transaction():
        assert db.mark_upload_finalizing("z" * 32) is True
    expired = db.cleanup_expired_staging()
    assert (
        "z" * 32 not in expired
    ), "finalizing rows must be preserved against the cleanup pass"


def test_list_user_files_pagination(db: Database):
    uid = _create_user(db)
    for i in range(5):
        with db.transaction():
            db.create_file(
                file_id=f"{i:032x}",
                owner_id=uid,
                filename=f"f{i}.bin",
                visibility=0,
                total_chunks=1,
                total_bytes=100 + i,
                encrypted_metadata=b"m",
                file_header=b"h",
            )
    all_rows = db.list_user_files(uid, limit=200, offset=0)
    assert len(all_rows) == 5
    page1 = db.list_user_files(uid, limit=2, offset=0)
    page2 = db.list_user_files(uid, limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    # Disjoint
    ids1 = {r["file_id"] for r in page1}
    ids2 = {r["file_id"] for r in page2}
    assert ids1.isdisjoint(ids2)


def test_list_user_files_rejects_bad_pagination(db: Database):
    uid = _create_user(db)
    with pytest.raises(ValueError):
        db.list_user_files(uid, limit=0)
    with pytest.raises(ValueError):
        db.list_user_files(uid, limit=1, offset=-1)
    with pytest.raises(ValueError):
        db.list_user_files(uid, limit=10_000)


def test_schema_version_set(db: Database):
    row = db.conn.execute("SELECT version FROM schema_version").fetchone()
    assert row["version"] == 5


def test_double_connect_is_idempotent(tmp_path: Path):
    path = str(tmp_path / "x.db")
    d1 = Database(path)
    d1.connect()
    # Re-open the same DB; schema_version table should remain consistent.
    d1.close()
    d2 = Database(path)
    d2.connect()
    row = d2.conn.execute("SELECT version FROM schema_version").fetchone()
    assert row["version"] == 5
    d2.close()


def test_owner_pubkey_default_empty(db: Database):
    uid = _create_user(db)
    fid = "e" * 32
    with db.transaction():
        db.create_file(
            file_id=fid,
            owner_id=uid,
            filename="x.bin",
            visibility=0,
            total_chunks=1,
            total_bytes=1,
            encrypted_metadata=b"m",
            file_header=b"h",
        )
    pk = db.get_owner_ed25519_pubkey(fid)
    assert pk == b"", "default ed25519_pubkey should surface as empty bytes, not None"
