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

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from server.database import SCHEMA_VERSION, Database


def test_db_file_is_chmod_0600(tmp_path: Path) -> None:
    """L-1 (pentest): the DB (holding password hashes + metadata) is 0600."""
    import os
    import stat

    p = tmp_path / "meta.db"
    db = Database(str(p))
    db.connect()
    try:
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    finally:
        db.close()


# A users table shaped exactly as it was at schema v5 — i.e. WITHOUT the
# v6 x25519 columns — so a v6 migration applied over it exercises the real
# ALTER path (rather than a no-op against an already-current SCHEMA_SQL).
_V5_USERS_TABLE = """
CREATE TABLE schema_version (version INTEGER NOT NULL);
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL DEFAULT 1073741824,
    used_bytes INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    session_version INTEGER NOT NULL DEFAULT 1,
    ed25519_pubkey BLOB NOT NULL DEFAULT x'',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
"""


def _make_v5_db(path: str) -> None:
    """Create a raw sqlite file at schema v5 (no x25519 columns, one row)."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(_V5_USERS_TABLE)
        conn.execute("INSERT INTO schema_version (version) VALUES (5)")
        now = time.time()
        conn.execute(
            "INSERT INTO users (user_id, username, password_hash, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("legacy-uid", "legacy", "$argon2id$x", now, now),
        )
        conn.commit()
    finally:
        conn.close()


def _make_legacy_db(path: str, version: int) -> None:
    """Create a raw sqlite file shaped EXACTLY as it was at ``version``.

    Includes only the columns/tables that existed at that schema version, so
    the real ALTER-based migration path runs (rather than a no-op against an
    already-current SCHEMA_SQL). Seeds one user + one login_attempt so the
    upgrade can be asserted to preserve data. Used by the MIG-1 tests: before
    the table/index split these would crash in ``connect()`` with
    ``OperationalError: no such column`` because SCHEMA_SQL created an index
    over a column the old table did not yet have.
    """
    users_cols = [
        "user_id TEXT PRIMARY KEY",
        "username TEXT UNIQUE NOT NULL",
        "password_hash TEXT NOT NULL",
        "quota_bytes INTEGER NOT NULL DEFAULT 1073741824",
        "used_bytes INTEGER NOT NULL DEFAULT 0",
        "is_active INTEGER NOT NULL DEFAULT 1",
    ]
    if version >= 3:
        users_cols.append("session_version INTEGER NOT NULL DEFAULT 1")
    if version >= 4:
        users_cols.append("ed25519_pubkey BLOB NOT NULL DEFAULT x''")
    # x25519 columns only exist at v6, which we never *build* here.
    users_cols += ["created_at REAL NOT NULL", "updated_at REAL NOT NULL"]

    la_cols = ["username TEXT NOT NULL"]
    if version >= 2:
        la_cols.append("ip_address TEXT NOT NULL DEFAULT ''")
    la_cols.append("attempt_time REAL NOT NULL")

    su_cols = [
        "upload_id TEXT PRIMARY KEY",
        "owner_id TEXT NOT NULL",
        "filename TEXT NOT NULL",
        "expected_chunks INTEGER",
    ]
    if version >= 4:
        su_cols.append("finalizing INTEGER NOT NULL DEFAULT 0")
    su_cols += ["created_at REAL NOT NULL", "expires_at REAL NOT NULL"]

    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        conn.execute(f"CREATE TABLE users ({', '.join(users_cols)})")
        conn.execute(f"CREATE TABLE login_attempts ({', '.join(la_cols)})")
        conn.execute(f"CREATE TABLE staging_uploads ({', '.join(su_cols)})")
        # Tables whose shape is stable across these versions.
        conn.execute(
            "CREATE TABLE files ("
            "file_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, "
            "filename TEXT NOT NULL, visibility INTEGER NOT NULL DEFAULT 0, "
            "total_chunks INTEGER NOT NULL, total_bytes INTEGER NOT NULL, "
            "encrypted_metadata BLOB NOT NULL, file_header BLOB NOT NULL, "
            "created_at REAL NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE file_shares ("
            "file_id TEXT NOT NULL, shared_with_id TEXT NOT NULL, "
            "wrapped_keys BLOB NOT NULL, created_at REAL NOT NULL, "
            "PRIMARY KEY (file_id, shared_with_id))"
        )
        conn.execute(
            "CREATE TABLE staging_chunks ("
            "upload_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, "
            "chunk_hash TEXT NOT NULL, chunk_size INTEGER NOT NULL, "
            "created_at REAL NOT NULL, PRIMARY KEY (upload_id, chunk_index))"
        )
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        now = time.time()
        conn.execute(
            "INSERT INTO users (user_id, username, password_hash, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("legacy-uid", "legacy", "$argon2id$x", now, now),
        )
        if version >= 2:
            conn.execute(
                "INSERT INTO login_attempts (username, ip_address, attempt_time) "
                "VALUES (?, ?, ?)",
                ("legacy", "10.0.0.9", now),
            )
        else:
            conn.execute(
                "INSERT INTO login_attempts (username, attempt_time) VALUES (?, ?)",
                ("legacy", now),
            )
        conn.commit()
    finally:
        conn.close()


# The `db` fixture now lives in tests/conftest.py (canonical, shared).


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
    assert row["version"] == 6


def test_double_connect_is_idempotent(tmp_path: Path):
    path = str(tmp_path / "x.db")
    d1 = Database(path)
    d1.connect()
    # Re-open the same DB; schema_version table should remain consistent.
    d1.close()
    d2 = Database(path)
    d2.connect()
    row = d2.conn.execute("SELECT version FROM schema_version").fetchone()
    assert row["version"] == 6
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


# ──────────────────────────── Schema v6 (2C) ────────────────────────────


def test_fresh_db_reports_version_6(db: Database):
    row = db.conn.execute("SELECT version FROM schema_version").fetchone()
    assert row["version"] == 6
    assert SCHEMA_VERSION == 6


def test_fresh_db_has_x25519_columns(db: Database):
    cols = {r["name"] for r in db.conn.execute("PRAGMA table_info(users)").fetchall()}
    assert "x25519_pubkey" in cols
    assert "x25519_self_sig" in cols


def test_v5_to_v6_migration_adds_columns(tmp_path: Path):
    path = str(tmp_path / "v5.db")
    _make_v5_db(path)

    d = Database(path)
    d.connect()
    try:
        row = d.conn.execute("SELECT version FROM schema_version").fetchone()
        assert row["version"] == 6
        cols = {
            r["name"] for r in d.conn.execute("PRAGMA table_info(users)").fetchall()
        }
        assert "x25519_pubkey" in cols
        assert "x25519_self_sig" in cols
        # Pre-existing v5 row survives and is "not enrolled" (empty cols).
        assert d.get_user_x25519("legacy") is None
        legacy = d.get_user_by_username("legacy")
        assert legacy is not None
        assert legacy["x25519_pubkey"] == b""
        assert legacy["x25519_self_sig"] == b""
    finally:
        d.close()


def test_v5_to_v6_migration_is_idempotent(tmp_path: Path):
    """Running connect() twice over the same file must not fail on the
    duplicate ALTER (the per-statement duplicate-column catch in the runner).

    Note: MIGRATION_V5_TO_V6 is now a *list* of single ALTER statements
    (MIG-2), so this re-runs each statement individually rather than via
    executescript over a multi-statement string.
    """
    path = str(tmp_path / "v5.db")
    _make_v5_db(path)

    d1 = Database(path)
    d1.connect()
    d1.close()

    # Second open sees version == SCHEMA_VERSION and takes the no-op path;
    # force the migration to run twice as a direct check too.
    d2 = Database(path)
    d2.connect()
    try:
        # Re-running each migration ALTER directly must be tolerated — the
        # only swallowed error is "duplicate column name".
        from server.database import MIGRATION_V5_TO_V6

        for stmt in MIGRATION_V5_TO_V6:
            try:
                d2.conn.execute(stmt)
            except sqlite3.OperationalError as exc:
                assert "duplicate column name" in str(exc).lower()
        row = d2.conn.execute("SELECT version FROM schema_version").fetchone()
        assert row["version"] == 6
    finally:
        d2.close()


def test_db_at_version_6_does_not_fail_closed_guard(tmp_path: Path):
    """A DB already at the current version opens cleanly (no mismatch)."""
    path = str(tmp_path / "v6.db")
    d1 = Database(path)
    d1.connect()
    d1.close()
    d2 = Database(path)
    d2.connect()  # must not raise
    try:
        row = d2.conn.execute("SELECT version FROM schema_version").fetchone()
        assert row["version"] == 6
    finally:
        d2.close()


def test_db_above_version_6_fails_closed(tmp_path: Path):
    """A DB stamped above the known version fails the <6 / mismatch guard."""
    path = str(tmp_path / "future.db")
    d1 = Database(path)
    d1.connect()
    d1.conn.execute("UPDATE schema_version SET version = 7")
    d1.close()

    d2 = Database(path)
    with pytest.raises(RuntimeError, match="Schema version mismatch"):
        d2.connect()


def test_set_and_get_user_x25519_round_trips(db: Database):
    _create_user(db)
    pubkey = bytes(range(32))
    sig = bytes(range(64))
    assert db.set_user_x25519("alice", pubkey, sig) is True

    got = db.get_user_x25519("alice")
    assert got is not None
    out_pub, out_sig = got
    assert out_pub == pubkey
    assert isinstance(out_pub, bytes)
    assert out_sig == sig
    assert isinstance(out_sig, bytes)


def test_set_user_x25519_unknown_user_returns_false(db: Database):
    assert db.set_user_x25519("ghost", bytes(32), bytes(64)) is False


def test_get_user_x25519_unenrolled_returns_none(db: Database):
    _create_user(db)
    assert db.get_user_x25519("alice") is None


def test_get_user_x25519_unknown_returns_none(db: Database):
    assert db.get_user_x25519("nobody") is None


def test_list_enrolled_users_only_returns_enrolled(db: Database):
    _create_user(db, "alice")
    _create_user(db, "bob")
    _create_user(db, "carol")
    db.set_user_x25519("alice", bytes(range(32)), bytes(range(64)))
    db.set_user_x25519("carol", bytes(range(32, 64)), bytes(range(64, 128)))

    enrolled = db.list_enrolled_users()
    names = [e["username"] for e in enrolled]
    assert names == ["alice", "carol"], "bob is not enrolled; order is by username"
    alice = enrolled[0]
    assert alice["x25519_pubkey"] == bytes(range(32))
    assert alice["x25519_self_sig"] == bytes(range(64))
    assert isinstance(alice["ed25519_pubkey"], bytes)


def test_list_enrolled_users_empty_when_none_enrolled(db: Database):
    _create_user(db, "alice")
    assert db.list_enrolled_users() == []


# ──────────────────────── MIG-1: legacy (<v4) upgrade ────────────────────────


@pytest.mark.parametrize("start_version", [1, 2, 3])
def test_legacy_db_migrates_to_v6(tmp_path: Path, start_version: int) -> None:
    """A v1/v2/v3-shaped DB upgrades cleanly to v6 (MIG-1).

    Before the table/index split, ``connect()`` raised
    ``OperationalError: no such column`` because SCHEMA_SQL created an index
    over login_attempts.ip_address / staging_uploads.finalizing BEFORE the
    migrations added those columns.
    """
    path = str(tmp_path / f"v{start_version}.db")
    _make_legacy_db(path, start_version)

    d = Database(path)
    d.connect()  # must NOT raise OperationalError
    try:
        row = d.conn.execute("SELECT version FROM schema_version").fetchone()
        assert row["version"] == 6

        ucols = {
            r["name"] for r in d.conn.execute("PRAGMA table_info(users)").fetchall()
        }
        assert {
            "session_version",
            "ed25519_pubkey",
            "x25519_pubkey",
            "x25519_self_sig",
        } <= ucols
        lacols = {
            r["name"]
            for r in d.conn.execute("PRAGMA table_info(login_attempts)").fetchall()
        }
        assert "ip_address" in lacols
        sucols = {
            r["name"]
            for r in d.conn.execute("PRAGMA table_info(staging_uploads)").fetchall()
        }
        assert "finalizing" in sucols

        # The two indexes whose CREATE used to crash before the columns existed.
        la_idx = {
            r["name"]
            for r in d.conn.execute("PRAGMA index_list(login_attempts)").fetchall()
        }
        su_idx = {
            r["name"]
            for r in d.conn.execute("PRAGMA index_list(staging_uploads)").fetchall()
        }
        assert "idx_login_attempts_ip_time" in la_idx
        assert "idx_staging_uploads_owner" in su_idx

        # The pre-existing user row survives with new columns defaulted.
        legacy = d.get_user_by_username("legacy")
        assert legacy is not None
        assert legacy["session_version"] == 1
        assert legacy["ed25519_pubkey"] == b""
        assert legacy["x25519_pubkey"] == b""
        assert legacy["x25519_self_sig"] == b""
    finally:
        d.close()


# ──────────────────────── MIG-2: partial-migration recovery ──────────────────


def test_partial_v6_migration_completes_on_reconnect(tmp_path: Path) -> None:
    """A crash AFTER the first v6 ALTER but before the second must still add
    the second column on the next connect (per-statement idempotent ALTERs —
    MIG-2). Before the fix, the single executescript aborted on the duplicate
    first ALTER and never ran the second, leaving x25519_self_sig missing.
    """
    path = str(tmp_path / "v5partial.db")
    _make_v5_db(path)  # v5 users (no x25519 cols), version=5

    # Manually apply ONLY the first of the two v6 ALTERs, leaving version=5.
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "ALTER TABLE users ADD COLUMN x25519_pubkey BLOB NOT NULL DEFAULT x''"
        )
        conn.commit()
    finally:
        conn.close()

    d = Database(path)
    d.connect()
    try:
        cols = {
            r["name"] for r in d.conn.execute("PRAGMA table_info(users)").fetchall()
        }
        assert "x25519_pubkey" in cols
        assert (
            "x25519_self_sig" in cols
        ), "2nd ALTER must run even though the 1st was a duplicate"
        row = d.conn.execute("SELECT version FROM schema_version").fetchone()
        assert row["version"] == 6
    finally:
        d.close()


# ──────────────────────── AUTH-1: peer-scoped attempt count ──────────────────


def test_count_recent_attempts_ip_scoping(db: Database) -> None:
    """count_recent_attempts scopes to a peer when ip_address is given, and
    preserves the legacy username-only count when it is None (AUTH-1)."""
    for _ in range(3):
        db.record_login_attempt("alice", "1.1.1.1")
    for _ in range(2):
        db.record_login_attempt("alice", "2.2.2.2")

    # Unscoped (legacy) counts every peer's rows for the username.
    assert db.count_recent_attempts("alice", 3600) == 5
    # Peer-scoped counts only that peer's rows.
    assert db.count_recent_attempts("alice", 3600, "1.1.1.1") == 3
    assert db.count_recent_attempts("alice", 3600, "2.2.2.2") == 2
    # A peer with no rows for this user counts zero (no cross-peer lockout).
    assert db.count_recent_attempts("alice", 3600, "9.9.9.9") == 0


# ──────────────────────── STG-2: clear finalizing claim ──────────────────────


def test_clear_finalizing_allows_reclaim(db: Database) -> None:
    uid = _create_user(db)
    db.create_staging_upload(
        upload_id="c" * 32,
        owner_id=uid,
        filename="x.bin",
        expected_chunks=1,
        expiry_seconds=60,
    )
    with db.transaction():
        assert db.mark_upload_finalizing("c" * 32) is True
    # While finalizing=1 a second claim is blocked.
    with db.transaction():
        assert db.mark_upload_finalizing("c" * 32) is False
    # Clearing the claim lets the row be claimed again (the retry path).
    assert db.clear_finalizing("c" * 32) is True
    with db.transaction():
        assert db.mark_upload_finalizing("c" * 32) is True


def test_clear_finalizing_unknown_returns_false(db: Database) -> None:
    assert db.clear_finalizing("0" * 32) is False


# ──────────────────────── STG-3: re-upload size delta ────────────────────────


def test_get_staging_chunk_size(db: Database) -> None:
    uid = _create_user(db)
    db.create_staging_upload(
        upload_id="s" * 32,
        owner_id=uid,
        filename="x.bin",
        expected_chunks=2,
        expiry_seconds=60,
    )
    assert db.get_staging_chunk_size("s" * 32, 0) is None
    db.add_staging_chunk("s" * 32, 0, "hash", 1234)
    assert db.get_staging_chunk_size("s" * 32, 0) == 1234
    assert db.get_staging_chunk_size("s" * 32, 1) is None


# ──────────────────────── STG-4: atomic open-upload cap ──────────────────────


def test_try_create_staging_upload_enforces_cap_atomically(db: Database) -> None:
    """Two concurrent inits at the cap boundary: exactly one may cross (STG-4).

    The count + conditional insert run in ONE BEGIN IMMEDIATE transaction, so
    the non-atomic two-step (count, then insert) race that let both inits pass
    a snapshot count cannot happen here.
    """
    uid = _create_user(db)
    cap = 4
    for i in range(cap - 1):
        assert (
            db.try_create_staging_upload(
                upload_id=f"{i:032x}",
                owner_id=uid,
                filename="x.bin",
                expected_chunks=1,
                expiry_seconds=3600,
                max_open_uploads=cap,
            )
            is True
        )

    results: list[bool] = []
    barrier = threading.Barrier(2)

    def worker(j: int) -> None:
        barrier.wait()
        results.append(
            db.try_create_staging_upload(
                upload_id=f"{100 + j:032x}",
                owner_id=uid,
                filename="x.bin",
                expected_chunks=1,
                expiry_seconds=3600,
                max_open_uploads=cap,
            )
        )

    threads = [threading.Thread(target=worker, args=(j,)) for j in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(results) == 1, "exactly one init may cross the cap boundary"
    assert db.count_open_uploads(uid) == cap


def test_try_create_staging_upload_under_cap_succeeds(db: Database) -> None:
    uid = _create_user(db)
    assert (
        db.try_create_staging_upload(
            upload_id="d" * 32,
            owner_id=uid,
            filename="x.bin",
            expected_chunks=1,
            expiry_seconds=3600,
            max_open_uploads=2,
        )
        is True
    )
    assert db.get_staging_upload("d" * 32) is not None


# ──────────────────────── STG-5: synchronous expired reclaim ─────────────────


def test_reclaim_expired_staging_for_user(db: Database) -> None:
    """An expired-but-present upload is reclaimed synchronously (STG-5).

    Such a row is excluded from ``get_total_staging_bytes`` while it still
    sits on disk, so reclaiming it at init keeps the user's caps accurate.
    """
    uid = _create_user(db)
    db.create_staging_upload(
        upload_id="e" * 32,
        owner_id=uid,
        filename="x.bin",
        expected_chunks=1,
        expiry_seconds=-60,  # already expired
    )
    db.add_staging_chunk("e" * 32, 0, "hash", 1000)
    # Expired bytes are cap-invisible but the row still exists pre-reclaim.
    assert db.get_total_staging_bytes(uid) == 0
    assert db.get_staging_upload("e" * 32) is not None

    reclaimed = db.reclaim_expired_staging_for_user(uid)
    assert "e" * 32 in reclaimed
    assert db.get_staging_upload("e" * 32) is None


def test_reclaim_expired_staging_skips_finalizing(db: Database) -> None:
    """A finalizing row past expiry is NOT reclaimed (left to finalize/grace)."""
    uid = _create_user(db)
    db.create_staging_upload(
        upload_id="f" * 32,
        owner_id=uid,
        filename="x.bin",
        expected_chunks=1,
        expiry_seconds=-60,
    )
    with db.transaction():
        assert db.mark_upload_finalizing("f" * 32) is True
    assert db.reclaim_expired_staging_for_user(uid) == []
    assert db.get_staging_upload("f" * 32) is not None


def test_reclaim_expired_staging_keeps_live_uploads(db: Database) -> None:
    """A still-valid (non-expired) upload is never reclaimed."""
    uid = _create_user(db)
    db.create_staging_upload(
        upload_id="a" * 32,
        owner_id=uid,
        filename="x.bin",
        expected_chunks=1,
        expiry_seconds=3600,
    )
    assert db.reclaim_expired_staging_for_user(uid) == []
    assert db.get_staging_upload("a" * 32) is not None
