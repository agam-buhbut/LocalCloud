"""Connection-level durability/WAL PRAGMAs (Phase 4B-a).

Under WAL, ``synchronous=NORMAL`` is crash-safe (the db cannot corrupt; only
the last committed txn may be lost on power loss) and avoids an fsync on every
commit. Pin that the connection actually opens at NORMAL, and that WAL +
foreign-key enforcement are still in force (NORMAL must not silently disable
them).
"""

from __future__ import annotations

from server.database import Database

# sqlite synchronous: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA
_NORMAL = 1


def test_connection_opens_at_synchronous_normal(db: Database) -> None:
    val = db.conn.execute("PRAGMA synchronous").fetchone()[0]
    assert val == _NORMAL


def test_wal_and_foreign_keys_still_on(db: Database) -> None:
    assert db.conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert db.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
