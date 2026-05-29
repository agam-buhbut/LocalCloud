"""SEC-M4: bound login_attempts row growth under a username flood.

A single peer can otherwise author one login_attempts row per synthetic
username it tries. With a per-peer cap on inserts within the rate-limit
window, a flood of DISTINCT usernames from ONE peer stays bounded under
the cap. The in-memory composite limiter (server.auth) still enforces
lockout and the auth response stays generic — these tests only assert
the storage-layer row bound.
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


def _count_rows_for_ip(db: Database, ip: str) -> int:
    row = db.conn.execute(
        "SELECT COUNT(*) AS cnt FROM login_attempts WHERE ip_address = ?",
        (ip,),
    ).fetchone()
    return int(row["cnt"])


def test_distinct_username_flood_from_one_peer_is_bounded(db: Database):
    """A flood of distinct usernames from one peer stays under the cap."""
    peer = "10.0.0.99"
    cap = 25
    window = 60
    # Try far more distinct usernames than the cap.
    for i in range(cap * 20):
        db.record_login_attempt(
            f"user{i:06d}",
            peer,
            max_rows_per_window=cap,
            window_seconds=window,
        )
    rows = _count_rows_for_ip(db, peer)
    assert rows <= cap, f"per-peer rows {rows} exceeded cap {cap}"
    # The cap should actually be hit, not just trivially under (e.g. the
    # insert path must be reached, not short-circuited entirely).
    assert rows == cap


def test_cap_is_per_peer_not_global(db: Database):
    """One peer hitting the cap must not block a different peer's rows."""
    cap = 5
    window = 60
    for i in range(cap * 4):
        db.record_login_attempt(
            f"user{i:06d}",
            "10.0.0.1",
            max_rows_per_window=cap,
            window_seconds=window,
        )
    # Second peer is independent and still under its own cap.
    db.record_login_attempt(
        "victim",
        "10.0.0.2",
        max_rows_per_window=cap,
        window_seconds=window,
    )
    assert _count_rows_for_ip(db, "10.0.0.1") == cap
    assert _count_rows_for_ip(db, "10.0.0.2") == 1


def test_record_without_cap_is_unbounded_backcompat(db: Database):
    """Default call (no cap kwargs) keeps legacy unconditional-insert behavior."""
    peer = "10.0.0.7"
    for i in range(30):
        db.record_login_attempt(f"user{i:06d}", peer)
    assert _count_rows_for_ip(db, peer) == 30


def test_cap_counts_only_within_window(db: Database):
    """Rows aged out of the window do not count against the cap."""
    peer = "10.0.0.5"
    cap = 3
    # Insert rows with a tiny window so previously-recorded rows fall
    # outside the window on the next call. Using window_seconds=0 means
    # only rows with attempt_time strictly greater than `now` count —
    # i.e. nothing prior counts — so every call inserts.
    for i in range(cap * 3):
        db.record_login_attempt(
            f"user{i:06d}",
            peer,
            max_rows_per_window=cap,
            window_seconds=0,
        )
    # All inserts went through because the window never retained prior rows.
    assert _count_rows_for_ip(db, peer) == cap * 3


def test_empty_ip_not_capped_against_other_empty_ip_peers(db: Database):
    """Empty ip_address must not let one un-identified caller starve inserts.

    peer_id is validated non-empty before record_login_attempt in the
    auth flow, but guard the DB method directly: when ip_address is empty
    the cap is not applied (there is no peer to attribute rows to).
    """
    cap = 2
    window = 60
    for i in range(10):
        db.record_login_attempt(
            f"user{i:06d}",
            "",
            max_rows_per_window=cap,
            window_seconds=window,
        )
    assert _count_rows_for_ip(db, "") == 10
