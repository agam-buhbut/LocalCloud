"""Timing-equalization invariants for the share / unshare endpoints (3B).

These endpoints must be timing input-INDEPENDENT: an attacker must not be
able to tell whether a share target exists (a username-enumeration oracle)
from the response. After the Phase 3B dedup factored the equalization into
``server.timing.sleep_until_deadline`` + the ``_apply_share`` /
``_apply_unshare`` helpers, this module guards that the property survived.

Two complementary, DETERMINISTIC assertions (no flaky wall-clock compare):

1. **Same work shape** — both the "real recipient" branch and the
   "unknown target" branch open exactly ONE write transaction (verified by
   spying on ``Database.transaction``). Identical transaction shape is the
   structural core of the equalization (same lock-take + WAL frame); the
   constant deadline only caps residual variance.
2. **Constant-deadline floor** — with the shared budget patched to a small
   floor, BOTH branches take at least that long, so a fast "no row" path
   cannot finish measurably sooner than a "row exists" one. This mirrors the
   existing directory test (``test_api_users.test_directory_applies_
   constant_deadline``).
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

import pytest

import server.storage as storage_mod
import server.timing as timing_mod
from server.database import Database
from tests.conftest import KeyedClient, UploadedFile

_DATA = b"timing-equalization-fixture-" * 64  # ~1.8 KiB

# A well-formed wrapped-keys blob (within the share length bounds) for the
# unknown-target branch, which never reaches a real recipient.
_DUMMY_WRAPPED = (b"\x00" * 136).hex()


@pytest.fixture()
def count_write_transactions(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[], int]:
    """Spy on ``Database.transaction``; return a reader for the count.

    Wraps the real context manager (behavior unchanged) and bumps a counter
    each time a write transaction is opened. The returned callable yields
    the current count so a test can snapshot it around one request.
    """
    calls = {"n": 0}
    original = Database.transaction

    def _counting(self: Database):
        calls["n"] += 1
        return original(self)

    monkeypatch.setattr(Database, "transaction", _counting)
    return lambda: calls["n"]


# ──────────────────────── dummy-write content guard ────────────────────────


class _RecordingConn:
    """Minimal connection stand-in that records executed SQL.

    ``_timing_dummy_write`` only calls ``conn.execute(sql, params)``; capturing
    the statements lets us assert the dummy branch issues REAL WAL-emitting
    writes rather than an empty ``pass``.
    """

    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.statements.append(sql)


def test_timing_dummy_write_issues_two_real_updates() -> None:
    """The dummy write must emit the same two UPDATEs as the real branch.

    The same-tx-count tests below pin that exactly ONE transaction opens on
    every branch, but the whole if/else lives inside that single transaction,
    so they are blind to a regression that emptied ``_timing_dummy_write`` to a
    ``pass``: an empty transaction commits no WAL frame and finishes measurably
    sooner, reinstating the username-enumeration oracle the equalization
    exists to close. Pin the write content directly so such a regression fails.
    """
    conn = _RecordingConn()
    storage_mod._timing_dummy_write(conn, "f" * 32, "u" * 16)  # type: ignore[arg-type]

    updates = [s for s in conn.statements if s.strip().upper().startswith("UPDATE")]
    assert len(updates) == 2, conn.statements
    assert any("files" in s for s in updates)
    assert any("users" in s for s in updates)


# ──────────────────────── same-work-shape (structural) ────────────────────────


async def test_share_same_tx_count_for_real_and_unknown_target(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
    count_write_transactions: Callable[[], int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A share to a real user and to an unknown user open the SAME #txns.

    If the unknown-target branch skipped the write transaction, an attacker
    could enumerate usernames by latency / lock contention. Both must open
    exactly one.
    """
    # Keep the test fast: the deadline floor is exercised separately.
    monkeypatch.setattr(timing_mod, "TIMING_BUDGET_S", 0.0)

    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    # Real target.
    before = count_write_transactions()
    resp_real = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": recipient.username, "wrapped_keys": _DUMMY_WRAPPED},
    )
    real_txns = count_write_transactions() - before
    assert resp_real.status_code == 200

    # Unknown target — uniform success, but must do equivalent DB work.
    before = count_write_transactions()
    resp_unknown = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": "nonexistent-user", "wrapped_keys": _DUMMY_WRAPPED},
    )
    unknown_txns = count_write_transactions() - before
    assert resp_unknown.status_code == 200

    assert real_txns == unknown_txns == 1


async def test_self_share_same_tx_count_as_unknown_target(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
    count_write_transactions: Callable[[], int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit self-share no-op opens the same one write transaction.

    A self-share is a deliberate no-op (the owner already has access; owner
    bundles go through POST /self_keys), but it must remain
    timing-indistinguishable from an unknown target — so it still runs the
    equivalent dummy write inside one transaction.
    """
    monkeypatch.setattr(timing_mod, "TIMING_BUDGET_S", 0.0)

    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    before = count_write_transactions()
    resp = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": owner.username, "wrapped_keys": _DUMMY_WRAPPED},
    )
    self_txns = count_write_transactions() - before
    assert resp.status_code == 200
    assert self_txns == 1

    # The self-share created no share row (it is a true no-op).
    keys = await owner.authed.get(f"/api/files/{uploaded.file_id}/wrapped_keys")
    assert (await keys.get_json())["wrapped_keys"] is None


async def test_unshare_same_tx_count_for_real_and_unknown_target(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
    count_write_transactions: Callable[[], int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unshare of a real recipient and of an unknown user open the SAME #txns."""
    monkeypatch.setattr(timing_mod, "TIMING_BUDGET_S", 0.0)

    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=1)

    before = count_write_transactions()
    resp_real = await owner.authed.delete(
        f"/api/files/{uploaded.file_id}/share/{recipient.username}"
    )
    real_txns = count_write_transactions() - before
    assert resp_real.status_code == 200

    before = count_write_transactions()
    resp_unknown = await owner.authed.delete(
        f"/api/files/{uploaded.file_id}/share/nonexistent-user"
    )
    unknown_txns = count_write_transactions() - before
    assert resp_unknown.status_code == 200

    assert real_txns == unknown_txns == 1


# ──────────────────────── constant-deadline floor (wall-clock) ────────────────


async def test_share_applies_constant_deadline_floor(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both the real and the unknown-target share meet the deadline floor.

    Patch the shared budget to a small but non-trivial value and assert
    BOTH lookups take at least that long, so a fast 'no recipient' path
    cannot finish measurably sooner than a 'recipient exists' one.
    """
    floor = 0.05
    monkeypatch.setattr(timing_mod, "TIMING_BUDGET_S", floor)

    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    t0 = time.monotonic()
    await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": recipient.username, "wrapped_keys": _DUMMY_WRAPPED},
    )
    dt_real = time.monotonic() - t0

    t0 = time.monotonic()
    await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": "nonexistent-user", "wrapped_keys": _DUMMY_WRAPPED},
    )
    dt_unknown = time.monotonic() - t0

    # Both meet the floor (allow a small scheduler slack below it).
    assert dt_real >= floor - 0.01
    assert dt_unknown >= floor - 0.01


async def test_unshare_applies_constant_deadline_floor(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both the real and the unknown-target unshare meet the deadline floor."""
    floor = 0.05
    monkeypatch.setattr(timing_mod, "TIMING_BUDGET_S", floor)

    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=1)

    t0 = time.monotonic()
    await owner.authed.delete(
        f"/api/files/{uploaded.file_id}/share/{recipient.username}"
    )
    dt_real = time.monotonic() - t0

    t0 = time.monotonic()
    await owner.authed.delete(f"/api/files/{uploaded.file_id}/share/nonexistent-user")
    dt_unknown = time.monotonic() - t0

    assert dt_real >= floor - 0.01
    assert dt_unknown >= floor - 0.01


# ``storage_mod`` is imported so a future refactor that drops the helpers
# this test relies on (``_apply_share`` / ``_apply_unshare``) fails loudly
# here rather than silently weakening the equalization.
assert hasattr(storage_mod, "_apply_share")
assert hasattr(storage_mod, "_apply_unshare")
