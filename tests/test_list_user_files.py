"""Semantics of ``Database.list_user_files`` (Phase 4D).

The 4D optimization rewrites this query to avoid materializing the whole
public corpus into temporary B-trees. These tests pin the *observable*
contract the rewrite must preserve exactly:

- a file is visible iff the user owns it, it is shared with them, or it is
  public (visibility == 2);
- a file appears **exactly once** even when it qualifies under more than one
  branch (owner∩public, shared∩public) — the original ``UNION`` deduped, and
  the rewrite's ``UNION ALL`` + explicit dedup must too;
- results are ordered by ``created_at`` DESC and paginate without gaps or
  overlap.

``created_at`` is stamped from ``time.time()`` inside ``create_file``; a fast
loop would tie and make ordering unspecified, so we monkeypatch it to a
strictly increasing clock for the ordering/pagination tests.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator

import pytest

import server.database as database_mod
from server.database import Database

# visibility ints (mirror server.policy.Visibility): 0 private, 1 shared, 2 public
_PRIVATE, _SHARED, _PUBLIC = 0, 1, 2


def _user(db: Database, name: str) -> str:
    return db.create_user(
        username=name, password_hash="$argon2id$x", quota_bytes=1 << 40
    )


def _file(db: Database, owner: str, vis: int, name: str) -> str:
    fid = f"{abs(hash(name)) % (16**32):032x}"
    with db.transaction():
        db.create_file(
            file_id=fid,
            owner_id=owner,
            filename=name,
            visibility=vis,
            total_chunks=1,
            total_bytes=100,
            encrypted_metadata=b"m",
            file_header=b"h",
        )
    return fid


@pytest.fixture()
def increasing_clock(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make ``create_file``'s ``created_at`` strictly increasing.

    Each ``time.time()`` call in the database module returns the next integer,
    so file creation order == created_at order with no ties.
    """
    counter = itertools.count(1000.0, 1.0)
    monkeypatch.setattr(database_mod.time, "time", lambda: next(counter))
    yield


def test_owned_shared_public_all_visible(db: Database) -> None:
    me = _user(db, "me")
    other = _user(db, "other")
    owned = _file(db, me, _PRIVATE, "owned.bin")
    shared = _file(db, other, _SHARED, "shared.bin")
    with db.transaction():
        db.add_file_share(shared, me, b"\x00" * 136)
    public = _file(db, other, _PUBLIC, "public.bin")

    ids = {r["file_id"] for r in db.list_user_files(me, limit=50)}
    assert ids == {owned, shared, public}


def test_other_users_private_file_hidden(db: Database) -> None:
    me = _user(db, "me")
    other = _user(db, "other")
    _file(db, other, _PRIVATE, "secret.bin")  # not shared with me
    assert db.list_user_files(me, limit=50) == []


def test_owned_public_file_appears_once(db: Database) -> None:
    """A file I own that is also public qualifies under two branches → once."""
    me = _user(db, "me")
    fid = _file(db, me, _PUBLIC, "mine-public.bin")
    rows = db.list_user_files(me, limit=50)
    assert [r["file_id"] for r in rows] == [fid]


def test_shared_public_file_appears_once(db: Database) -> None:
    """A file shared with me that is also public qualifies twice → once."""
    me = _user(db, "me")
    other = _user(db, "other")
    fid = _file(db, other, _PUBLIC, "shared-and-public.bin")
    with db.transaction():
        db.add_file_share(fid, me, b"\x00" * 136)
    rows = db.list_user_files(me, limit=50)
    assert [r["file_id"] for r in rows].count(fid) == 1
    assert len(rows) == 1


def test_order_is_created_at_desc(db: Database, increasing_clock: None) -> None:
    me = _user(db, "me")
    other = _user(db, "other")
    # Interleave branches so ordering can't accidentally pass by branch order.
    a = _file(db, me, _PRIVATE, "a")
    b = _file(db, other, _PUBLIC, "b")
    c = _file(db, me, _PRIVATE, "c")
    s = _file(db, other, _SHARED, "s")
    with db.transaction():
        db.add_file_share(s, me, b"\x00" * 136)
    # creation order a<b<c<s  → newest-first is s,c,b,a
    rows = db.list_user_files(me, limit=50)
    assert [r["file_id"] for r in rows] == [s, c, b, a]


def test_pagination_across_branches_no_gap_no_overlap(
    db: Database, increasing_clock: None
) -> None:
    me = _user(db, "me")
    other = _user(db, "other")
    created: list[str] = []
    # 6 files spanning all three branches, distinct increasing created_at.
    created.append(_file(db, me, _PRIVATE, "p0"))
    created.append(_file(db, other, _PUBLIC, "p1"))
    s = _file(db, other, _SHARED, "p2")
    with db.transaction():
        db.add_file_share(s, me, b"\x00" * 136)
    created.append(s)
    created.append(_file(db, me, _PRIVATE, "p3"))
    created.append(_file(db, other, _PUBLIC, "p4"))
    created.append(_file(db, me, _PRIVATE, "p5"))

    newest_first = list(reversed(created))
    page1 = [r["file_id"] for r in db.list_user_files(me, limit=2, offset=0)]
    page2 = [r["file_id"] for r in db.list_user_files(me, limit=2, offset=2)]
    page3 = [r["file_id"] for r in db.list_user_files(me, limit=2, offset=4)]
    assert page1 == newest_first[0:2]
    assert page2 == newest_first[2:4]
    assert page3 == newest_first[4:6]
