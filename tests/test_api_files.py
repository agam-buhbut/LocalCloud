"""Route-level integration tests: list, delete, share/unshare (ARCH-H1).

Covers the file-management routes end-to-end:
- ``GET /api/files`` pagination and the cross-user total_bytes suppression
- ``DELETE /api/files/<id>`` owner-only + idempotent
- ``POST /api/files/<id>/share`` visibility transitions, wrapped_keys for a
  shared recipient (with a REAL key unwrap), and self-share behaviour
- ``DELETE /api/files/<id>/share/<user>`` revokes access

Files are installed with genuine encrypted bytes via the ``seed_file``
conftest factory so these routes run against real data without the broken
upload ingest path. Sharing uses the real keycore wrap/unwrap so the
shared-recipient path proves a recipient can actually recover the file
keys from the bundle the server returns.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from tests.conftest import KeyedClient, UploadedFile

_DATA = b"shared-file-contents-" * 100  # ~2.1 KiB


# ──────────────────────────── list ────────────────────────────


async def test_list_returns_owned_file(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)
    resp = await owner.authed.get("/api/files")
    assert resp.status_code == 200
    files = (await resp.get_json())["files"]
    assert any(f["file_id"] == uploaded.file_id for f in files)


async def test_list_pagination_limits_results(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """limit/offset bound the returned page and walk the full set.

    Seed 3 files, then page through them 2-at-a-time and assert the page
    sizes and that the union of pages covers every file exactly once.
    """
    owner = await make_keyed_client()
    ids = {
        seed_file(owner.user_id, owner.keystore, _DATA + bytes([i])).file_id
        for i in range(3)
    }

    page1 = await owner.authed.get("/api/files?limit=2&offset=0")
    assert page1.status_code == 200
    p1 = await page1.get_json()
    assert p1["limit"] == 2 and p1["offset"] == 0
    assert len(p1["files"]) == 2

    page2 = await owner.authed.get("/api/files?limit=2&offset=2")
    p2 = await page2.get_json()
    assert len(p2["files"]) == 1

    seen = {f["file_id"] for f in p1["files"]} | {f["file_id"] for f in p2["files"]}
    assert seen == ids


async def test_list_rejects_out_of_range_limit(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    owner = await make_keyed_client()
    resp = await owner.authed.get("/api/files?limit=0")
    assert resp.status_code == 400


async def test_list_suppresses_total_bytes_for_non_owner(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """A PUBLIC file lists for a stranger WITHOUT total_bytes (#H9).

    The owner sees total_bytes for their own files; a different user
    listing the same (public) file must not — padded-ciphertext sizes
    must not leak across users.
    """
    owner = await make_keyed_client()
    viewer = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=2)

    # Owner sees total_bytes.
    owner_list = await owner.authed.get("/api/files")
    owner_entry = next(
        f
        for f in (await owner_list.get_json())["files"]
        if f["file_id"] == uploaded.file_id
    )
    assert "total_bytes" in owner_entry

    # A different user sees the same public file but NOT its total_bytes.
    viewer_list = await viewer.authed.get("/api/files")
    viewer_entry = next(
        f
        for f in (await viewer_list.get_json())["files"]
        if f["file_id"] == uploaded.file_id
    )
    assert "total_bytes" not in viewer_entry


# ──────────────────────────── delete ────────────────────────────


async def test_owner_can_delete(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)
    resp = await owner.authed.delete(f"/api/files/{uploaded.file_id}")
    assert resp.status_code == 200
    # Gone afterwards.
    meta = await owner.authed.get(f"/api/files/{uploaded.file_id}")
    assert meta.status_code == 404


async def test_non_owner_cannot_delete(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """A stranger deleting another user's file gets 404 and the file stays.

    The regression guard is twofold: the response is 404 (no enumeration)
    AND the file is still readable by its owner afterwards.
    """
    owner = await make_keyed_client()
    stranger = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=2)

    resp = await stranger.authed.delete(f"/api/files/{uploaded.file_id}")
    assert resp.status_code == 404

    # Owner can still read it -> the stranger's delete was a no-op.
    still = await owner.authed.get(f"/api/files/{uploaded.file_id}")
    assert still.status_code == 200


async def test_delete_second_time_is_clean_not_found(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """A second delete is a clean not-found with no quota double-release.

    Per the task contract, deleting an already-deleted file returns 404
    (the ownership check finds no row). The load-bearing guard is that the
    second delete does NOT release quota again: used_bytes must stay at 0
    after the first delete, not go negative / wrap on the second.
    """
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)

    # Usage accrued by the seeded file, then released by the first delete.
    q0 = await owner.authed.get("/api/files/quota")
    assert (await q0.get_json())["used_bytes"] > 0

    first = await owner.authed.delete(f"/api/files/{uploaded.file_id}")
    assert first.status_code == 200
    q1 = await owner.authed.get("/api/files/quota")
    assert (await q1.get_json())["used_bytes"] == 0

    second = await owner.authed.delete(f"/api/files/{uploaded.file_id}")
    assert second.status_code == 404

    # No double-release: usage is still exactly 0, not driven below it.
    q2 = await owner.authed.get("/api/files/quota")
    assert (await q2.get_json())["used_bytes"] == 0


# ──────────────────────────── share / unshare ────────────────────────────


def _wrap_for(
    owner: KeyedClient, recipient: KeyedClient, uploaded: UploadedFile
) -> bytes:
    """Wrap the file's keys for ``recipient`` using the owner's keystore."""
    file_id_bytes = bytes.fromhex(uploaded.file_id)
    recipient_x = recipient.keystore.x25519_public_key()  # type: ignore[attr-defined]
    return owner.keystore.wrap_file_keys(  # type: ignore[attr-defined]
        uploaded.file_key, uploaded.meta_key, file_id_bytes, recipient_x
    )


async def test_share_makes_file_visible_to_recipient(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """Before share the recipient can't see a private file; after, they can.

    Asserts the visibility transition: a private file is invisible to the
    recipient, then sharing grants metadata access and promotes the file
    to SHARED visibility.
    """
    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    # Pre-share: recipient denied.
    before = await recipient.authed.get(f"/api/files/{uploaded.file_id}")
    assert before.status_code == 404

    wrapped = _wrap_for(owner, recipient, uploaded)
    share = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": recipient.username, "wrapped_keys": wrapped.hex()},
    )
    assert share.status_code == 200

    # Post-share: recipient can read metadata, and visibility is SHARED.
    after = await recipient.authed.get(f"/api/files/{uploaded.file_id}")
    assert after.status_code == 200
    assert (await after.get_json())["visibility"] == 1


async def test_shared_recipient_can_unwrap_keys(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """The recipient fetches wrapped_keys and recovers the real file keys.

    End-to-end proof that the bundle round-trips: the recipient unwraps it
    with their own keystore + the owner's Ed25519 identity and gets back
    exactly the file_key / meta_key the owner holds.
    """
    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    wrapped = _wrap_for(owner, recipient, uploaded)
    share = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": recipient.username, "wrapped_keys": wrapped.hex()},
    )
    assert share.status_code == 200

    resp = await recipient.authed.get(f"/api/files/{uploaded.file_id}/wrapped_keys")
    assert resp.status_code == 200
    bundle = bytes.fromhex((await resp.get_json())["wrapped_keys"])

    file_id_bytes = bytes.fromhex(uploaded.file_id)
    owner_ed = owner.keystore.ed25519_public_key()  # type: ignore[attr-defined]
    fk, mk = recipient.keystore.unwrap_file_keys(  # type: ignore[attr-defined]
        bundle, file_id_bytes, owner_ed
    )
    assert fk == uploaded.file_key
    assert mk == uploaded.meta_key


async def test_unshare_revokes_recipient_access(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """After unshare the recipient can no longer read the file or its keys."""
    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    wrapped = _wrap_for(owner, recipient, uploaded)
    await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": recipient.username, "wrapped_keys": wrapped.hex()},
    )
    # Sanity: access granted.
    assert (
        await recipient.authed.get(f"/api/files/{uploaded.file_id}")
    ).status_code == 200

    unshare = await owner.authed.delete(
        f"/api/files/{uploaded.file_id}/share/{recipient.username}"
    )
    assert unshare.status_code == 200

    # Revoked: metadata + wrapped_keys both denied now.
    after = await recipient.authed.get(f"/api/files/{uploaded.file_id}")
    assert after.status_code == 404
    keys = await recipient.authed.get(f"/api/files/{uploaded.file_id}/wrapped_keys")
    assert keys.status_code == 404


async def test_share_with_unknown_user_is_uniform_success(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """Sharing with a non-existent user returns the SAME 200 (no enum).

    The share endpoint must not reveal whether the target username exists;
    an unknown target yields the uniform {"status": "shared"} 200 but does
    NOT create a share row (the file stays private).
    """
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    # A well-formed wrapped-keys blob (length within bounds) for a ghost.
    wrapped = b"\x00" * 136
    resp = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": "ghostuser", "wrapped_keys": wrapped.hex()},
    )
    assert resp.status_code == 200
    assert (await resp.get_json())["status"] == "shared"

    # No real recipient -> file stays private (visibility unchanged).
    meta = await owner.authed.get(f"/api/files/{uploaded.file_id}")
    assert (await meta.get_json())["visibility"] == 0


async def test_self_share_is_noop_no_self_keys(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """Sharing a file with yourself is a uniform no-op.

    The owner already has access; a self-share must not create a wrapped-
    keys row for the owner (get_wrapped_keys stays null) and must not
    change visibility.
    """
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    wrapped = _wrap_for(owner, owner, uploaded)
    resp = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": owner.username, "wrapped_keys": wrapped.hex()},
    )
    assert resp.status_code == 200

    # No self share-row was created.
    keys = await owner.authed.get(f"/api/files/{uploaded.file_id}/wrapped_keys")
    assert keys.status_code == 200
    assert (await keys.get_json())["wrapped_keys"] is None
    # Visibility unchanged (still private).
    meta = await owner.authed.get(f"/api/files/{uploaded.file_id}")
    assert (await meta.get_json())["visibility"] == 0


async def test_share_non_owner_rejected(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """A non-owner cannot share someone else's file (404, no enumeration)."""
    owner = await make_keyed_client()
    stranger = await make_keyed_client()
    third = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=2)

    wrapped = b"\x00" * 136
    resp = await stranger.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": third.username, "wrapped_keys": wrapped.hex()},
    )
    assert resp.status_code == 404


async def test_share_rejects_oversized_wrapped_keys(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """wrapped_keys decoding to more than MAX_WRAPPED_KEYS_BYTES is rejected.

    Deterministic negative: the size bound is checked before the timing
    budget starts, so this 400 does not depend on any constant-time path.
    A blob one byte over the 4096-byte cap must be rejected; this is the
    DB-bloat guard against a hostile owner stuffing the share row.
    """
    from server.storage import MAX_WRAPPED_KEYS_BYTES

    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    oversized = (b"\x00" * (MAX_WRAPPED_KEYS_BYTES + 1)).hex()
    resp = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": recipient.username, "wrapped_keys": oversized},
    )
    assert resp.status_code == 400


async def test_share_rejects_malformed_body(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """A non-string shared_with, or a missing wrapped_keys, is rejected (400).

    Deterministic negative: these structural body checks run before the
    timing budget, so the 400 is not subject to any constant-time branch.
    """
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)
    wrapped = (b"\x00" * 136).hex()

    # Non-string shared_with.
    bad_target = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": 123, "wrapped_keys": wrapped},
    )
    assert bad_target.status_code == 400

    # Missing wrapped_keys entirely.
    missing_keys = await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": "someone"},
    )
    assert missing_keys.status_code == 400


async def test_unshare_then_revoked_file_downgrades_to_private(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """Unsharing the last recipient downgrades visibility back to PRIVATE.

    Share promotes a private file to SHARED; removing the only share must
    return it to PRIVATE so the access policy matches the (now absent)
    share rows.
    """
    owner = await make_keyed_client()
    recipient = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    wrapped = _wrap_for(owner, recipient, uploaded)
    await owner.authed.post(
        f"/api/files/{uploaded.file_id}/share",
        json={"shared_with": recipient.username, "wrapped_keys": wrapped.hex()},
    )
    promoted = await owner.authed.get(f"/api/files/{uploaded.file_id}")
    assert (await promoted.get_json())["visibility"] == 1

    await owner.authed.delete(
        f"/api/files/{uploaded.file_id}/share/{recipient.username}"
    )
    downgraded = await owner.authed.get(f"/api/files/{uploaded.file_id}")
    assert (await downgraded.get_json())["visibility"] == 0
