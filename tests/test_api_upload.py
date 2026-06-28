"""Route-level integration tests for the upload state machine (ARCH-H1).

These exercise ``/api/files/upload/init``, ``/upload/<id>/chunk/<i>`` and
``/upload/<id>/finalize`` over the Quart test client.

The full init -> chunk -> finalize ingest path is driven against the live
routes (via the ``http_upload`` conftest fixture, which uploads genuine
FileEncryptor ciphertext through init + every chunk). Each finalize gate
is covered by a regression test that drives a real, otherwise-valid upload
to the point where exactly one gate fires — so the assertion fails if that
gate is removed, rather than passing for a spurious reason.

(Historical note: ``upload_init`` once returned a *hyphenated* UUID and
stored the staging row under it, while ``upload_chunk`` / ``upload_finalize``
canonicalize the path id through ``_validate_id`` — which strips hyphens —
before the DB lookup. The keys never matched, so the first chunk POST 400'd
and no upload could complete. ``upload_init`` now generates the id in the
same canonical no-hyphen form, so the genuine ingest path works end to end.)
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
from quart import Quart

from server import storage
from shared.crypto import blake2b_hash
from tests.conftest import (
    TEST_PEER_PORT,
    AuthedClient,
    EncryptedUpload,
    KeyedClient,
)

# 2.5 KiB at the 1 KiB test chunk size -> 3 chunks (2 full + 1 partial).
_MULTI_CHUNK_DATA = bytes(range(256)) * 10  # 2560 bytes


async def _finalize(
    authed: AuthedClient,
    upload_id: str,
    enc: EncryptedUpload,
    *,
    overrides: dict[str, object] | None = None,
):
    """POST a finalize body for ``enc`` to ``upload_id``.

    By default the body is well-formed (and finalize succeeds). ``overrides``
    replaces individual fields so a single-gate negative test can corrupt
    exactly one field while every other part of the body stays valid.
    """
    body: dict[str, object] = {
        "file_id": enc.file_id_hex,
        "total_chunks": enc.total_chunks,
        "file_header": enc.header_bytes.hex(),
        "encrypted_metadata": enc.encrypted_metadata.hex(),
        "visibility": 0,
        "expected_hashes": [h.hex() for h in enc.chunk_hashes],
    }
    if overrides:
        body.update(overrides)
    return await authed.post(f"/api/files/upload/{upload_id}/finalize", json=body)


async def _used_bytes(authed: AuthedClient) -> int:
    """Return the user's currently committed quota usage (used_bytes)."""
    resp = await authed.get("/api/files/quota")
    assert resp.status_code == 200
    return (await resp.get_json())["used_bytes"]


async def _listed_ids(authed: AuthedClient) -> set[str]:
    """Return the set of file_ids the user can currently list."""
    resp = await authed.get("/api/files")
    assert resp.status_code == 200
    return {f["file_id"] for f in (await resp.get_json())["files"]}


# ──────────────────────── ingest happy path ────────────────────────


async def test_upload_init_chunk_finalize_happy_path(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    encrypt_file: Callable[..., EncryptedUpload],
) -> None:
    """init -> chunk(s) -> finalize with a real multi-chunk encrypted file.

    Drives the documented client flow: init returns an upload_id, each
    chunk is POSTed to that id, then finalize commits. Asserts every step
    succeeds, finalize returns the canonical file_id, and the file becomes
    listable.
    """
    owner = await make_keyed_client()
    enc = encrypt_file(owner.keystore, _MULTI_CHUNK_DATA)
    assert enc.total_chunks >= 2

    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "file.bin", "expected_chunks": enc.total_chunks},
    )
    assert init.status_code == 201
    upload_id = (await init.get_json())["upload_id"]

    for idx, blob in enumerate(enc.chunk_blobs):
        chunk = await owner.authed.client.post(
            f"/api/files/upload/{upload_id}/chunk/{idx}",
            data=blob,
            headers={
                "Authorization": f"Bearer {owner.authed.token}",
                "Content-Type": "application/octet-stream",
            },
            scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
        )
        assert chunk.status_code == 200, await chunk.get_data()
        assert (await chunk.get_json())["chunk_hash"] == enc.chunk_hashes[idx].hex()

    fin = await _finalize(owner.authed, upload_id, enc)
    assert fin.status_code == 201
    assert (await fin.get_json())["file_id"] == enc.file_id_hex

    listing = await owner.authed.get("/api/files")
    ids = {f["file_id"] for f in (await listing.get_json())["files"]}
    assert enc.file_id_hex in ids


# ──────────────────────────── init validation ────────────────────────────


async def test_upload_init_returns_upload_id(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    owner = await make_keyed_client()
    resp = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 2},
    )
    assert resp.status_code == 201
    assert isinstance((await resp.get_json())["upload_id"], str)


async def test_upload_init_rejects_missing_fields(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    owner = await make_keyed_client()
    resp = await owner.authed.post(
        "/api/files/upload/init", json={"filename": "ok.bin"}
    )
    assert resp.status_code == 400


async def test_upload_init_rejects_zero_chunks(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """expected_chunks must be >= 1 (a zero-chunk upload is meaningless)."""
    owner = await make_keyed_client()
    resp = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 0},
    )
    assert resp.status_code == 400


async def test_upload_init_rejects_bool_chunks(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A JSON bool must not slip through the int check for expected_chunks."""
    owner = await make_keyed_client()
    resp = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": True},
    )
    assert resp.status_code == 400


async def test_upload_init_rejects_control_char_filename(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A filename containing a NUL / control char is rejected at init."""
    owner = await make_keyed_client()
    resp = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "bad\x00name.bin", "expected_chunks": 1},
    )
    assert resp.status_code == 400


async def test_upload_init_requires_auth(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """init without a bearer token is rejected by require_auth."""
    owner = await make_keyed_client()
    resp = await owner.authed.client.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 1},
        scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
    )
    assert resp.status_code == 401


# ──────────────────────── chunk validation (reachable gates) ────────────────────────


async def test_upload_chunk_rejects_wrong_content_type(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A chunk POST without octet-stream content type is rejected (415).

    The content-type gate runs before the staging-row lookup, so it is
    reachable despite the hyphen bug below it.
    """
    owner = await make_keyed_client()
    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 1},
    )
    upload_id = (await init.get_json())["upload_id"]
    resp = await owner.authed.client.post(
        f"/api/files/upload/{upload_id}/chunk/0",
        data=b"x" * 2048,
        headers={
            "Authorization": f"Bearer {owner.authed.token}",
            "Content-Type": "text/plain",
        },
        scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
    )
    assert resp.status_code == 415


async def test_upload_chunk_rejects_out_of_range_index(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A chunk index past MAX_CHUNKS_PER_FILE is rejected (400).

    This gate runs before the staging-row lookup too, so it is reachable.
    """
    from shared.models import MAX_CHUNKS_PER_FILE

    owner = await make_keyed_client()
    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 1},
    )
    upload_id = (await init.get_json())["upload_id"]
    resp = await owner.authed.client.post(
        f"/api/files/upload/{upload_id}/chunk/{MAX_CHUNKS_PER_FILE}",
        data=b"x" * 2048,
        headers={
            "Authorization": f"Bearer {owner.authed.token}",
            "Content-Type": "application/octet-stream",
        },
        scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
    )
    assert resp.status_code == 400


async def test_upload_chunk_rejects_malformed_upload_id(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A syntactically invalid upload_id is rejected at _validate_id (400)."""
    owner = await make_keyed_client()
    resp = await owner.authed.client.post(
        "/api/files/upload/not-a-valid-id/chunk/0",
        data=b"x" * 2048,
        headers={
            "Authorization": f"Bearer {owner.authed.token}",
            "Content-Type": "application/octet-stream",
        },
        scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
    )
    assert resp.status_code == 400


# ──────────────────────── finalize validation: pre-lookup gates ────────────────────────
#
# These two gates run BEFORE finalize looks the staging row up, so they
# fire without a staged upload. The body-validation gates (which run after
# the lookup succeeds) are covered further down by ``_real_finalize_*``
# tests that drive a genuine, fully-staged upload and corrupt exactly one
# finalize field — so each fails only because that specific gate fired.


async def test_finalize_rejects_malformed_upload_id(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A syntactically invalid upload_id is rejected before the lookup."""
    owner = await make_keyed_client()
    resp = await owner.authed.post(
        "/api/files/upload/not-a-valid-id/finalize",
        json={"file_id": "ab" * 16},
    )
    assert resp.status_code == 400


async def test_finalize_rejects_empty_body(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """An empty JSON body is rejected before the staging lookup."""
    owner = await make_keyed_client()
    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 1},
    )
    upload_id = (await init.get_json())["upload_id"]
    resp = await owner.authed.post(f"/api/files/upload/{upload_id}/finalize", json={})
    assert resp.status_code == 400


# ──────────────────────── chunk-ingest gates (real staged upload) ────────────────────────


async def test_upload_chunk_rejects_oversized_chunk(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A chunk larger than state.max_chunk_size is rejected with 413.

    Real guard: the size gate runs after the staging-row lookup succeeds,
    and the oversized blob is still under the per-user quota, so if the gate
    were removed the chunk would be accepted (200) instead of 413.
    """
    from server.storage import DEFAULT_MAX_CHUNK_SIZE

    # Quota generous enough that the size gate — not the quota gate — is what
    # rejects the oversized blob.
    owner = await make_keyed_client(quota_bytes=DEFAULT_MAX_CHUNK_SIZE * 4)
    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 1},
    )
    upload_id = (await init.get_json())["upload_id"]
    resp = await owner.authed.client.post(
        f"/api/files/upload/{upload_id}/chunk/0",
        data=b"x" * (DEFAULT_MAX_CHUNK_SIZE + 1),
        headers={
            "Authorization": f"Bearer {owner.authed.token}",
            "Content-Type": "application/octet-stream",
        },
        scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
    )
    assert resp.status_code == 413


async def test_upload_chunk_rejects_small_non_final_chunk(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A non-final chunk smaller than MIN_CHUNK_SIZE is rejected (400).

    Real guard: with expected_chunks=2 the chunk at index 0 is non-final, so
    the MIN_CHUNK_SIZE floor applies. A sub-floor blob must be rejected; if
    the floor check were removed it would be accepted (200).
    """
    from server.storage import MIN_CHUNK_SIZE

    owner = await make_keyed_client()
    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 2},
    )
    upload_id = (await init.get_json())["upload_id"]
    resp = await owner.authed.client.post(
        f"/api/files/upload/{upload_id}/chunk/0",
        data=b"x" * (MIN_CHUNK_SIZE - 1),
        headers={
            "Authorization": f"Bearer {owner.authed.token}",
            "Content-Type": "application/octet-stream",
        },
        scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
    )
    assert resp.status_code == 400


async def test_upload_chunk_rejects_index_at_expected_chunks(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """A chunk_index equal to expected_chunks (one past the last) is rejected.

    Real guard for the per-upload ``chunk_index >= expected_chunks`` gate
    (distinct from the global MAX_CHUNKS_PER_FILE gate, which is covered
    separately). expected_chunks=2 admits indices {0, 1}; index 2 must be
    rejected, and the index is far below MAX_CHUNKS_PER_FILE so only the
    per-upload gate can be doing the rejecting.
    """
    owner = await make_keyed_client()
    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 2},
    )
    upload_id = (await init.get_json())["upload_id"]
    resp = await owner.authed.client.post(
        f"/api/files/upload/{upload_id}/chunk/2",
        data=b"x" * 2048,
        headers={
            "Authorization": f"Bearer {owner.authed.token}",
            "Content-Type": "application/octet-stream",
        },
        scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
    )
    assert resp.status_code == 400


async def test_upload_chunk_quota_gate_rejects_over_quota_chunk(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    """The per-user quota gate rejects a chunk that would exceed the quota.

    Real guard: a 4 KiB single (final) chunk is under max_chunk_size, so the
    size gate passes; with a 2 KiB quota the transactional quota check is the
    only thing that can reject it (413). Removing that check accepts it.

    NOTE: the separate per-user *staging* cap (MAX_STAGING_BYTES_PER_USER,
    4 GiB) is checked one line later in the same transaction, but it is far
    above any quota a test can set, so the quota gate always trips first and
    that staging-cap branch is not independently reachable through the route.
    """
    owner = await make_keyed_client(quota_bytes=2048)
    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "ok.bin", "expected_chunks": 1},
    )
    upload_id = (await init.get_json())["upload_id"]
    resp = await owner.authed.client.post(
        f"/api/files/upload/{upload_id}/chunk/0",
        data=b"x" * 4096,
        headers={
            "Authorization": f"Bearer {owner.authed.token}",
            "Content-Type": "application/octet-stream",
        },
        scope_base={"client": (owner.authed.peer_host, TEST_PEER_PORT)},
    )
    assert resp.status_code == 413
    # Nothing was committed by a rejected chunk.
    assert await _used_bytes(owner.authed) == 0


# ──────────────────── finalize gates (real, fully-staged upload) ────────────────────
# Each test below drives a genuine init -> chunk(s) upload via http_upload
# (so the staging row exists and the finalize body is otherwise valid),
# then corrupts exactly ONE finalize input. The assertion therefore fails
# only because that specific gate fired — these are real guards, not
# row-not-found false positives.


async def test_real_finalize_commits_file_and_quota(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    http_upload: Callable[..., Awaitable[tuple[EncryptedUpload, str]]],
) -> None:
    """A successful finalize makes the file listable and commits its quota.

    Drives the live state machine end to end and asserts the two
    side effects a correct finalize must produce: the file appears in the
    owner's listing, and used_bytes equals the committed ciphertext size
    (chunk bytes + header + encrypted metadata).
    """
    owner = await make_keyed_client()
    assert await _used_bytes(owner.authed) == 0

    enc, upload_id = await http_upload(owner.authed, owner.keystore, _MULTI_CHUNK_DATA)
    assert enc.total_chunks >= 2

    fin = await _finalize(owner.authed, upload_id, enc)
    assert fin.status_code == 201
    assert (await fin.get_json())["file_id"] == enc.file_id_hex

    # File is listable.
    assert enc.file_id_hex in await _listed_ids(owner.authed)

    # Quota committed = ciphertext bytes the server stored.
    expected_bytes = (
        sum(len(b) for b in enc.chunk_blobs)
        + len(enc.header_bytes)
        + len(enc.encrypted_metadata)
    )
    assert await _used_bytes(owner.authed) == expected_bytes


async def test_real_finalize_rejects_wrong_total_chunks(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    http_upload: Callable[..., Awaitable[tuple[EncryptedUpload, str]]],
) -> None:
    """Finalize with a total_chunks that disagrees with the staged upload.

    The body declares one more chunk than was staged; finalize rejects it
    (400), commits no file, and charges no quota. (Two redundant gates
    enforce this — the expected_chunks match and the staged-count match —
    so the assertion guards the observable contract: a mismatched count is
    never committed.)
    """
    owner = await make_keyed_client()
    enc, upload_id = await http_upload(owner.authed, owner.keystore, _MULTI_CHUNK_DATA)

    resp = await _finalize(
        owner.authed,
        upload_id,
        enc,
        overrides={"total_chunks": enc.total_chunks + 1},
    )
    assert resp.status_code == 400
    assert enc.file_id_hex not in await _listed_ids(owner.authed)
    assert await _used_bytes(owner.authed) == 0


async def test_real_finalize_rejects_corrupted_expected_hash(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    http_upload: Callable[..., Awaitable[tuple[EncryptedUpload, str]]],
) -> None:
    """Finalize with a tampered expected_hash is rejected with no commit.

    Flips one hex nibble of the first expected chunk hash (length
    preserved, so the length pre-check passes and the constant-time compare
    is what fails). The file must NOT be committed and quota must NOT be
    charged — this is the integrity gate against a hostile client/MITM
    swapping in chunk bytes that don't match the signed Merkle root.
    """
    owner = await make_keyed_client()
    enc, upload_id = await http_upload(owner.authed, owner.keystore, _MULTI_CHUNK_DATA)

    hashes = [h.hex() for h in enc.chunk_hashes]
    first = hashes[0]
    # Flip the last hex digit, keeping the string length identical.
    flipped = first[:-1] + ("0" if first[-1] != "0" else "1")
    assert flipped != first and len(flipped) == len(first)
    hashes[0] = flipped

    resp = await _finalize(
        owner.authed, upload_id, enc, overrides={"expected_hashes": hashes}
    )
    assert resp.status_code == 400
    assert enc.file_id_hex not in await _listed_ids(owner.authed)
    assert await _used_bytes(owner.authed) == 0


async def test_real_double_finalize_does_not_commit_twice(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    http_upload: Callable[..., Awaitable[tuple[EncryptedUpload, str]]],
) -> None:
    """Re-finalizing a completed upload does not produce a second commit.

    The first finalize commits and deletes the staging row; the second
    finalize for the same upload_id must be rejected (the one-shot guard:
    the row is gone, so 4xx — observed 400 — not a 201 second commit). The
    load-bearing assertion is that quota and the listing each reflect
    exactly ONE committed file, never two.
    """
    owner = await make_keyed_client()
    enc, upload_id = await http_upload(owner.authed, owner.keystore, _MULTI_CHUNK_DATA)

    first = await _finalize(owner.authed, upload_id, enc)
    assert first.status_code == 201
    committed = await _used_bytes(owner.authed)
    assert committed > 0

    second = await _finalize(owner.authed, upload_id, enc)
    assert second.status_code in (400, 409, 410)

    # No double commit: quota unchanged and exactly one listing entry.
    assert await _used_bytes(owner.authed) == committed
    ids = await _listed_ids(owner.authed)
    assert ids == {enc.file_id_hex}


# ──────────────────── staging robustness (STG-1/2/3/5, PERF-2) ───────────────


async def _post_chunk(authed: AuthedClient, upload_id: str, index: int, data: bytes):
    """POST raw bytes to a chunk endpoint with the octet-stream content type."""
    return await authed.client.post(
        f"/api/files/upload/{upload_id}/chunk/{index}",
        data=data,
        headers={
            "Authorization": f"Bearer {authed.token}",
            "Content-Type": "application/octet-stream",
        },
        scope_base={"client": (authed.peer_host, TEST_PEER_PORT)},
    )


async def test_requota_fail_preserves_prior_chunk_and_finalizes(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    tmp_data_dir: Path,
) -> None:
    """STG-1 / PERF-2: a quota-failed re-upload of an accepted index must NOT
    destroy the prior chunk; the upload still finalizes into a complete,
    downloadable file, and the rejected re-upload leaves no temp behind.

    Before the write-temp-then-promote fix the re-upload os.replace'd into
    {idx}.bin and then unlinked it on quota rejection, so finalize promoted a
    blob missing a chunk.
    """
    quota = 5000
    owner = await make_keyed_client(quota_bytes=quota)
    original = b"A" * 1500
    chunk_hash = blake2b_hash(original).hex()

    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "f.bin", "expected_chunks": 1},
    )
    assert init.status_code == 201
    upload_id = (await init.get_json())["upload_id"]

    assert (await _post_chunk(owner.authed, upload_id, 0, original)).status_code == 200

    # Re-upload the same index with a chunk that blows the quota.
    reup = await _post_chunk(owner.authed, upload_id, 0, b"B" * (quota + 1000))
    assert reup.status_code == 413

    # The original chunk file survived untouched, and the rejected re-upload
    # left no temp file behind (PERF-2).
    staging_upload_dir = Path(tmp_data_dir) / "staging" / upload_id
    assert (staging_upload_dir / "0.bin").read_bytes() == original
    leftover = [p.name for p in staging_upload_dir.iterdir() if p.name != "0.bin"]
    assert leftover == [], f"rejected re-upload left junk in staging: {leftover}"

    # Finalize against the ORIGINAL chunk's hash → complete, committed file.
    file_id = "ab" * 16
    fin = await owner.authed.post(
        f"/api/files/upload/{upload_id}/finalize",
        json={
            "file_id": file_id,
            "total_chunks": 1,
            "file_header": (b"h" * 64).hex(),
            "encrypted_metadata": (b"m" * 64).hex(),
            "visibility": 0,
            "expected_hashes": [chunk_hash],
        },
    )
    assert fin.status_code == 201, await fin.get_data()

    # The finalized chunk downloads back as the original bytes (not missing).
    dl = await owner.authed.get(f"/api/files/{file_id}/chunk/0")
    assert dl.status_code == 200
    assert (await dl.get_data()) == original


async def test_reupload_same_index_not_over_rejected(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    app: Quart,
) -> None:
    """STG-3: a same-size re-upload near quota charges only the size delta, so
    it is not falsely over-quota, and the staging total reflects one chunk.

    Before the delta fix the re-upload double-counted (2000 + 2000 > 3000) and
    returned 413.
    """
    owner = await make_keyed_client(quota_bytes=3000)
    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "f.bin", "expected_chunks": 2},
    )
    upload_id = (await init.get_json())["upload_id"]

    payload = b"x" * 2000  # >= MIN_CHUNK_SIZE; 2x would exceed the 3000 quota
    assert (await _post_chunk(owner.authed, upload_id, 0, payload)).status_code == 200
    assert (await _post_chunk(owner.authed, upload_id, 0, payload)).status_code == 200

    db = app.db  # type: ignore[attr-defined]
    assert db.get_total_staging_bytes(owner.user_id) == 2000


async def test_finalize_transient_failure_clears_finalizing_and_allows_retry(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    http_upload: Callable[..., Awaitable[tuple[EncryptedUpload, str]]],
    monkeypatch: pytest.MonkeyPatch,
    app: Quart,
) -> None:
    """STG-2: a transient commit failure clears the finalize claim so a retry
    is accepted, instead of stranding finalizing=1 and returning a misleading
    'Upload expired' 410 on the retry.
    """
    owner = await make_keyed_client()
    enc, upload_id = await http_upload(owner.authed, owner.keystore, _MULTI_CHUNK_DATA)

    real_commit = storage._commit_finalized_blob
    calls = {"n": 0}

    def flaky_commit(*args: object, **kwargs: object) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient commit boom")
        return real_commit(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(storage, "_commit_finalized_blob", flaky_commit)

    first = await _finalize(owner.authed, upload_id, enc)
    assert first.status_code == 500  # transient server error, NOT 410 expiry

    # The claim was cleared so the row is reclaimable / retryable.
    db = app.db  # type: ignore[attr-defined]
    upload = db.get_staging_upload(upload_id)
    assert upload is not None
    assert upload["finalizing"] == 0

    # A retry now succeeds (commit works on the 2nd call), proving the retry
    # was NOT blocked by the one-shot claim guard.
    second = await _finalize(owner.authed, upload_id, enc)
    assert second.status_code == 201
    assert (await second.get_json())["file_id"] == enc.file_id_hex
    assert calls["n"] == 2


async def test_init_reclaims_expired_staging_of_same_user(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    app: Quart,
    tmp_data_dir: Path,
) -> None:
    """STG-5: a new init reclaims the same user's expired staging row + dir
    synchronously, so the expired upload stops counting against caps before
    the periodic GC runs.
    """
    owner = await make_keyed_client()
    db = app.db  # type: ignore[attr-defined]
    stale_id = "ab" * 16
    db.create_staging_upload(
        upload_id=stale_id,
        owner_id=owner.user_id,
        filename="stale.bin",
        expected_chunks=1,
        expiry_seconds=-60,  # already expired
    )
    stale_dir = Path(tmp_data_dir) / "staging" / stale_id
    stale_dir.mkdir(parents=True, exist_ok=True)

    init = await owner.authed.post(
        "/api/files/upload/init",
        json={"filename": "new.bin", "expected_chunks": 1},
    )
    assert init.status_code == 201

    assert db.get_staging_upload(stale_id) is None, "expired row must be reclaimed"
    assert not stale_dir.exists(), "expired staging dir must be removed"
