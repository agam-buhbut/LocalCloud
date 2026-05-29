"""Route-level integration tests for the download surface (ARCH-H1).

Covers ``GET /api/files/<id>`` (metadata), ``/<id>/owner_pubkey``, and
``/<id>/chunk/<i>`` end-to-end, plus the wrapped-keys access control that
gates a non-owner.

Files are installed with genuine encrypted bytes via the ``seed_file``
conftest factory (DB row + blob chunks on disk, exactly the layout a
correct finalize produces). This drives the real download routes against
real ciphertext WITHOUT going through the broken upload ingest path (see
test_api_upload.py for that bug). The decryption round-trips through the
client ``FileEncryptor`` so the test proves the server returns bytes the
client can actually decrypt — header signature, per-chunk AEAD tags, and
the Merkle root all verified by the real decryptor.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from tests.conftest import EncryptedUpload, KeyedClient, UploadedFile

_DATA = b"the quick brown fox jumps over the lazy dog\n" * 80  # ~3.5 KiB


async def _download_and_decrypt(
    authed,
    uploaded: UploadedFile,
    out_path,
    signer_pubkey: bytes,
    file_key: bytes,
    meta_key: bytes,
) -> bytes:
    """Fetch metadata + every chunk over HTTP and decrypt to out_path.

    Returns the decrypted plaintext bytes. Uses the real client
    FileEncryptor.decrypt_file so every integrity check is exercised.
    """
    from client.encryptor import FileEncryptor

    meta_resp = await authed.get(f"/api/files/{uploaded.file_id}")
    assert meta_resp.status_code == 200
    meta = await meta_resp.get_json()
    header_bytes = bytes.fromhex(meta["file_header"])
    enc_meta = bytes.fromhex(meta["encrypted_metadata"])
    total_chunks = meta["total_chunks"]

    chunks: list[bytes] = []
    for i in range(total_chunks):
        cr = await authed.get(f"/api/files/{uploaded.file_id}/chunk/{i}")
        assert cr.status_code == 200
        chunks.append(await cr.get_data())

    enc = FileEncryptor(uploaded.owner_keystore, chunk_size=1024)  # type: ignore[arg-type]
    enc.decrypt_file(
        input_chunks=iter(chunks),
        header_data=header_bytes,
        encrypted_metadata=enc_meta,
        file_key=file_key,
        meta_key=meta_key,
        signer_pubkey=signer_pubkey,
        output_path=out_path,
    )
    return out_path.read_bytes()


# ──────────────────────────── owner round-trip ────────────────────────────


async def test_owner_can_download_and_decrypt(
    tmp_path,
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """The owner fetches chunks + metadata and decrypts to the original.

    This is the real round-trip: server-served ciphertext is decrypted by
    the client and must equal the original plaintext byte-for-byte.
    """
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)

    signer = owner.keystore.ed25519_public_key()  # type: ignore[attr-defined]
    out = tmp_path / "decrypted.bin"
    plaintext = await _download_and_decrypt(
        owner.authed,
        uploaded,
        out,
        signer_pubkey=signer,
        file_key=uploaded.file_key,
        meta_key=uploaded.meta_key,
    )
    assert plaintext == _DATA


async def test_real_upload_then_download_roundtrips(
    tmp_path,
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    http_upload: Callable[..., Awaitable[tuple[EncryptedUpload, str]]],
) -> None:
    """End-to-end: upload a multi-chunk file via the live state machine,
    finalize it, then download every chunk + metadata over the routes and
    decrypt back to the original bytes.

    Unlike the seed_file-based tests, this exercises the REAL finalize
    on-disk/DB layout (atomic staging->blob rename, the committed files
    row), so the hand-rolled seed_file layout is validated against what a
    genuine finalize actually produces at least once.
    """
    from client.encryptor import FileEncryptor

    owner = await make_keyed_client()
    enc, upload_id = await http_upload(owner.authed, owner.keystore, _DATA)
    assert enc.total_chunks >= 2

    fin = await owner.authed.post(
        f"/api/files/upload/{upload_id}/finalize",
        json={
            "file_id": enc.file_id_hex,
            "total_chunks": enc.total_chunks,
            "file_header": enc.header_bytes.hex(),
            "encrypted_metadata": enc.encrypted_metadata.hex(),
            "visibility": 0,
            "expected_hashes": [h.hex() for h in enc.chunk_hashes],
        },
    )
    assert fin.status_code == 201, await fin.get_data()

    meta_resp = await owner.authed.get(f"/api/files/{enc.file_id_hex}")
    assert meta_resp.status_code == 200
    meta = await meta_resp.get_json()
    total_chunks = meta["total_chunks"]
    assert total_chunks == enc.total_chunks

    chunks: list[bytes] = []
    for i in range(total_chunks):
        cr = await owner.authed.get(f"/api/files/{enc.file_id_hex}/chunk/{i}")
        assert cr.status_code == 200
        chunks.append(await cr.get_data())

    out = tmp_path / "roundtrip.bin"
    decryptor = FileEncryptor(owner.keystore, chunk_size=1024)  # type: ignore[arg-type]
    decryptor.decrypt_file(
        input_chunks=iter(chunks),
        header_data=bytes.fromhex(meta["file_header"]),
        encrypted_metadata=bytes.fromhex(meta["encrypted_metadata"]),
        file_key=enc.file_key,
        meta_key=enc.meta_key,
        signer_pubkey=owner.keystore.ed25519_public_key(),  # type: ignore[attr-defined]
        output_path=out,
    )
    assert out.read_bytes() == _DATA


async def test_owner_pubkey_matches_registered_key(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """/owner_pubkey returns the owner's registered Ed25519 key."""
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)

    resp = await owner.authed.get(f"/api/files/{uploaded.file_id}/owner_pubkey")
    assert resp.status_code == 200
    pk = bytes.fromhex((await resp.get_json())["pubkey"])
    assert pk == owner.keystore.ed25519_public_key()  # type: ignore[attr-defined]


async def test_metadata_includes_total_bytes_for_owner(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """The owner's metadata view includes total_bytes."""
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)
    resp = await owner.authed.get(f"/api/files/{uploaded.file_id}")
    body = await resp.get_json()
    assert "total_bytes" in body
    assert body["total_bytes"] > 0


# ──────────────────────────── not found / validation ────────────────────────────


async def test_metadata_unknown_file_is_404(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
) -> None:
    owner = await make_keyed_client()
    resp = await owner.authed.get(f"/api/files/{'ab' * 16}")
    assert resp.status_code == 404


async def test_chunk_index_out_of_range_is_404(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)
    resp = await owner.authed.get(f"/api/files/{uploaded.file_id}/chunk/9999")
    assert resp.status_code == 404


async def test_chunk_response_has_no_store_cache_header(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """Chunk responses must not be cacheable (no metadata/timestamp leak)."""
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)
    resp = await owner.authed.get(f"/api/files/{uploaded.file_id}/chunk/0")
    assert resp.status_code == 200
    assert "no-store" in resp.headers.get("Cache-Control", "")


# ──────────────────────────── non-owner access control ────────────────────────────


async def test_non_owner_cannot_read_private_file(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """A stranger cannot fetch a private file's metadata or chunks (404).

    404 (not 403) is deliberate: the route must not reveal that the file
    exists to a non-authorized caller.
    """
    owner = await make_keyed_client()
    stranger = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    meta = await stranger.authed.get(f"/api/files/{uploaded.file_id}")
    assert meta.status_code == 404

    chunk = await stranger.authed.get(f"/api/files/{uploaded.file_id}/chunk/0")
    assert chunk.status_code == 404


async def test_non_owner_without_share_cannot_fetch_keys(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """A non-owner with no share row cannot fetch wrapped keys.

    Even for a private file the wrapped_keys endpoint must deny a stranger
    — it 404s (access denied == not found, no enumeration).
    """
    owner = await make_keyed_client()
    stranger = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA, visibility=0)

    resp = await stranger.authed.get(f"/api/files/{uploaded.file_id}/wrapped_keys")
    assert resp.status_code == 404


async def test_owner_wrapped_keys_is_none_when_unshared(
    make_keyed_client: Callable[..., Awaitable[KeyedClient]],
    seed_file: Callable[..., UploadedFile],
) -> None:
    """The owner has access but no share row -> wrapped_keys is null.

    get_wrapped_keys returns the per-recipient bundle; the owner never has
    one (they hold the raw keys), so the endpoint returns 200 with null
    rather than 404.
    """
    owner = await make_keyed_client()
    uploaded = seed_file(owner.user_id, owner.keystore, _DATA)
    resp = await owner.authed.get(f"/api/files/{uploaded.file_id}/wrapped_keys")
    assert resp.status_code == 200
    assert (await resp.get_json())["wrapped_keys"] is None
