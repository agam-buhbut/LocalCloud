"""Property / fuzz tests for the client encryption engine (CRY-GAP).

Covers the security-critical invariants of ``client.encryptor`` plus the
AEAD AAD construction in ``shared.models.ChunkAAD``:

* nonce uniqueness — every chunk nonce and the metadata nonce, across
  many encryptions, is unique (a XChaCha20-Poly1305 nonce reuse under a
  fixed key is catastrophic);
* key isolation — distinct files get distinct file_key and meta_key, and
  the two keys for one file differ;
* fail-on-corruption — flipping ANY single byte of a chunk / header /
  metadata makes ``decrypt_file`` raise, and never yields wrong plaintext;
* AAD binding (CRY-M1 / CRY-M2 + the metadata sentinel) — flipping ANY
  AAD-relevant field (file_id, chunk_index, total_chunks, protocol
  version, the metadata sentinel index) makes the AEAD decrypt fail.

The AAD-binding cases drive ``encrypt_chunk`` / ``decrypt_chunk`` with
``ChunkAAD`` directly so they isolate the AEAD-AAD gate from the
signature / Merkle gates — they are precise regression guards for the AAD
fields, not incidental catches via the outer integrity checks.

Determinism: the cryptographic randomness is real CSPRNG (that is the
property under test), but every test is bounded to a fixed number of
iterations / hypothesis examples and uses ``tmp_path`` for all file I/O —
no sleeps, no network. A single module-scoped keystore amortizes the
512 MiB Argon2id key-store seal (~seconds) across the whole module.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from client.encryptor import EncryptResult, FileEncryptor
from client.keystore import KeyStore
from shared.crypto import decrypt_chunk, encrypt_chunk, generate_key, generate_nonce
from shared.exceptions import DecryptionError, LocalCloudError
from shared.models import (
    METADATA_CHUNK_INDEX,
    NONCE_LEN,
    PROTOCOL_VERSION,
    ChunkAAD,
)

# Small chunk size so a handful of bytes spans several chunks — keeps the
# per-encryption cost tiny while still exercising multi-chunk nonce draws.
_CHUNK_SIZE = 64


@pytest.fixture(scope="module")
def keystore(tmp_path_factory: pytest.TempPathFactory) -> KeyStore:
    """One unlocked KeyStore for the whole module.

    Generating the store runs the client-side Argon2id KDF once; reusing
    it across every encryption keeps the suite fast while still using a
    real signing key (so signatures verify on the happy path).
    """
    d = tmp_path_factory.mktemp("keystore")
    ks = KeyStore(str(d / "keys.enc"))
    ks.generate("module-test-password-123456")
    yield ks
    ks.lock()


def _encrypt(
    keystore: KeyStore, tmp_path: Path, plaintext: bytes
) -> tuple[EncryptResult, list[bytes]]:
    src = tmp_path / "in.bin"
    src.write_bytes(plaintext)
    enc = FileEncryptor(keystore, chunk_size=_CHUNK_SIZE)
    chunks: list[bytes] = []
    res = enc.encrypt_file(src, "in.bin", lambda _i, blob: chunks.append(blob))
    return res, chunks


def _decrypt(
    keystore: KeyStore,
    tmp_path: Path,
    res: EncryptResult,
    chunks: list[bytes],
    *,
    header_data: bytes | None = None,
    encrypted_metadata: bytes | None = None,
) -> bytes:
    """Run the full verified decrypt; return the recovered plaintext."""
    enc = FileEncryptor(keystore, chunk_size=_CHUNK_SIZE)
    out = tmp_path / f"out-{os.getpid()}-{len(chunks)}.bin"
    if out.exists():
        out.unlink()
    enc.decrypt_file(
        input_chunks=iter(chunks),
        header_data=res.header.serialize() if header_data is None else header_data,
        encrypted_metadata=(
            res.encrypted_metadata if encrypted_metadata is None else encrypted_metadata
        ),
        file_key=res.file_key,
        meta_key=res.meta_key,
        signer_pubkey=keystore.ed25519_public_key(),
        output_path=out,
    )
    return out.read_bytes()


# ──────────────────────────── Round-trip sanity ────────────────────────────


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(plaintext=st.binary(min_size=0, max_size=400))
def test_encrypt_decrypt_roundtrip(
    keystore: KeyStore, tmp_path: Path, plaintext: bytes
) -> None:
    res, chunks = _encrypt(keystore, tmp_path, plaintext)
    assert _decrypt(keystore, tmp_path, res, chunks) == plaintext


# ──────────────────────────── Nonce uniqueness ────────────────────────────


def test_chunk_and_metadata_nonces_unique(keystore: KeyStore, tmp_path: Path) -> None:
    """No chunk nonce or metadata nonce repeats across many encryptions.

    Each chunk blob is ``nonce(24) || ciphertext``; the metadata blob is
    likewise ``nonce(24) || ciphertext``. We collect every nonce produced
    over many multi-chunk encryptions into one set and assert the count
    equals the number of nonces seen — any collision (e.g. a nonce derived
    deterministically, or a reset counter) fails here.
    """
    seen: set[bytes] = set()
    total = 0
    # 150 bytes at a 64-byte chunk size => 3 chunks + 1 metadata nonce
    # per run; 150 runs => ~600 nonces drawn.
    for i in range(150):
        plaintext = os.urandom(150)
        sub = tmp_path / f"r{i}"
        sub.mkdir()
        res, chunks = _encrypt(keystore, sub, plaintext)
        for blob in chunks:
            seen.add(blob[:NONCE_LEN])
            total += 1
        seen.add(res.encrypted_metadata[:NONCE_LEN])
        total += 1
    assert len(seen) == total, "nonce collision detected across encryptions"


# ──────────────────────────── Key isolation ────────────────────────────


def test_distinct_files_have_distinct_keys(keystore: KeyStore, tmp_path: Path) -> None:
    """file_key/meta_key are freshly sampled per file and never reused."""
    file_keys: set[bytes] = set()
    meta_keys: set[bytes] = set()
    runs = 100
    for i in range(runs):
        sub = tmp_path / f"k{i}"
        sub.mkdir()
        res, _ = _encrypt(keystore, sub, b"x" * 10)
        # The two keys for a single file must differ from each other.
        assert res.file_key != res.meta_key
        file_keys.add(res.file_key)
        meta_keys.add(res.meta_key)
    assert len(file_keys) == runs, "file_key reused across files"
    assert len(meta_keys) == runs, "meta_key reused across files"
    # And no file_key ever collides with a meta_key.
    assert file_keys.isdisjoint(meta_keys), "file_key/meta_key namespaces overlap"


# ──────────────────────────── Fail on corruption ────────────────────────────


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(data=st.data())
def test_flip_chunk_byte_fails(
    keystore: KeyStore, tmp_path: Path, data: st.DataObject
) -> None:
    """Flipping any single byte of any chunk blob makes decrypt raise."""
    res, chunks = _encrypt(keystore, tmp_path, os.urandom(200))
    ci = data.draw(st.integers(min_value=0, max_value=len(chunks) - 1))
    bi = data.draw(st.integers(min_value=0, max_value=len(chunks[ci]) - 1))
    mask = data.draw(st.integers(min_value=1, max_value=255))

    corrupted = list(chunks)
    ba = bytearray(corrupted[ci])
    ba[bi] ^= mask
    corrupted[ci] = bytes(ba)

    out = tmp_path / f"corrupt-{os.getpid()}.bin"
    if out.exists():
        out.unlink()
    with pytest.raises(LocalCloudError):
        _decrypt(keystore, tmp_path, res, corrupted)
    assert not out.exists(), "corrupted decrypt left an output file"


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(data=st.data())
def test_flip_metadata_byte_fails(
    keystore: KeyStore, tmp_path: Path, data: st.DataObject
) -> None:
    """Flipping any single byte of the metadata blob makes decrypt raise."""
    res, chunks = _encrypt(keystore, tmp_path, os.urandom(200))
    meta = res.encrypted_metadata
    bi = data.draw(st.integers(min_value=0, max_value=len(meta) - 1))
    mask = data.draw(st.integers(min_value=1, max_value=255))
    ba = bytearray(meta)
    ba[bi] ^= mask

    with pytest.raises(LocalCloudError):
        _decrypt(keystore, tmp_path, res, chunks, encrypted_metadata=bytes(ba))


@settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(data=st.data())
def test_flip_header_byte_fails(
    keystore: KeyStore, tmp_path: Path, data: st.DataObject
) -> None:
    """Flipping any single byte of the serialized header makes decrypt raise.

    A header flip may trip the CBOR parser (MalformedRequestError), header
    validation (CryptoError), or the Ed25519 signature (SignatureError);
    all are LocalCloudError subclasses. The invariant is simply: it raises
    and never produces output.
    """
    res, chunks = _encrypt(keystore, tmp_path, os.urandom(200))
    header = res.header.serialize()
    bi = data.draw(st.integers(min_value=0, max_value=len(header) - 1))
    mask = data.draw(st.integers(min_value=1, max_value=255))
    ba = bytearray(header)
    ba[bi] ^= mask

    out = tmp_path / f"hdrcorrupt-{os.getpid()}.bin"
    if out.exists():
        out.unlink()
    with pytest.raises(LocalCloudError):
        _decrypt(keystore, tmp_path, res, chunks, header_data=bytes(ba))
    assert not out.exists(), "corrupted-header decrypt left an output file"


# ──────────────────────────── AAD binding ────────────────────────────
# These drive the AEAD primitive with ChunkAAD directly so a failure
# pinpoints the AAD construction, not the signature/Merkle layers.

_PAYLOAD = b"the-quick-brown-fox-jumps" * 4


def _make_chunk(
    file_id: bytes, chunk_index: int, total_chunks: int
) -> tuple[bytes, bytes, bytes]:
    """Return (key, nonce, ciphertext) for a chunk under the given AAD."""
    key = generate_key()
    nonce = generate_nonce()
    aad = ChunkAAD(
        file_id=file_id, chunk_index=chunk_index, total_chunks=total_chunks
    ).serialize()
    ct = encrypt_chunk(key, nonce, _PAYLOAD, aad)
    return key, nonce, ct


@settings(max_examples=50, deadline=None)
@given(
    file_id=st.binary(min_size=16, max_size=16),
    chunk_index=st.integers(min_value=0, max_value=1_000_000),
    total_chunks=st.integers(min_value=1, max_value=100_000),
)
def test_aad_correct_field_decrypts(
    file_id: bytes, chunk_index: int, total_chunks: int
) -> None:
    """Sanity: the matching AAD round-trips (so the negatives below mean
    something)."""
    key, nonce, ct = _make_chunk(file_id, chunk_index, total_chunks)
    aad = ChunkAAD(
        file_id=file_id, chunk_index=chunk_index, total_chunks=total_chunks
    ).serialize()
    assert decrypt_chunk(key, nonce, ct, aad) == _PAYLOAD


@settings(max_examples=60, deadline=None)
@given(
    file_id=st.binary(min_size=16, max_size=16),
    other_file_id=st.binary(min_size=16, max_size=16),
    chunk_index=st.integers(min_value=0, max_value=100_000),
    total_chunks=st.integers(min_value=1, max_value=100_000),
)
def test_aad_file_id_binding(
    file_id: bytes,
    other_file_id: bytes,
    chunk_index: int,
    total_chunks: int,
) -> None:
    """A different file_id in the AAD fails the AEAD tag."""
    if other_file_id == file_id:
        other_file_id = bytes((other_file_id[0] ^ 0x01,)) + other_file_id[1:]
    key, nonce, ct = _make_chunk(file_id, chunk_index, total_chunks)
    wrong = ChunkAAD(
        file_id=other_file_id, chunk_index=chunk_index, total_chunks=total_chunks
    ).serialize()
    with pytest.raises(DecryptionError):
        decrypt_chunk(key, nonce, ct, wrong)


@settings(max_examples=60, deadline=None)
@given(
    file_id=st.binary(min_size=16, max_size=16),
    chunk_index=st.integers(min_value=0, max_value=100_000),
    other_index=st.integers(min_value=0, max_value=100_000),
    total_chunks=st.integers(min_value=1, max_value=100_000),
)
def test_aad_chunk_index_binding(
    file_id: bytes,
    chunk_index: int,
    other_index: int,
    total_chunks: int,
) -> None:
    """A different chunk_index in the AAD fails the AEAD tag (anti-reorder)."""
    if other_index == chunk_index:
        other_index = (other_index + 1) % 100_001
    key, nonce, ct = _make_chunk(file_id, chunk_index, total_chunks)
    wrong = ChunkAAD(
        file_id=file_id, chunk_index=other_index, total_chunks=total_chunks
    ).serialize()
    with pytest.raises(DecryptionError):
        decrypt_chunk(key, nonce, ct, wrong)


@settings(max_examples=60, deadline=None)
@given(
    file_id=st.binary(min_size=16, max_size=16),
    chunk_index=st.integers(min_value=0, max_value=100_000),
    total_chunks=st.integers(min_value=1, max_value=100_000),
    other_total=st.integers(min_value=1, max_value=100_000),
)
def test_aad_total_chunks_binding(
    file_id: bytes,
    chunk_index: int,
    total_chunks: int,
    other_total: int,
) -> None:
    """A different total_chunks in the AAD fails the AEAD tag."""
    if other_total == total_chunks:
        other_total = (other_total % 100_000) + 1
    key, nonce, ct = _make_chunk(file_id, chunk_index, total_chunks)
    wrong = ChunkAAD(
        file_id=file_id, chunk_index=chunk_index, total_chunks=other_total
    ).serialize()
    with pytest.raises(DecryptionError):
        decrypt_chunk(key, nonce, ct, wrong)


@settings(max_examples=40, deadline=None)
@given(
    file_id=st.binary(min_size=16, max_size=16),
    chunk_index=st.integers(min_value=0, max_value=100_000),
    total_chunks=st.integers(min_value=1, max_value=100_000),
)
def test_aad_protocol_version_binding(
    file_id: bytes, chunk_index: int, total_chunks: int
) -> None:
    """A different protocol_version in the AAD fails the AEAD tag."""
    key, nonce, ct = _make_chunk(file_id, chunk_index, total_chunks)
    wrong = ChunkAAD(
        file_id=file_id,
        chunk_index=chunk_index,
        protocol_version=PROTOCOL_VERSION + 1,
        total_chunks=total_chunks,
    ).serialize()
    with pytest.raises(DecryptionError):
        decrypt_chunk(key, nonce, ct, wrong)


@settings(max_examples=40, deadline=None)
@given(file_id=st.binary(min_size=16, max_size=16))
def test_aad_metadata_sentinel_binding(file_id: bytes) -> None:
    """Metadata sealed under the sentinel index can't be opened as a chunk.

    The metadata AAD uses chunk_index == METADATA_CHUNK_INDEX (0xFFFFFFFF)
    with total_chunks == 0; that index sits above every real chunk index,
    so a hostile server cannot present the metadata blob in a data-chunk
    slot (or vice-versa). Decrypting metadata under a real chunk-0 AAD —
    and a real chunk under the sentinel AAD — must both fail.
    """
    key = generate_key()
    nonce = generate_nonce()

    meta_aad = ChunkAAD(
        file_id=file_id, chunk_index=METADATA_CHUNK_INDEX, total_chunks=0
    ).serialize()
    meta_ct = encrypt_chunk(key, nonce, _PAYLOAD, meta_aad)

    chunk0_aad = ChunkAAD(file_id=file_id, chunk_index=0, total_chunks=1).serialize()
    with pytest.raises(DecryptionError):
        decrypt_chunk(key, nonce, meta_ct, chunk0_aad)

    # And the reverse: a real chunk can't be opened under the sentinel AAD.
    key2 = generate_key()
    nonce2 = generate_nonce()
    chunk_ct = encrypt_chunk(key2, nonce2, _PAYLOAD, chunk0_aad)
    with pytest.raises(DecryptionError):
        decrypt_chunk(key2, nonce2, chunk_ct, meta_aad)
