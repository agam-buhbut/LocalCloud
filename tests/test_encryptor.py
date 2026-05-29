"""End-to-end encrypt/decrypt round-trip tests.

These tests exercise the streaming callback-based encrypt/decrypt path
that the CLI was previously calling incorrectly (#C1-#C4). Failure here
means the CLI is broken in a way the unit-level tests can't catch.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# `keycore` is required (built with maturin develop). Tests are skipped
# if it isn't present in this venv.
keycore = pytest.importorskip("keycore")

# These imports must come after `importorskip` because they transitively
# pull in `keycore`; importing them at the top would fail the whole
# module collection in environments without the Rust extension.
from client.encryptor import FileEncryptor  # noqa: E402
from client.keystore import KeyStore  # noqa: E402
from shared.exceptions import (  # noqa: E402
    CryptoError,
    DecryptionError,
    SignatureError,
)
from shared.models import (  # noqa: E402
    CHUNK_SIZE,
    MAX_CHUNKS_PER_FILE,
    FileHeader,
)


@pytest.fixture()
def keystore(tmp_path: Path) -> KeyStore:
    ks = KeyStore(str(tmp_path / "keys.enc"))
    ks.generate("test-password-1234")
    yield ks
    ks.lock()


def _round_trip(
    keystore: KeyStore,
    tmp_path: Path,
    plaintext: bytes,
    chunk_size: int = 1024,
):
    """Encrypt + decrypt and return decrypted bytes."""
    src = tmp_path / "in.bin"
    src.write_bytes(plaintext)
    enc = FileEncryptor(keystore, chunk_size=chunk_size)
    chunks: list[bytes] = []

    def on_chunk(idx: int, blob: bytes) -> None:
        chunks.append(blob)

    result = enc.encrypt_file(src, "in.bin", on_chunk)

    out = tmp_path / "out.bin"
    enc.decrypt_file(
        input_chunks=iter(chunks),
        header_data=result.header.serialize(),
        encrypted_metadata=result.encrypted_metadata,
        file_key=result.file_key,
        meta_key=result.meta_key,
        signer_pubkey=keystore.ed25519_public_key(),
        output_path=out,
    )
    return out.read_bytes(), result, chunks


def test_roundtrip_small_file(keystore: KeyStore, tmp_path: Path):
    plaintext = b"hello, localcloud!" * 100
    decrypted, _, _ = _round_trip(keystore, tmp_path, plaintext, chunk_size=512)
    assert decrypted == plaintext


def test_roundtrip_exact_chunk_boundary(keystore: KeyStore, tmp_path: Path):
    plaintext = b"x" * 1024
    decrypted, _, _ = _round_trip(keystore, tmp_path, plaintext, chunk_size=1024)
    assert decrypted == plaintext


def test_roundtrip_multi_chunk(keystore: KeyStore, tmp_path: Path):
    plaintext = os.urandom(4096 + 17)  # 4 full chunks + 1 small
    decrypted, _, _ = _round_trip(keystore, tmp_path, plaintext, chunk_size=1024)
    assert decrypted == plaintext


def test_roundtrip_empty_file(keystore: KeyStore, tmp_path: Path):
    plaintext = b""
    decrypted, _, _ = _round_trip(keystore, tmp_path, plaintext, chunk_size=1024)
    assert decrypted == plaintext


def test_tampered_chunk_rejected(keystore: KeyStore, tmp_path: Path):
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(4096))
    enc = FileEncryptor(keystore, chunk_size=1024)
    chunks: list[bytes] = []
    enc.encrypt_file(src, "in.bin", lambda i, b: chunks.append(b))

    # Flip a bit in the second chunk's ciphertext (post-nonce).
    bad = bytearray(chunks[1])
    bad[30] ^= 0x01
    chunks[1] = bytes(bad)

    out = tmp_path / "out.bin"
    enc2 = FileEncryptor(keystore, chunk_size=1024)
    # Need to re-encrypt to get a result for keys; easier: do another full
    # encrypt for this test
    enc3_chunks: list[bytes] = []
    result = enc2.encrypt_file(src, "in.bin", lambda i, b: enc3_chunks.append(b))

    with pytest.raises(DecryptionError):
        enc2.decrypt_file(
            input_chunks=iter([enc3_chunks[0], bad, *enc3_chunks[2:]]),
            header_data=result.header.serialize(),
            encrypted_metadata=result.encrypted_metadata,
            file_key=result.file_key,
            meta_key=result.meta_key,
            signer_pubkey=keystore.ed25519_public_key(),
            output_path=out,
        )
    # Critical: output_path must NOT exist after a failed decrypt.
    assert not out.exists()


def test_encrypt_produces_independent_file_and_meta_keys(
    keystore: KeyStore, tmp_path: Path
):
    # The file_key and meta_key must be independently sampled. This is a
    # regression guard for the catastrophic-RNG tripwire in encrypt_file:
    # if the two per-file keys ever came back equal we would have lost the
    # independent-key half of metadata/chunk domain separation. (CRY-M2)
    _, result, _ = _round_trip(keystore, tmp_path, b"payload", chunk_size=1024)
    assert result.file_key != result.meta_key
    assert len(result.file_key) == 32
    assert len(result.meta_key) == 32


def test_wrong_file_key_rejected(keystore: KeyStore, tmp_path: Path):
    plaintext = os.urandom(2000)
    _, result, chunks = _round_trip(keystore, tmp_path, plaintext, chunk_size=1024)
    out = tmp_path / "out2.bin"
    wrong_key = os.urandom(32)
    enc = FileEncryptor(keystore, chunk_size=1024)
    with pytest.raises(DecryptionError):
        enc.decrypt_file(
            input_chunks=iter(chunks),
            header_data=result.header.serialize(),
            encrypted_metadata=result.encrypted_metadata,
            file_key=wrong_key,
            meta_key=result.meta_key,
            signer_pubkey=keystore.ed25519_public_key(),
            output_path=out,
        )
    assert not out.exists()


def test_wrong_signer_pubkey_rejected(keystore: KeyStore, tmp_path: Path):
    plaintext = os.urandom(2000)
    _, result, chunks = _round_trip(keystore, tmp_path, plaintext, chunk_size=1024)
    out = tmp_path / "out3.bin"
    wrong_pubkey = os.urandom(32)
    enc = FileEncryptor(keystore, chunk_size=1024)
    with pytest.raises(SignatureError):
        enc.decrypt_file(
            input_chunks=iter(chunks),
            header_data=result.header.serialize(),
            encrypted_metadata=result.encrypted_metadata,
            file_key=result.file_key,
            meta_key=result.meta_key,
            signer_pubkey=wrong_pubkey,
            output_path=out,
        )
    assert not out.exists()


def test_oversize_encrypted_metadata_rejected(keystore: KeyStore, tmp_path: Path):
    plaintext = b"hi"
    _, result, _ = _round_trip(keystore, tmp_path, plaintext)
    enc = FileEncryptor(keystore, chunk_size=1024)
    huge_meta = b"x" * (1 << 21)  # 2 MiB — well above the cap
    with pytest.raises(DecryptionError):
        enc.decrypt_metadata(huge_meta, result.meta_key, result.header.file_id)


def test_chunk_count_mismatch_rejected(keystore: KeyStore, tmp_path: Path):
    plaintext = os.urandom(4096)
    _, result, chunks = _round_trip(keystore, tmp_path, plaintext, chunk_size=1024)
    out = tmp_path / "out4.bin"
    enc = FileEncryptor(keystore, chunk_size=1024)
    # Drop the last chunk — should fail at the post-loop count check.
    with pytest.raises(DecryptionError):
        enc.decrypt_file(
            input_chunks=iter(chunks[:-1]),
            header_data=result.header.serialize(),
            encrypted_metadata=result.encrypted_metadata,
            file_key=result.file_key,
            meta_key=result.meta_key,
            signer_pubkey=keystore.ed25519_public_key(),
            output_path=out,
        )
    assert not out.exists()


class _ExplodingChunks:
    """Iterator that raises if anything tries to pull a chunk from it.

    Used to prove decrypt_file rejects a bad header *before* it begins
    consuming (and writing) chunk bytes.
    """

    def __iter__(self) -> _ExplodingChunks:
        return self

    def __next__(self) -> bytes:
        raise AssertionError("decrypt_file consumed a chunk before geometry check")


def test_decrypt_rejects_nonstandard_chunk_size_before_writing(
    keystore: KeyStore, tmp_path: Path
):
    # A header whose chunk_size != the decryptor's configured chunk_size
    # must be rejected up front (CRY-M3 / ARCH-M6). The gate is on
    # self.chunk_size; here the FileEncryptor is built with chunk_size=1024,
    # so a header advertising 8 MiB is refused before any chunk is touched.
    # 8 MiB passes FileHeader.validate() (<= MAX_CHUNK_SIZE) yet is not the
    # on-wire chunk size this instance produces. (In production every caller
    # uses the default chunk_size == module CHUNK_SIZE, so this also rejects
    # a hostile production header advertising a different size.)
    assert CHUNK_SIZE != 8 * 1024 * 1024
    assert 8 * 1024 * 1024 != 1024  # header size differs from the instance size
    header = FileHeader(
        file_id=os.urandom(16),
        chunk_size=8 * 1024 * 1024,
        total_chunks=1,
        merkle_root=os.urandom(32),
        signature=b"",  # empty signature is valid per FileHeader.validate()
    )
    out = tmp_path / "nope.bin"
    enc = FileEncryptor(keystore, chunk_size=1024)
    # match= pins this to the geometry gate specifically: SignatureError /
    # DecryptionError are also CryptoError subclasses, so without the
    # message match this could pass for the wrong reason.
    with pytest.raises(CryptoError, match="chunk_size"):
        enc.decrypt_file(
            input_chunks=_ExplodingChunks(),
            header_data=header.serialize(),
            encrypted_metadata=b"\x00" * 64,
            file_key=os.urandom(32),
            meta_key=os.urandom(32),
            signer_pubkey=keystore.ed25519_public_key(),
            output_path=out,
        )
    assert not out.exists()


def test_decrypt_rejects_total_chunks_over_operational_ceiling(
    keystore: KeyStore, tmp_path: Path
):
    # total_chunks above MAX_CHUNKS_PER_FILE (operational ceiling) but
    # still within the wire-format MAX_CHUNKS must be rejected before any
    # chunk bytes are written. (CRY-M3 / ARCH-M6)
    header = FileHeader(
        file_id=os.urandom(16),
        chunk_size=CHUNK_SIZE,
        total_chunks=MAX_CHUNKS_PER_FILE + 1,
        merkle_root=os.urandom(32),
        signature=b"",
    )
    out = tmp_path / "nope2.bin"
    enc = FileEncryptor(keystore, chunk_size=1024)
    with pytest.raises(CryptoError, match="maximum chunk count"):
        enc.decrypt_file(
            input_chunks=_ExplodingChunks(),
            header_data=header.serialize(),
            encrypted_metadata=b"\x00" * 64,
            file_key=os.urandom(32),
            meta_key=os.urandom(32),
            signer_pubkey=keystore.ed25519_public_key(),
            output_path=out,
        )
    assert not out.exists()


def test_wrap_unwrap_via_keystore(tmp_path: Path):
    """Per-recipient X25519 wrap/unwrap end-to-end."""
    sender = KeyStore(str(tmp_path / "sender.enc"))
    sender.generate("pw-sender")
    recipient = KeyStore(str(tmp_path / "recipient.enc"))
    recipient.generate("pw-recipient")
    try:
        file_key = os.urandom(32)
        meta_key = os.urandom(32)
        file_id = os.urandom(16)

        wrapped = sender.wrap_file_keys(
            file_key=file_key,
            meta_key=meta_key,
            file_id=file_id,
            recipient_pubkey=recipient.x25519_public_key(),
        )
        fk, mk = recipient.unwrap_file_keys(
            wrapped_bundle=wrapped,
            file_id=file_id,
            sender_pubkey=sender.ed25519_public_key(),
        )
        assert fk == file_key
        assert mk == meta_key
    finally:
        sender.lock()
        recipient.lock()


def test_wrapped_bundle_wrong_file_id_fails(tmp_path: Path):
    sender = KeyStore(str(tmp_path / "s.enc"))
    sender.generate("pw")
    recipient = KeyStore(str(tmp_path / "r.enc"))
    recipient.generate("pw")
    try:
        fid_a = os.urandom(16)
        fid_b = os.urandom(16)
        wrapped = sender.wrap_file_keys(
            file_key=os.urandom(32),
            meta_key=os.urandom(32),
            file_id=fid_a,
            recipient_pubkey=recipient.x25519_public_key(),
        )
        with pytest.raises(Exception):
            recipient.unwrap_file_keys(
                wrapped_bundle=wrapped,
                file_id=fid_b,
                sender_pubkey=sender.ed25519_public_key(),
            )
    finally:
        sender.lock()
        recipient.lock()


def test_wrapped_bundle_with_trailing_bytes_rejected(tmp_path: Path):
    """Exact-length check on wrapped bundle (#H13.6 / #66)."""
    sender = KeyStore(str(tmp_path / "s.enc"))
    sender.generate("pw")
    recipient = KeyStore(str(tmp_path / "r.enc"))
    recipient.generate("pw")
    try:
        fid = os.urandom(16)
        wrapped = sender.wrap_file_keys(
            file_key=os.urandom(32),
            meta_key=os.urandom(32),
            file_id=fid,
            recipient_pubkey=recipient.x25519_public_key(),
        )
        # Append trailing bytes — must be rejected, not silently ignored.
        with pytest.raises(Exception):
            recipient.unwrap_file_keys(
                wrapped_bundle=wrapped + b"\x00\x00",
                file_id=fid,
                sender_pubkey=sender.ed25519_public_key(),
            )
    finally:
        sender.lock()
        recipient.lock()
