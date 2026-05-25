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
    DecryptionError,
    SignatureError,
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
