# LocalCloud - Cryptographic Primitives
#
# AEAD encryption (XChaCha20-Poly1305), BLAKE2b hashing, Merkle tree
# construction, and Argon2id password hashing for server-side use.
#
# Key management (X25519, Ed25519, key wrapping, mlock) is handled
# by the Rust keycore module — NOT this file.

from __future__ import annotations

import hashlib
import os

import argon2
import nacl.exceptions
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

from shared.exceptions import CryptoError, DecryptionError
from shared.models import BLAKE2B_DIGEST_LEN, KEY_LEN, MAX_CHUNKS, NONCE_LEN

# ──────────────────────────── Random Generation ────────────────────────────


def generate_key() -> bytes:
    """Generate a 256-bit random key from OS CSPRNG.

    Aborts if the entropy source fails (os.urandom raises on failure).
    """
    return os.urandom(KEY_LEN)


def generate_nonce() -> bytes:
    """Generate a 192-bit random nonce for XChaCha20-Poly1305.

    192-bit nonces are safe for random generation without tracking —
    collision probability is negligible for any practical number of files.
    """
    return os.urandom(NONCE_LEN)


def generate_file_id() -> bytes:
    """Generate a 128-bit random file identifier."""
    return os.urandom(16)


# ──────────────────────────── AEAD Encryption ────────────────────────────


def encrypt_chunk(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt a chunk using XChaCha20-Poly1305 AEAD.

    Args:
        key: 32-byte encryption key
        nonce: 24-byte nonce (must be unique per key)
        plaintext: data to encrypt
        aad: additional authenticated data (not encrypted, but authenticated)

    Returns:
        ciphertext || 16-byte authentication tag

    Raises:
        CryptoError: on encryption failure
    """
    if len(key) != KEY_LEN:
        raise CryptoError("Key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise CryptoError("Nonce must be 24 bytes")

    try:
        return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    except (nacl.exceptions.CryptoError, TypeError, ValueError) as e:
        # Mirror decrypt_chunk's narrow catch: PyNaCl raises CryptoError on
        # an AEAD failure and TypeError/ValueError on bad argument types or
        # lengths — anything else is a genuine bug and must propagate.
        raise CryptoError("Encryption failed") from e


def decrypt_chunk(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt a chunk using XChaCha20-Poly1305 AEAD.

    Args:
        key: 32-byte encryption key
        nonce: 24-byte nonce used during encryption
        ciphertext: encrypted data with appended 16-byte auth tag
        aad: additional authenticated data (must match encryption)

    Returns:
        plaintext

    Raises:
        DecryptionError: on authentication failure or decryption error
    """
    if len(key) != KEY_LEN:
        raise DecryptionError("Key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise DecryptionError("Nonce must be 24 bytes")

    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)
    except nacl.exceptions.CryptoError as e:
        # Deliberately generic message — don't reveal why decryption failed
        raise DecryptionError("Decryption failed") from e


# ──────────────────────────── Hashing ────────────────────────────


def blake2b_hash(data: bytes, digest_size: int = BLAKE2B_DIGEST_LEN) -> bytes:
    """Compute BLAKE2b hash of data.

    Args:
        data: input bytes
        digest_size: output hash length in bytes (default 32)

    Returns:
        BLAKE2b digest
    """
    h = hashlib.blake2b(data, digest_size=digest_size)
    return h.digest()


# ──────────────────────────── Merkle Tree ────────────────────────────
# Leaves and internal nodes use distinct one-byte tags so that no
# internal-node hash can ever collide with a leaf hash, closing the
# classic Merkle second-preimage surface (CVE-2012-2459 class). Odd
# nodes are hashed with the internal tag instead of promoted raw, so a
# single-element tree and a single-node layer stay distinguishable.

_MERKLE_LEAF_TAG = b"\x00"
_MERKLE_NODE_TAG = b"\x01"


def _leaf_hash(chunk_hash: bytes) -> bytes:
    if len(chunk_hash) != BLAKE2B_DIGEST_LEN:
        raise CryptoError("Merkle leaf input must be exactly digest-sized")
    return blake2b_hash(_MERKLE_LEAF_TAG + chunk_hash)


def _pair_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != BLAKE2B_DIGEST_LEN or len(right) != BLAKE2B_DIGEST_LEN:
        raise CryptoError("Merkle pair inputs must be exactly digest-sized")
    return blake2b_hash(_MERKLE_NODE_TAG + left + right)


def _promote_hash(single: bytes) -> bytes:
    # Explicitly rehash an odd single node under the internal tag so
    # that a promoted layer cannot be confused with a leaf.
    if len(single) != BLAKE2B_DIGEST_LEN:
        raise CryptoError("Merkle promote input must be exactly digest-sized")
    return blake2b_hash(_MERKLE_NODE_TAG + single)


def merkle_root(chunk_hashes: list[bytes]) -> bytes:
    """Compute Merkle root from a list of chunk hashes.

    Uses a binary tree with BLAKE2b and distinct domain tags for leaves
    and internal nodes. Odd nodes are rehashed (not promoted raw).

    Args:
        chunk_hashes: list of BLAKE2b hashes, one per ciphertext chunk

    Returns:
        Merkle root hash (32 bytes)

    Raises:
        CryptoError: if chunk_hashes is empty
    """
    if not chunk_hashes:
        raise CryptoError("Cannot compute Merkle root of empty list")
    if len(chunk_hashes) > MAX_CHUNKS:
        raise CryptoError("Too many chunks for Merkle root")

    level = [_leaf_hash(h) for h in chunk_hashes]
    if len(level) == 1:
        return level[0]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                next_level.append(_pair_hash(level[i], level[i + 1]))
            else:
                next_level.append(_promote_hash(level[i]))
        level = next_level

    return level[0]


# ──────────────────────────── Argon2id (Server-side) ────────────────────────────
# For server-side password hashing (lower cost than client-side).
# Client-side Argon2id is handled in the Rust keycore module.

# Server-side Argon2id parameters (lower than client but still GPU-resistant)
SERVER_ARGON2_MEMORY_COST = 131072  # 128 MiB in KiB
SERVER_ARGON2_TIME_COST = 3
SERVER_ARGON2_PARALLELISM = 1

_password_hasher = argon2.PasswordHasher(
    memory_cost=SERVER_ARGON2_MEMORY_COST,
    time_cost=SERVER_ARGON2_TIME_COST,
    parallelism=SERVER_ARGON2_PARALLELISM,
    type=argon2.Type.ID,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id for server-side storage.

    Returns an encoded hash string containing algorithm, params, salt, and hash.
    """
    return _password_hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against a stored Argon2id hash.

    Uses constant-time comparison internally (via argon2-cffi).
    Returns True only if the password matches the stored hash.

    Returns False for an ordinary password mismatch (VerifyMismatchError)
    so callers cannot distinguish wrong-password from "no such user" by
    exception type. A corrupted or unparseable hash string (InvalidHashError)
    is re-raised as a CryptoError so callers can distinguish data corruption
    from a wrong-password attempt instead of misreading it as authentication
    failure.

    Raises:
        CryptoError: stored hash is structurally invalid.
    """
    try:
        return _password_hasher.verify(stored_hash, password)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.InvalidHashError as e:
        raise CryptoError("Stored password hash is corrupted") from e
    except argon2.exceptions.VerificationError:
        return False
