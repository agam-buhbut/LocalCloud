# LocalCloud - Cryptographic Primitives
#
# AEAD encryption (XChaCha20-Poly1305), BLAKE2b hashing, Merkle tree
# construction, and Argon2id password hashing for server-side use.
#
# Key management (X25519, Ed25519, key wrapping, mlock) is handled
# by the Rust keycore module — NOT this file.

from __future__ import annotations

import hashlib
import math
import os

from nacl.aead import XCHACHA20POLY1305_NONCEBYTES
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

from shared.exceptions import CryptoError, DecryptionError, MerkleVerificationError
from shared.models import BLAKE2B_DIGEST_LEN, KEY_LEN, NONCE_LEN

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


def encrypt_chunk(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> bytes:
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
        return crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, key
        )
    except Exception as e:
        raise CryptoError("Encryption failed") from e


def decrypt_chunk(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes
) -> bytes:
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
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, nonce, key
        )
    except Exception:
        # Deliberately generic — don't reveal why decryption failed
        raise DecryptionError("Decryption failed")


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


def merkle_root(chunk_hashes: list[bytes]) -> bytes:
    """Compute Merkle root from a list of chunk hashes.

    Uses a binary tree with BLAKE2b as the internal hash function.
    Leaf nodes are the chunk hashes themselves.
    If the number of leaves is odd, the last leaf is promoted (not duplicated).

    Args:
        chunk_hashes: list of BLAKE2b hashes, one per ciphertext chunk

    Returns:
        Merkle root hash (32 bytes)

    Raises:
        CryptoError: if chunk_hashes is empty
    """
    if not chunk_hashes:
        raise CryptoError("Cannot compute Merkle root of empty list")

    if len(chunk_hashes) == 1:
        return chunk_hashes[0]

    # Build the tree bottom-up
    level = list(chunk_hashes)
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                # Hash pair: H(left || right)
                combined = level[i] + level[i + 1]
                next_level.append(blake2b_hash(combined))
            else:
                # Odd node — promote without duplication
                next_level.append(level[i])
        level = next_level

    return level[0]


def merkle_proof(chunk_hashes: list[bytes], chunk_index: int) -> list[tuple[bytes, bool]]:
    """Generate a Merkle proof for a specific chunk.

    Returns a list of (sibling_hash, is_right) tuples from leaf to root.

    Args:
        chunk_hashes: all chunk hashes
        chunk_index: index of the chunk to prove

    Returns:
        proof path as list of (sibling_hash, is_right_sibling) tuples
    """
    if not chunk_hashes or chunk_index >= len(chunk_hashes):
        raise CryptoError("Invalid chunk index for Merkle proof")

    if len(chunk_hashes) == 1:
        return []

    proof = []
    level = list(chunk_hashes)
    idx = chunk_index

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                combined = level[i] + level[i + 1]
                next_level.append(blake2b_hash(combined))
            else:
                next_level.append(level[i])

        # Record sibling for proof
        if idx % 2 == 0:
            if idx + 1 < len(level):
                proof.append((level[idx + 1], True))  # sibling is on right
        else:
            proof.append((level[idx - 1], False))  # sibling is on left

        idx //= 2
        level = next_level

    return proof


def verify_merkle_proof(
    leaf_hash: bytes,
    proof: list[tuple[bytes, bool]],
    expected_root: bytes,
) -> bool:
    """Verify a Merkle proof against an expected root.

    Args:
        leaf_hash: the hash of the chunk being proved
        proof: proof path from merkle_proof()
        expected_root: the expected Merkle root to verify against

    Returns:
        True if the proof is valid
    """
    current = leaf_hash
    for sibling, is_right in proof:
        if is_right:
            current = blake2b_hash(current + sibling)
        else:
            current = blake2b_hash(sibling + current)
    return current == expected_root


# ──────────────────────────── Argon2id (Server-side) ────────────────────────────
# For server-side password hashing (lower cost than client-side).
# Client-side Argon2id is handled in the Rust keycore module.

import argon2

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
    Returns True if the password matches, False otherwise.
    Never raises on wrong password — only on corrupted hash format.
    """
    try:
        return _password_hasher.verify(stored_hash, password)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.VerificationError:
        return False
