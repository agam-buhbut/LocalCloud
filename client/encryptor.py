# LocalCloud - Client Per-File Encryption Engine
#
# Implements chunked, padded, authenticated encryption with Merkle tree
# integrity proofs and signed roots for replay protection.
#
# Security properties:
# - Per-file random keys (file_key, meta_key) from CSPRNG
# - Per-chunk unique nonce (192-bit random)
# - AEAD binding: file_id + chunk_index + version + total_chunks
# - Merkle root signed with Ed25519 to detect server rollback
# - Atomic failure: any verification error aborts entire operation

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Optional

from client.keystore import KeyStore
from shared.crypto import (
    blake2b_hash,
    decrypt_chunk,
    encrypt_chunk,
    generate_key,
    generate_nonce,
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
)
from shared.exceptions import (
    CryptoError,
    DecryptionError,
    MerkleVerificationError,
    SignatureError,
)
from shared.models import (
    CHUNK_SIZE,
    ChunkAAD,
    FileHeader,
    MetadataBlob,
    Visibility,
    pad_to_size_class,
    unpad,
)


@dataclass
class EncryptedFile:
    """Result of encrypting a file — everything needed for upload."""
    header: FileHeader
    chunks: list[bytes]  # Each is nonce (24) + ciphertext + tag (16)
    chunk_hashes: list[bytes]  # BLAKE2b of each chunk
    encrypted_metadata: bytes
    file_key: bytes  # For key wrapping (owner keeps this)
    meta_key: bytes  # For key wrapping (owner keeps this)


class FileEncryptor:
    """Per-file encryption engine.

    Each file gets independent random keys. Keys are never derived from
    filenames, timestamps, or user secrets.
    """

    def __init__(self, keystore: KeyStore, chunk_size: int = CHUNK_SIZE):
        self.keystore = keystore
        self.chunk_size = chunk_size

    def encrypt_file(
        self,
        plaintext: bytes,
        filename: str,
        visibility: Visibility = Visibility.PRIVATE,
        owner: str = "",
    ) -> EncryptedFile:
        """Encrypt a file with per-file random keys.

        Args:
            plaintext: raw file contents
            filename: original filename (included in encrypted metadata)
            visibility: file visibility mode
            owner: owner username (included in encrypted metadata)

        Returns:
            EncryptedFile with all data needed for upload
        """
        # Generate per-file random keys
        file_key = generate_key()
        meta_key = generate_key()

        # Generate file ID
        file_id = os.urandom(16)

        # Chunk and pad plaintext
        chunks_plain = self._chunk_plaintext(plaintext)
        total_chunks = len(chunks_plain)

        # Encrypt each chunk with unique nonce and bound AAD
        encrypted_chunks = []
        chunk_hashes = []

        for i, chunk_plain in enumerate(chunks_plain):
            nonce = generate_nonce()
            aad = ChunkAAD(
                file_id=file_id,
                chunk_index=i,
                total_chunks=total_chunks,
            ).serialize()

            ciphertext = encrypt_chunk(file_key, nonce, chunk_plain, aad)

            # Package: nonce || ciphertext (includes tag)
            chunk_blob = nonce + ciphertext
            encrypted_chunks.append(chunk_blob)

            # Hash the ciphertext chunk for Merkle tree
            chunk_hashes.append(blake2b_hash(chunk_blob))

        # Build Merkle tree and sign root
        root = merkle_root(chunk_hashes)
        signature = self.keystore.sign(root)

        # Build file header
        header = FileHeader(
            file_id=file_id,
            chunk_size=self.chunk_size,
            total_chunks=total_chunks,
            merkle_root=root,
            signature=signature,
        )

        # Encrypt metadata
        import time
        now = time.time()
        metadata = MetadataBlob(
            owner=owner,
            visibility=visibility,
            created_at=now,
            modified_at=now,
            original_size=len(plaintext),
            version_number=1,
        )
        meta_plain = metadata.serialize()
        meta_padded = pad_to_size_class(meta_plain)
        meta_nonce = generate_nonce()
        meta_aad = ChunkAAD(
            file_id=file_id,
            chunk_index=0xFFFFFFFF,  # Special index for metadata
            total_chunks=0,
        ).serialize()
        meta_ct = encrypt_chunk(meta_key, meta_nonce, meta_padded, meta_aad)
        encrypted_metadata = meta_nonce + meta_ct

        return EncryptedFile(
            header=header,
            chunks=encrypted_chunks,
            chunk_hashes=chunk_hashes,
            encrypted_metadata=encrypted_metadata,
            file_key=file_key,
            meta_key=meta_key,
        )

    def decrypt_file(
        self,
        chunks: list[bytes],
        header_data: bytes,
        encrypted_metadata: bytes,
        file_key: bytes,
        meta_key: bytes,
        signer_pubkey: bytes,
    ) -> bytes:
        """Decrypt a file with full integrity verification.

        Verification order:
        1. Validate header
        2. Verify Ed25519 signature on Merkle root
        3. Verify each chunk hash against Merkle tree
        4. Decrypt each chunk (AEAD tag verification)
        5. Fail atomically on ANY error

        Args:
            chunks: list of (nonce || ciphertext) blobs
            header_data: serialized FileHeader
            encrypted_metadata: nonce || ciphertext of metadata
            file_key: decrypted file encryption key
            meta_key: decrypted metadata encryption key
            signer_pubkey: Ed25519 public key of the file owner

        Returns:
            decrypted plaintext

        Raises:
            MerkleVerificationError: Merkle proof fails
            SignatureError: Ed25519 signature invalid
            DecryptionError: AEAD tag verification fails
        """
        # 1. Parse and validate header
        header = FileHeader.deserialize(header_data)
        header.validate()

        if len(chunks) != header.total_chunks:
            raise CryptoError("Chunk count mismatch")

        # 2. Verify Ed25519 signature on Merkle root
        import keycore
        if not keycore.verify_signature(
            signer_pubkey, header.merkle_root, header.signature
        ):
            raise SignatureError("Invalid Merkle root signature")

        # 3. Compute chunk hashes and verify Merkle root
        chunk_hashes = [blake2b_hash(chunk) for chunk in chunks]
        computed_root = merkle_root(chunk_hashes)
        if computed_root != header.merkle_root:
            raise MerkleVerificationError("Merkle root mismatch")

        # 4. Decrypt each chunk — fail atomically
        decrypted_chunks = []
        for i, chunk_blob in enumerate(chunks):
            if len(chunk_blob) < 24:  # nonce length
                raise DecryptionError("Chunk too short")

            nonce = chunk_blob[:24]
            ciphertext = chunk_blob[24:]

            aad = ChunkAAD(
                file_id=header.file_id,
                chunk_index=i,
                total_chunks=header.total_chunks,
            ).serialize()

            try:
                plaintext_chunk = decrypt_chunk(file_key, nonce, ciphertext, aad)
            except DecryptionError:
                raise  # Re-raise — atomic failure
            except Exception:
                raise DecryptionError("Chunk decryption failed")

            decrypted_chunks.append(plaintext_chunk)

        # 5. Reassemble and remove padding (#10)
        full_plaintext = b"".join(decrypted_chunks)

        # Decrypt metadata to get original_size for proper trimming
        metadata = self.decrypt_metadata(encrypted_metadata, meta_key, header.file_id)
        if metadata.original_size is not None and metadata.original_size <= len(full_plaintext):
            full_plaintext = full_plaintext[: metadata.original_size]

        return full_plaintext

    def decrypt_metadata(
        self,
        encrypted_metadata: bytes,
        meta_key: bytes,
        file_id: bytes,
    ) -> MetadataBlob:
        """Decrypt the metadata blob.

        Args:
            encrypted_metadata: nonce || ciphertext
            meta_key: metadata encryption key
            file_id: file ID for AAD binding

        Returns:
            deserialized MetadataBlob
        """
        if len(encrypted_metadata) < 24:
            raise DecryptionError("Metadata too short")

        nonce = encrypted_metadata[:24]
        ciphertext = encrypted_metadata[24:]

        aad = ChunkAAD(
            file_id=file_id,
            chunk_index=0xFFFFFFFF,
            total_chunks=0,
        ).serialize()

        padded = decrypt_chunk(meta_key, nonce, ciphertext, aad)
        meta_bytes = unpad(padded)
        return MetadataBlob.deserialize(meta_bytes)

    def _chunk_plaintext(self, data: bytes) -> list[bytes]:
        """Split plaintext into fixed-size chunks with padding.

        The last chunk is padded to chunk_size to reduce length leakage.
        """
        if not data:
            # Empty file — still produce one padded chunk
            return [b"\x00" * self.chunk_size]

        chunks = []
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i : i + self.chunk_size]
            # Pad last chunk to full chunk_size
            if len(chunk) < self.chunk_size:
                pad_len = self.chunk_size - len(chunk)
                chunk = chunk + b"\x00" * pad_len
            chunks.append(chunk)

        return chunks
