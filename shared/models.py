# LocalCloud - Shared Data Models and Constants
#
# Wire format definitions, protocol constants, and data structures
# used by both server and client. Serialization is CBOR (canonical).
# All structures are versioned for forward compatibility.

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

import cbor2

# ──────────────────────────── Protocol Constants ────────────────────────────

# Protocol version — increment on breaking wire format changes
PROTOCOL_VERSION: int = 1

# Magic bytes identifying a LocalCloud encrypted file
MAGIC: bytes = b"LCLD"

# Chunk size for file encryption (4 MiB)
CHUNK_SIZE: int = 4 * 1024 * 1024  # 4,194,304 bytes

# Padding size classes for metadata blobs (power-of-two buckets)
META_PAD_CLASSES: list[int] = [1024, 4096, 16384, 65536]

# File ID length (128-bit random, 16 bytes)
FILE_ID_LEN: int = 16

# Nonce length for XChaCha20-Poly1305
NONCE_LEN: int = 24

# AEAD tag length for XChaCha20-Poly1305
TAG_LEN: int = 16

# Key length
KEY_LEN: int = 32

# BLAKE2b digest length
BLAKE2B_DIGEST_LEN: int = 32


# ──────────────────────────── Enums ────────────────────────────

class Visibility(IntEnum):
    """File visibility modes for access control."""
    PRIVATE = 0
    SHARED = 1
    PUBLIC = 2


# ──────────────────────────── Data Structures ────────────────────────────

@dataclass
class FileHeader:
    """Self-describing header for an encrypted file.

    Placed at the beginning of the encrypted file stream.
    Authenticated via inclusion in the first chunk's AAD or via
    the signed Merkle root.
    """
    magic: bytes = MAGIC
    version: int = PROTOCOL_VERSION
    file_id: bytes = field(default_factory=lambda: os.urandom(FILE_ID_LEN))
    chunk_size: int = CHUNK_SIZE
    total_chunks: int = 0
    merkle_root: bytes = b""
    signature: bytes = b""  # Ed25519 signature over merkle_root

    def serialize(self) -> bytes:
        """Serialize to canonical CBOR."""
        return cbor2.dumps({
            "magic": self.magic,
            "version": self.version,
            "file_id": self.file_id,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "merkle_root": self.merkle_root,
            "signature": self.signature,
        }, canonical=True)

    @classmethod
    def deserialize(cls, data: bytes) -> "FileHeader":
        """Deserialize from CBOR."""
        obj = cbor2.loads(data)
        return cls(
            magic=obj["magic"],
            version=obj["version"],
            file_id=obj["file_id"],
            chunk_size=obj["chunk_size"],
            total_chunks=obj["total_chunks"],
            merkle_root=obj["merkle_root"],
            signature=obj["signature"],
        )

    def validate(self) -> None:
        """Validate header fields. Raises ProtocolError on failure."""
        from shared.exceptions import ProtocolError
        if self.magic != MAGIC:
            raise ProtocolError("Invalid magic bytes")
        if self.version != PROTOCOL_VERSION:
            raise ProtocolError(
                f"Unsupported protocol version: {self.version}"
            )
        if len(self.file_id) != FILE_ID_LEN:
            raise ProtocolError("Invalid file_id length")
        if self.chunk_size <= 0:
            raise ProtocolError("Invalid chunk_size")
        if self.total_chunks < 0:
            raise ProtocolError("Invalid total_chunks")


@dataclass
class ChunkAAD:
    """Associated Authenticated Data for per-chunk AEAD encryption.

    Binds each chunk to its file, position, and protocol version to
    prevent cross-file substitution and chunk reordering.
    """
    file_id: bytes
    chunk_index: int
    protocol_version: int = PROTOCOL_VERSION
    total_chunks: int = 0

    def serialize(self) -> bytes:
        """Serialize to a deterministic binary format for use as AAD.

        Uses struct packing for compactness and determinism:
        - file_id: 16 bytes
        - chunk_index: 4 bytes (uint32 big-endian)
        - protocol_version: 2 bytes (uint16 big-endian)
        - total_chunks: 4 bytes (uint32 big-endian)
        """
        return struct.pack(
            ">16sIHI",
            self.file_id,
            self.chunk_index,
            self.protocol_version,
            self.total_chunks,
        )


@dataclass
class MetadataBlob:
    """Plaintext metadata blob to be encrypted client-side.

    After encryption, only the encrypted form is sent to the server.
    Server never sees this content.
    """
    owner: str
    visibility: Visibility = Visibility.PRIVATE
    shared_with: list[str] = field(default_factory=list)
    created_at: float = 0.0
    modified_at: float = 0.0
    original_size: int = 0  # Padded — not exact
    blob_ids: list[str] = field(default_factory=list)
    version_number: int = 1

    def serialize(self) -> bytes:
        """Serialize to canonical CBOR."""
        return cbor2.dumps({
            "owner": self.owner,
            "visibility": int(self.visibility),
            "shared_with": self.shared_with,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "original_size": self.original_size,
            "blob_ids": self.blob_ids,
            "version_number": self.version_number,
        }, canonical=True)

    @classmethod
    def deserialize(cls, data: bytes) -> "MetadataBlob":
        """Deserialize from CBOR."""
        obj = cbor2.loads(data)
        return cls(
            owner=obj["owner"],
            visibility=Visibility(obj["visibility"]),
            shared_with=obj.get("shared_with", []),
            created_at=obj.get("created_at", 0.0),
            modified_at=obj.get("modified_at", 0.0),
            original_size=obj.get("original_size", 0),
            blob_ids=obj.get("blob_ids", []),
            version_number=obj.get("version_number", 1),
        )


# Length prefix size for padding scheme (4 bytes, big-endian u32)
_LENGTH_PREFIX_SIZE: int = 4


def pad_to_size_class(data: bytes, size_classes: list[int] | None = None) -> bytes:
    """Pad data to the smallest size class that fits.

    Uses length-prefixed padding: 4-byte big-endian length prefix followed
    by the data and then random padding bytes to reach the target size.

    This avoids PKCS#7 limitations for pad lengths > 255 and provides
    correct round-trip behavior for any data size.

    Format: [4-byte len][data][random padding]
    """
    if size_classes is None:
        size_classes = META_PAD_CLASSES

    # Total needed: 4-byte prefix + data
    needed = _LENGTH_PREFIX_SIZE + len(data)

    target_size = needed
    for sc in sorted(size_classes):
        if sc >= needed:
            target_size = sc
            break
    else:
        # Data is larger than all size classes — pad to next multiple
        # of the largest size class
        largest = size_classes[-1]
        target_size = ((needed // largest) + 1) * largest

    # Build output: length prefix + data + random padding
    pad_len = target_size - needed
    length_prefix = struct.pack(">I", len(data))
    padding = os.urandom(pad_len) if pad_len > 0 else b""
    return length_prefix + data + padding


def unpad(data: bytes) -> bytes:
    """Remove length-prefixed padding.

    Reads the 4-byte big-endian length prefix and extracts exactly
    that many bytes of payload.
    """
    if len(data) < _LENGTH_PREFIX_SIZE:
        raise ValueError("Data too short to contain length prefix")

    original_len = struct.unpack(">I", data[:_LENGTH_PREFIX_SIZE])[0]

    if original_len > len(data) - _LENGTH_PREFIX_SIZE:
        raise ValueError("Invalid length prefix — exceeds available data")

    return data[_LENGTH_PREFIX_SIZE : _LENGTH_PREFIX_SIZE + original_len]
