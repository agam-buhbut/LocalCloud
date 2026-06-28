# LocalCloud - Shared Data Models and Constants
#
# Wire format definitions, protocol constants, and data structures
# used by both server and client. Serialization is CBOR (canonical).
# All structures are versioned for forward compatibility.

from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import cbor2

# ──────────────────────────── Protocol Constants ────────────────────────────

# Protocol version — increment on breaking wire format changes.
# v2 (CRY-I2 / item 2D): the metadata blob's AAD now binds merkle_root via
# build_metadata_aad, pinning the encrypted metadata to one file version.
# This is a HARD CUTOVER — FileHeader.validate() accepts ONLY version 2;
# there is no v1 compatibility-read path (no version-downgrade oracle).
PROTOCOL_VERSION: int = 2

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

# Ed25519 signature length
ED25519_SIG_LEN: int = 64

# ──────────────────────────── Safety Bounds ────────────────────────────
# Hard caps that gate any deserialization of attacker-controlled bytes.
# Anything larger than these is rejected before parsing, preventing
# resource-exhaustion attacks via crafted CBOR or padded blobs.

# Maximum size of a CBOR-encoded FileHeader (bytes)
MAX_HEADER_BYTES: int = 4096

# Maximum size of a plaintext CBOR-encoded MetadataBlob (bytes)
MAX_METADATA_BYTES: int = 65536

# Maximum chunk size accepted in a FileHeader (16 MiB — design uses 4 MiB,
# margin left for future formats)
MAX_CHUNK_SIZE: int = 16 * 1024 * 1024

# Wire-format ceiling on the number of chunks the parser will accept
# in a single FileHeader (~1M => up to 16 TiB at 16 MiB).
MAX_CHUNKS: int = 1 << 20

# Operational ceiling on the chunks per file that producers / accepters
# in this build are willing to handle (~400 GiB at 4 MiB). The wire
# format permits more (MAX_CHUNKS above) for forward compatibility,
# but the actual encryptor + server reject above this value to bound
# memory / disk syscall pressure. Keeping the two consts distinct
# (MAX_CHUNKS vs MAX_CHUNKS_PER_FILE) was the source of the mismatch
# noted in Round-2 LOW-1. (Round-3 fix)
MAX_CHUNKS_PER_FILE: int = 100_000

# Sentinel chunk_index used in the metadata blob's AAD (the metadata is
# AEAD-encrypted independently of the data chunks). It is the maximum u32
# value, deliberately chosen to sit above every legitimate chunk index so
# it can never alias a real chunk's AAD. See the invariant assertion
# below the safety bounds.
METADATA_CHUNK_INDEX: int = 0xFFFFFFFF

# Maximum size for a padded metadata blob (1 MiB). Anything larger is
# unreasonable for metadata and likely indicates abuse or a bug.
MAX_PADDED_SIZE: int = 1 << 20

# Per-string length bound used for metadata fields (owner, shared_with
# entries, blob_ids).
_MAX_META_STR_LEN: int = 256

# Domain separation tag for Merkle-root signatures. Bumped to v2 when
# the signing input was expanded to cover the full FileHeader (not just
# merkle_root) so v1 signatures cannot replay against v2 verifiers.
MERKLE_SIG_CONTEXT: bytes = b"localcloud-merkle-v2"

# Domain separation tag for the metadata blob's AEAD AAD (item 2D). The
# "v2" tracks PROTOCOL_VERSION 2: a metadata blob sealed under this tag can
# never verify under any other domain (the data-chunk ChunkAAD or a future
# version), so the data-vs-metadata separation the v1 sentinel index
# provided is now carried by the domain tag instead.
METADATA_AAD_CONTEXT: bytes = b"localcloud-meta-aad-v2"


def build_merkle_signing_input(
    file_id: bytes,
    merkle_root: bytes,
    chunk_size: int = 0,
    total_chunks: int = 0,
    protocol_version: int = 0,
) -> bytes:
    """Build the message signed for a file's Merkle root.

    Format::

        MERKLE_SIG_CONTEXT
            || file_id (16 bytes)
            || merkle_root (32 bytes)
            || chunk_size (8 bytes, big-endian u64)
            || total_chunks (8 bytes, big-endian u64)
            || protocol_version (2 bytes, big-endian u16)

    Each field is fixed-length, so the encoding is unambiguous and
    collision-free across fields. The chunk_size / total_chunks /
    protocol_version bindings ensure a hostile server cannot present a
    header with mutated fields under a stale signature — earlier versions
    covered only merkle_root, which caught most attacks indirectly via
    per-chunk AAD but left a gap for new header fields. (Round-2 H3/H12)
    """
    if len(file_id) != FILE_ID_LEN:
        raise ValueError("file_id must be 16 bytes")
    if len(merkle_root) != BLAKE2B_DIGEST_LEN:
        raise ValueError("merkle_root must be 32 bytes")
    if chunk_size < 0 or chunk_size > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("chunk_size out of range")
    if total_chunks < 0 or total_chunks > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("total_chunks out of range")
    if protocol_version < 0 or protocol_version > 0xFFFF:
        raise ValueError("protocol_version out of range")
    return (
        MERKLE_SIG_CONTEXT
        + file_id
        + merkle_root
        + struct.pack(">QQH", chunk_size, total_chunks, protocol_version)
    )


def build_metadata_aad(
    file_id: bytes,
    merkle_root: bytes,
    protocol_version: int,
) -> bytes:
    """Build the AAD that binds the encrypted metadata blob to one file version.

    Format::

        METADATA_AAD_CONTEXT
            || file_id (16 bytes)
            || merkle_root (32 bytes)
            || protocol_version (2 bytes, big-endian u16)

    Including ``merkle_root`` pins the metadata blob to exactly the file
    version whose chunk set produces that root: a hostile server can no
    longer pair version-N's metadata with version-M's chunks/header for the
    same ``file_id`` (item 2D / CRY-I2). ``merkle_root`` is the right binder
    because it is the file's unique chunk-set fingerprint and is already what
    the Ed25519 signature covers; the signature itself is intentionally NOT
    in the AAD (it is over the root, so it adds no information).

    The domain tag ``METADATA_AAD_CONTEXT`` is the SOLE data-chunk-vs-metadata
    separator in the shipped AAD: ``build_metadata_aad`` uses only the context
    tag (a metadata blob and a chunk AAD can never collide — different lengths,
    content, and keys). ``METADATA_CHUNK_INDEX`` is NOT fed into the metadata
    AAD; it survives only as the import-time tripwire asserting the u32 ChunkAAD
    packing invariant (asserted at module load). The ``protocol_version`` field
    additionally forces non-interoperability on a future bump (defense in depth).
    The u16 width matches ``FileHeader.version``. (pentest 2026-06-28: corrected
    the prior "both mechanisms are live" claim — only the context tag is
    load-bearing for metadata/chunk separation.)

    Raises:
        ValueError: ``file_id`` is not ``FILE_ID_LEN`` bytes, ``merkle_root``
            is not ``BLAKE2B_DIGEST_LEN`` bytes, or ``protocol_version`` is
            outside the u16 range.
    """
    if len(file_id) != FILE_ID_LEN:
        raise ValueError("file_id must be 16 bytes")
    if len(merkle_root) != BLAKE2B_DIGEST_LEN:
        raise ValueError("merkle_root must be 32 bytes")
    if protocol_version < 0 or protocol_version > 0xFFFF:
        raise ValueError("protocol_version out of range")
    return (
        METADATA_AAD_CONTEXT
        + file_id
        + merkle_root
        + struct.pack(">H", protocol_version)
    )


# ──────────────────────────── Safe CBOR Decode ────────────────────────────


def _reject_tag(decoder: Any, tag: Any, shareable_index: Any = None) -> None:
    """Tag hook that refuses any CBOR tagged value the decoder hands us.

    This catches unknown tags only — cbor2 transparently decodes a set
    of well-known tags (datetime, Decimal, Fraction, UUID, …) into
    semantic Python objects before this hook fires. The post-decode
    type whitelist in ``_safe_cbor_loads`` rejects those too.
    """
    from shared.exceptions import MalformedRequestError

    raise MalformedRequestError("Unexpected CBOR tag in serialized payload")


# Types we accept from a CBOR decode. Anything else (datetime, Decimal,
# Fraction, UUID, set, frozenset, CBORTag, …) means a tag was present in
# the input — none of LocalCloud's wire formats use them, so they
# indicate attacker-controlled data and must be rejected.
_ALLOWED_CBOR_TYPES = (bool, int, float, str, bytes, bytearray, list, dict, type(None))


# Max recursion depth when type-checking decoded CBOR. Each nesting
# level costs at least one CBOR byte, so for the 64-KiB metadata cap
# and 4-KiB header cap, 64 is comfortably above any legitimate depth
# while still catching an attacker who hand-crafts a deeply nested
# payload to blow Python's recursion limit (Round-3 LOW-2).
_MAX_CBOR_WALK_DEPTH: int = 64


def _walk_safe(obj: Any, depth: int = 0) -> None:
    """Recursively assert that ``obj`` contains only whitelisted types.

    Raises ``MalformedRequestError`` on any type outside the whitelist
    or if recursion exceeds ``_MAX_CBOR_WALK_DEPTH``. Walks dict keys +
    values and list items.
    """
    from shared.exceptions import MalformedRequestError

    if depth > _MAX_CBOR_WALK_DEPTH:
        raise MalformedRequestError("CBOR payload nesting exceeds depth limit")
    if not isinstance(obj, _ALLOWED_CBOR_TYPES):
        raise MalformedRequestError(
            f"Unexpected CBOR type in payload: {type(obj).__name__}"
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_safe(k, depth + 1)
            _walk_safe(v, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _walk_safe(item, depth + 1)


def _safe_cbor_loads(data: bytes) -> Any:
    """Decode CBOR with tagged values rejected.

    Strategy:
    1. tag_hook rejects any unknown tag at decode time.
    2. The decoded value is recursively type-checked against an explicit
       whitelist to reject *known* tags that cbor2 transparently turns
       into rich Python objects (datetime, Decimal, UUID, etc.).

    All decode failures (truncation, unsupported types, tag-bearing
    content) surface as ``MalformedRequestError`` so callers handle them
    uniformly.
    """
    from shared.exceptions import MalformedRequestError

    try:
        decoder = cbor2.CBORDecoder(io.BytesIO(data), tag_hook=_reject_tag)
        value = decoder.decode()
    except MalformedRequestError:
        raise
    except (
        cbor2.CBORDecodeError,
        KeyError,
        TypeError,
        ValueError,
        # The pure-Python cbor2 decoder recurses in Python and can raise
        # RecursionError on attacker-crafted deep nesting that is still
        # under the size cap (the C decoder raises CBORDecodeError instead);
        # map it to MalformedRequestError so it never escapes uncaught.
        RecursionError,
    ) as e:
        raise MalformedRequestError("Malformed CBOR payload") from e

    _walk_safe(value)
    return value


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
        return cbor2.dumps(
            {
                "magic": self.magic,
                "version": self.version,
                "file_id": self.file_id,
                "chunk_size": self.chunk_size,
                "total_chunks": self.total_chunks,
                "merkle_root": self.merkle_root,
                "signature": self.signature,
            },
            canonical=True,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> FileHeader:
        """Deserialize from CBOR, with strict bounds and type checks.

        Refuses input larger than ``MAX_HEADER_BYTES``, any tagged CBOR
        value, missing fields, or fields of unexpected types. The
        constructed header is then ``validate()``-ed before returning.

        Raises:
            MalformedRequestError: input is over-sized, malformed,
                contains unexpected CBOR tags, or fails type/structural
                validation.
        """
        from shared.exceptions import MalformedRequestError, ProtocolError

        if len(data) > MAX_HEADER_BYTES:
            raise MalformedRequestError("FileHeader payload exceeds size cap")

        obj = _safe_cbor_loads(data)
        if not isinstance(obj, dict):
            raise MalformedRequestError("FileHeader payload is not a map")

        try:
            magic = obj["magic"]
            version = obj["version"]
            file_id = obj["file_id"]
            chunk_size = obj["chunk_size"]
            total_chunks = obj["total_chunks"]
            merkle_root = obj["merkle_root"]
            signature = obj["signature"]
        except KeyError as e:
            raise MalformedRequestError("FileHeader missing field") from e

        if not isinstance(magic, (bytes, bytearray)):
            raise MalformedRequestError("FileHeader.magic must be bytes")
        if not isinstance(version, int) or isinstance(version, bool):
            raise MalformedRequestError("FileHeader.version must be int")
        if not isinstance(file_id, (bytes, bytearray)):
            raise MalformedRequestError("FileHeader.file_id must be bytes")
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
            raise MalformedRequestError("FileHeader.chunk_size must be int")
        if not isinstance(total_chunks, int) or isinstance(total_chunks, bool):
            raise MalformedRequestError("FileHeader.total_chunks must be int")
        if not isinstance(merkle_root, (bytes, bytearray)):
            raise MalformedRequestError("FileHeader.merkle_root must be bytes")
        if not isinstance(signature, (bytes, bytearray)):
            raise MalformedRequestError("FileHeader.signature must be bytes")

        header = cls(
            magic=bytes(magic),
            version=version,
            file_id=bytes(file_id),
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            merkle_root=bytes(merkle_root),
            signature=bytes(signature),
        )
        try:
            header.validate()
        except ProtocolError as e:
            # validate() only ever raises ProtocolError; narrowing the catch
            # keeps a genuine non-ProtocolError bug from being silently
            # relabelled as a malformed-input error.
            raise MalformedRequestError("FileHeader failed validation") from e
        return header

    def validate(self) -> None:
        """Validate header fields. Raises ProtocolError on failure."""
        from shared.exceptions import ProtocolError

        if self.magic != MAGIC:
            raise ProtocolError("Invalid magic bytes")
        if self.version != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {self.version}")
        if len(self.file_id) != FILE_ID_LEN:
            raise ProtocolError("Invalid file_id length")
        if self.chunk_size <= 0 or self.chunk_size > MAX_CHUNK_SIZE:
            raise ProtocolError("Invalid chunk_size")
        # total_chunks must be >= 1 — a zero-chunk file is meaningless
        # and would let a hostile owner-signer ship a header that the
        # client's loop body never executes (no AEAD verification),
        # leaving Merkle compute with an empty list. (Round-9 I2)
        if self.total_chunks < 1 or self.total_chunks > MAX_CHUNKS:
            raise ProtocolError("Invalid total_chunks")
        if len(self.merkle_root) != BLAKE2B_DIGEST_LEN:
            raise ProtocolError("Invalid merkle_root length")
        # signature may be empty (unsigned placeholder during construction)
        # or exactly Ed25519's 64 bytes; anything else is malformed.
        if len(self.signature) not in (0, ED25519_SIG_LEN):
            raise ProtocolError("Invalid signature length")


# Wire-format width invariant for ChunkAAD (CRY-M1 / ARCH-L5).
#
# ChunkAAD.serialize() packs chunk_index and total_chunks as big-endian
# u32 (">16sIHI"). The controller chose to KEEP the u32 packing (option
# (b)): widening to u64 is a breaking wire change deferred to a protocol
# bump. The packing is sound only while BOTH of the following hold, so we
# bind them here as a hard module-load assertion rather than leaving the
# relationship implicit and reviewer-checked:
#   1. MAX_CHUNKS < 2**32 — every legitimate chunk index/count produced or
#      accepted by this build fits in the u32 field with no truncation.
#   2. METADATA_CHUNK_INDEX (0xFFFFFFFF) > MAX_CHUNKS — the metadata
#      sentinel index sits strictly above every real chunk index, so the
#      metadata AAD can never alias a data-chunk AAD.
# If a future edit widens MAX_CHUNKS past the u32 ceiling without also
# widening the packing, this assertion fails at import time instead of
# silently producing aliasing AADs.
assert MAX_CHUNKS < 2**32, "ChunkAAD packs chunk indices as u32"
assert (
    METADATA_CHUNK_INDEX > MAX_CHUNKS
), "metadata sentinel index must not alias a real chunk index"


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

        Refuses to pack a ``file_id`` whose length is not exactly
        ``FILE_ID_LEN``: ``struct.pack("16s", ...)`` silently NUL-pads or
        truncates, which would let unequal IDs collapse to the same AAD.
        """
        from shared.exceptions import CryptoError

        if len(self.file_id) != FILE_ID_LEN:
            raise CryptoError(f"file_id must be exactly {FILE_ID_LEN} bytes")
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
    original_size: int = (
        0  # exact plaintext size; encrypted in the blob, never sent in clear.
    )
    blob_ids: list[str] = field(default_factory=list)
    # RESERVED forward-compat placeholder — NOT a security control. Always
    # written as 1 and never compared. It carries NO rollback/replay meaning:
    # a hostile server can serve any older, validly-signed file version and it
    # verifies. Do NOT gate acceptance on this field without a signed monotonic
    # anchor AND a persistent client-side high-water mark (e.g. reusing the
    # download owner-pin store). See the threat model's "Accepted limitations".
    version_number: int = 1

    def serialize(self) -> bytes:
        """Serialize to canonical CBOR."""
        return cbor2.dumps(
            {
                "owner": self.owner,
                "visibility": int(self.visibility),
                "shared_with": self.shared_with,
                "created_at": self.created_at,
                "modified_at": self.modified_at,
                "original_size": self.original_size,
                "blob_ids": self.blob_ids,
                "version_number": self.version_number,
            },
            canonical=True,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> MetadataBlob:
        """Deserialize from CBOR, with strict bounds and type checks.

        Refuses input larger than ``MAX_METADATA_BYTES``, any tagged CBOR
        value, fields of unexpected types, and over-long strings or list
        entries that could be used for memory amplification.

        Raises:
            MalformedRequestError: input is over-sized, malformed, contains
                unexpected CBOR tags, or fails type/structural validation.
        """
        from shared.exceptions import MalformedRequestError

        if len(data) > MAX_METADATA_BYTES:
            raise MalformedRequestError("MetadataBlob payload exceeds size cap")

        obj = _safe_cbor_loads(data)
        if not isinstance(obj, dict):
            raise MalformedRequestError("MetadataBlob payload is not a map")

        try:
            owner = obj["owner"]
            visibility_raw = obj["visibility"]
        except KeyError as e:
            raise MalformedRequestError("MetadataBlob missing field") from e

        shared_with = obj.get("shared_with", [])
        created_at = obj.get("created_at", 0.0)
        modified_at = obj.get("modified_at", 0.0)
        original_size = obj.get("original_size", 0)
        blob_ids = obj.get("blob_ids", [])
        version_number = obj.get("version_number", 1)

        if not isinstance(owner, str):
            raise MalformedRequestError("MetadataBlob.owner must be str")
        if len(owner) > _MAX_META_STR_LEN:
            raise MalformedRequestError("MetadataBlob.owner too long")
        if not isinstance(visibility_raw, int) or isinstance(visibility_raw, bool):
            raise MalformedRequestError("MetadataBlob.visibility must be int")
        if not isinstance(shared_with, list):
            raise MalformedRequestError("MetadataBlob.shared_with must be list")
        for item in shared_with:
            if not isinstance(item, str) or len(item) > _MAX_META_STR_LEN:
                raise MalformedRequestError(
                    "MetadataBlob.shared_with entries must be short strings"
                )
        if not isinstance(created_at, (int, float)) or isinstance(created_at, bool):
            raise MalformedRequestError("MetadataBlob.created_at must be a number")
        if not isinstance(modified_at, (int, float)) or isinstance(modified_at, bool):
            raise MalformedRequestError("MetadataBlob.modified_at must be a number")
        if not isinstance(original_size, int) or isinstance(original_size, bool):
            raise MalformedRequestError("MetadataBlob.original_size must be int")
        if not isinstance(blob_ids, list):
            raise MalformedRequestError("MetadataBlob.blob_ids must be list")
        for item in blob_ids:
            if not isinstance(item, str) or len(item) > _MAX_META_STR_LEN:
                raise MalformedRequestError(
                    "MetadataBlob.blob_ids entries must be short strings"
                )
        if not isinstance(version_number, int) or isinstance(version_number, bool):
            raise MalformedRequestError("MetadataBlob.version_number must be int")
        # NB: version_number is a reserved placeholder with NO security
        # meaning (see the field definition). It is type-checked here but is
        # attacker-controlled and unsigned beyond per-version integrity — never
        # use it for a rollback/replay decision without a signed anchor.

        try:
            visibility = Visibility(visibility_raw)
        except ValueError as e:
            raise MalformedRequestError(
                "MetadataBlob.visibility is not a known Visibility value"
            ) from e

        return cls(
            owner=owner,
            visibility=visibility,
            shared_with=list(shared_with),
            created_at=float(created_at),
            modified_at=float(modified_at),
            original_size=original_size,
            blob_ids=list(blob_ids),
            version_number=version_number,
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

    Raises:
        PaddingError: if the prefix is missing or claims more bytes than
            are present. ``PaddingError`` subclasses ``ValueError`` so the
            historical ``except ValueError`` / ``pytest.raises(ValueError)``
            contract still holds.
    """
    # Local import mirrors the other shared.exceptions uses in this module
    # (avoids a module-level import cycle).
    from shared.exceptions import PaddingError

    if len(data) < _LENGTH_PREFIX_SIZE:
        raise PaddingError("Data too short to contain length prefix")

    original_len = struct.unpack(">I", data[:_LENGTH_PREFIX_SIZE])[0]

    if original_len > len(data) - _LENGTH_PREFIX_SIZE:
        raise PaddingError("Invalid length prefix — exceeds available data")

    return data[_LENGTH_PREFIX_SIZE : _LENGTH_PREFIX_SIZE + original_len]
