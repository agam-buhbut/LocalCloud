"""Wire-format tests for shared.models.

Focus areas:
- FileHeader round-trip + bounds enforcement
- ChunkAAD: deterministic serialization, file_id length enforcement,
  collision-free across (file_id, chunk_index, total_chunks).
- MetadataBlob: round-trip + strict bounds on attacker-controlled fields.
- pad_to_size_class / unpad round-trip across bucket boundaries.
- _safe_cbor_loads rejects tagged values (no semantic-type smuggling).
"""

from __future__ import annotations

import os
import struct

import cbor2
import pytest

from shared.exceptions import CryptoError, MalformedRequestError, ProtocolError
from shared.models import (
    CHUNK_SIZE,
    FILE_ID_LEN,
    MAX_HEADER_BYTES,
    MAX_METADATA_BYTES,
    META_PAD_CLASSES,
    PROTOCOL_VERSION,
    ChunkAAD,
    FileHeader,
    MetadataBlob,
    Visibility,
    _safe_cbor_loads,
    pad_to_size_class,
    unpad,
)

# ──────────────────────────── FileHeader ────────────────────────────


def _valid_header() -> FileHeader:
    return FileHeader(
        file_id=os.urandom(FILE_ID_LEN),
        chunk_size=CHUNK_SIZE,
        total_chunks=3,
        merkle_root=os.urandom(32),
        signature=os.urandom(64),
    )


def test_file_header_roundtrip():
    header = _valid_header()
    decoded = FileHeader.deserialize(header.serialize())
    assert decoded.file_id == header.file_id
    assert decoded.merkle_root == header.merkle_root
    assert decoded.signature == header.signature
    assert decoded.chunk_size == header.chunk_size
    assert decoded.total_chunks == header.total_chunks
    assert decoded.version == PROTOCOL_VERSION


def test_file_header_oversize_rejected():
    # Build a CBOR map larger than MAX_HEADER_BYTES — should bounce
    # before the parser walks the structure.
    huge = b"X" * (MAX_HEADER_BYTES + 64)
    with pytest.raises(MalformedRequestError):
        FileHeader.deserialize(huge)


def test_file_header_missing_field_rejected():
    payload = cbor2.dumps({"magic": b"LCLD", "version": 1})
    with pytest.raises(MalformedRequestError):
        FileHeader.deserialize(payload)


def test_file_header_validate_bad_magic():
    header = _valid_header()
    header.magic = b"NOPE"
    with pytest.raises(ProtocolError):
        header.validate()


def test_file_header_validate_bad_chunk_size():
    header = _valid_header()
    header.chunk_size = 0
    with pytest.raises(ProtocolError):
        header.validate()


# ──────────────────────────── ChunkAAD ────────────────────────────


def test_chunk_aad_is_deterministic():
    fid = os.urandom(FILE_ID_LEN)
    a = ChunkAAD(file_id=fid, chunk_index=7, total_chunks=11).serialize()
    b = ChunkAAD(file_id=fid, chunk_index=7, total_chunks=11).serialize()
    assert a == b


def test_chunk_aad_collision_free_across_fields():
    fid = os.urandom(FILE_ID_LEN)
    base = ChunkAAD(file_id=fid, chunk_index=0, total_chunks=2).serialize()
    diff_idx = ChunkAAD(file_id=fid, chunk_index=1, total_chunks=2).serialize()
    diff_total = ChunkAAD(file_id=fid, chunk_index=0, total_chunks=3).serialize()
    other_fid = os.urandom(FILE_ID_LEN)
    diff_fid = ChunkAAD(file_id=other_fid, chunk_index=0, total_chunks=2).serialize()
    assert base != diff_idx
    assert base != diff_total
    assert base != diff_fid


def test_chunk_aad_rejects_wrong_file_id_length():
    short_fid = b"\x00" * (FILE_ID_LEN - 1)
    with pytest.raises(CryptoError):
        ChunkAAD(file_id=short_fid, chunk_index=0, total_chunks=1).serialize()


def test_chunk_aad_metadata_index_is_outside_max_chunks():
    # The encryptor uses 0xFFFFFFFF as the metadata sentinel index. This
    # must NOT collide with any legitimate chunk index, which are
    # bounded by MAX_CHUNKS in shared.models. (#25)
    from shared.models import MAX_CHUNKS

    assert MAX_CHUNKS < 0xFFFFFFFF


# ──────────────────────────── MetadataBlob ────────────────────────────


def _valid_metadata() -> MetadataBlob:
    return MetadataBlob(
        owner="alice",
        visibility=Visibility.PRIVATE,
        shared_with=["bob"],
        created_at=1.0,
        modified_at=1.0,
        original_size=4096,
        blob_ids=[],
        version_number=1,
    )


def test_metadata_roundtrip():
    md = _valid_metadata()
    decoded = MetadataBlob.deserialize(md.serialize())
    assert decoded.owner == "alice"
    assert decoded.visibility == Visibility.PRIVATE
    assert decoded.shared_with == ["bob"]
    assert decoded.original_size == 4096


def test_metadata_oversize_rejected():
    huge = b"X" * (MAX_METADATA_BYTES + 64)
    with pytest.raises(MalformedRequestError):
        MetadataBlob.deserialize(huge)


def test_metadata_rejects_tagged_cbor():
    # CBOR tag 0 = datetime string. Our deserializer must refuse all
    # tagged values regardless of which tag (Finding: tag-smuggling).
    payload = cbor2.dumps(
        {"owner": "x", "visibility": 0, "ts": cbor2.CBORTag(0, "2024-01-01")}
    )
    with pytest.raises(MalformedRequestError):
        MetadataBlob.deserialize(payload)


def test_metadata_rejects_overlong_owner():
    md_dict = {
        "owner": "x" * 1024,
        "visibility": 0,
        "shared_with": [],
        "created_at": 0.0,
        "modified_at": 0.0,
        "original_size": 0,
        "blob_ids": [],
        "version_number": 1,
    }
    payload = cbor2.dumps(md_dict)
    with pytest.raises(MalformedRequestError):
        MetadataBlob.deserialize(payload)


# ──────────────────────────── Padding ────────────────────────────


@pytest.mark.parametrize(
    "size",
    [0, 1, 100, 500, 1000, 1020, 1024, 1025, 4096, 16383, 65535, 70000],
)
def test_pad_unpad_roundtrip(size: int):
    original = os.urandom(size)
    padded = pad_to_size_class(original)
    assert unpad(padded) == original


def test_pad_lands_on_bucket():
    # For sizes ≤ largest bucket, padded length must be exactly the
    # bucket size.
    largest = META_PAD_CLASSES[-1]
    for sc in META_PAD_CLASSES:
        # Use a size that needs exactly this bucket
        target_data_size = sc - 4 - 1  # -4 for length prefix, -1 to need this bucket
        if target_data_size < 0:
            continue
        data = b"x" * target_data_size
        padded = pad_to_size_class(data)
        assert len(padded) == sc, f"size_class={sc}, padded={len(padded)}"
    _ = largest


# ──────────────────────────── Safe CBOR ────────────────────────────


def test_safe_cbor_loads_rejects_tag():
    payload = cbor2.dumps(cbor2.CBORTag(0, "2024-01-01T00:00:00Z"))
    with pytest.raises(MalformedRequestError):
        _safe_cbor_loads(payload)


def test_safe_cbor_loads_basic():
    payload = cbor2.dumps({"k": 42})
    assert _safe_cbor_loads(payload) == {"k": 42}


def test_safe_cbor_loads_truncated_input():
    # Truncate a valid encoding mid-payload.
    valid = cbor2.dumps({"a": "hello"})
    with pytest.raises(MalformedRequestError):
        _safe_cbor_loads(valid[: len(valid) - 2])


def test_unpad_truncated_rejected():
    # Length prefix says 1000 bytes but payload only has 4
    bad = struct.pack(">I", 1000) + b"abcd"
    with pytest.raises(ValueError):
        unpad(bad)
