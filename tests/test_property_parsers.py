"""Fuzz / property tests for the wire-format parsers (SEC-GAP).

Targets the three attacker-reachable decoders in ``shared.models``:

* ``_safe_cbor_loads`` — the hardened CBOR front door
* ``FileHeader.deserialize``
* ``MetadataBlob.deserialize``

A hostile storage server controls every byte these see. The contract is
binary: a decoder either returns a value / dataclass, or raises the
library's declared malformed-input exception. It must NEVER crash with an
unexpected exception type (e.g. ``struct.error``, ``RecursionError``,
``MemoryError``, ``KeyError``, ``OverflowError``) and must never hang or
return a half-built object.

The declared exception set is ``{MalformedRequestError}`` (a
``ProtocolError`` subclass). ``_DECLARED`` pins it so the test fails if a
new uncaught exception type ever leaks out of a decoder.

Inputs are driven by hypothesis: raw random bytes, deliberately oversized
bytes (past the size caps), arbitrary *valid* CBOR structures, and
CBOR-tagged payloads (both unknown tags and the well-known tags cbor2
auto-decodes into rich Python objects). Each branch is a real regression
guard — break a bounds check or a type check and the affected case starts
raising the wrong exception.
"""

from __future__ import annotations

from typing import Any

import cbor2
import pytest
from hypothesis import given
from hypothesis import strategies as st

from shared.exceptions import MalformedRequestError
from shared.models import (
    MAX_HEADER_BYTES,
    MAX_METADATA_BYTES,
    FileHeader,
    MetadataBlob,
    _safe_cbor_loads,
)

# The ONLY exception any of these decoders is permitted to raise on bad
# input. Anything else (struct.error, RecursionError, OverflowError,
# MemoryError, KeyError, ValueError, …) is a parser bug.
_DECLARED = MalformedRequestError


def _assert_safe(fn: Any, data: bytes) -> None:
    """fn(data) either returns, or raises exactly the declared exception.

    Any other exception type fails the test, surfacing the offending
    type/message so the regression is actionable.
    """
    try:
        fn(data)
    except _DECLARED:
        return
    except BaseException as exc:  # noqa: BLE001 — that's the whole point
        raise AssertionError(
            f"{getattr(fn, '__qualname__', fn)} raised undeclared "
            f"{type(exc).__name__}: {exc!r} on {data!r}"
        ) from exc


# ──────────────────────────── Input strategies ────────────────────────────

# JSON-ish CBOR-encodable Python values: the recursive structure cbor2
# will happily round-trip. Feeding decoder-built bytes back into the
# decoders exercises the "valid CBOR, wrong shape" surface.
_cbor_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**70), max_value=2**70)
    | st.floats(allow_nan=True, allow_infinity=True)
    | st.text(max_size=64)
    | st.binary(max_size=64),
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(st.text(max_size=16) | st.integers(), children, max_size=8),
    max_leaves=40,
)


@st.composite
def _encoded_cbor(draw: st.DrawFn) -> bytes:
    """Bytes of a freshly cbor2-encoded arbitrary value."""
    value = draw(_cbor_values)
    try:
        return cbor2.dumps(value, canonical=True)
    except (ValueError, OverflowError, RecursionError):
        # A handful of float/int corner cases aren't canonical-encodable;
        # fall back to a trivially valid encoding rather than discarding.
        return cbor2.dumps(None)


@st.composite
def _tagged_cbor(draw: st.DrawFn) -> bytes:
    """Bytes carrying a CBOR tag — the case the type-whitelist guards.

    Mixes arbitrary unknown tag numbers with the well-known tags cbor2
    transparently decodes (0/1 datetime, 2/3 bignum, 4 decimal, 37 UUID),
    since those bypass the tag_hook and must be caught post-decode. Some
    tags (2/3 bignum, 55799 self-describe) legitimately decode to a
    whitelisted type and are *accepted*; this strategy therefore feeds
    the succeed-or-reject ``_assert_safe`` contract, not strict rejection.
    """
    tag_num = draw(
        st.sampled_from([0, 1, 2, 3, 4, 30, 37, 55799])
        | st.integers(min_value=0, max_value=2**32)
    )
    payload = draw(
        st.text(max_size=16)
        | st.binary(max_size=16)
        | st.integers(min_value=0, max_value=2**32)
        | st.lists(st.integers(min_value=0, max_value=255), max_size=8)
    )
    try:
        return cbor2.dumps(cbor2.CBORTag(int(tag_num), payload))
    except (ValueError, OverflowError, TypeError):
        return cbor2.dumps(cbor2.CBORTag(9999, b"x"))


# Tag numbers that MUST be rejected: rich semantic objects (datetime,
# epoch, decimal, fraction, uuid) plus a spread of "unknown" application
# tags. Deliberately excludes the tags cbor2 decodes transparently to a
# whitelisted value — 2/3 (bignum -> int), 55799 (self-describe), and the
# stringref / shareable namespace tags 28/29/256/257 (which pass small
# payloads straight through). Those are covered by the looser
# succeed-or-reject ``_tagged_cbor`` test above; this set is the strict
# anti-tag-injection guard.
_REJECTABLE_TAGS = [0, 1, 4, 5, 6, 30, 37, 100, 1000, 12345, 0xDEAD, 0xFFFF, 999999]


# ──────────────────────────── _safe_cbor_loads ────────────────────────────


@given(data=st.binary(max_size=512))
def test_safe_cbor_loads_random_bytes(data: bytes) -> None:
    _assert_safe(_safe_cbor_loads, data)


@given(data=_encoded_cbor())
def test_safe_cbor_loads_valid_cbor(data: bytes) -> None:
    _assert_safe(_safe_cbor_loads, data)


@given(data=_tagged_cbor())
def test_safe_cbor_loads_tagged_cbor(data: bytes) -> None:
    # Tagged input either decodes to a whitelisted scalar (bignum,
    # self-describe) or is rejected — never an undeclared crash.
    _assert_safe(_safe_cbor_loads, data)


@pytest.mark.parametrize("tag_num", _REJECTABLE_TAGS)
def test_safe_cbor_loads_rejects_rich_tags(tag_num: int) -> None:
    """datetime / decimal / fraction / uuid / unknown tags are rejected.

    These are the tag-injection vectors: cbor2 turns the well-known ones
    into rich Python objects that bypass the tag_hook, so the post-decode
    type whitelist is the gate. A non-trivial payload is used so namespace
    tags that pass empty payloads through are not accidentally hit. Each
    MUST raise the declared exception — silent acceptance is the security
    bug this guards.
    """
    data = cbor2.dumps(cbor2.CBORTag(tag_num, b"\x01\x02\x03"))
    with pytest.raises(_DECLARED):
        _safe_cbor_loads(data)


@pytest.mark.parametrize(
    "data",
    [
        cbor2.dumps(cbor2.CBORTag(0, "2020-01-01T00:00:00Z")),  # datetime string
        cbor2.dumps(cbor2.CBORTag(1, 1577836800)),  # epoch datetime
        cbor2.dumps(cbor2.CBORTag(4, [-1, 273])),  # decimal fraction
        cbor2.dumps(cbor2.CBORTag(30, [1, 3])),  # rational
        cbor2.dumps(cbor2.CBORTag(37, b"\x00" * 16)),  # uuid
    ],
)
def test_safe_cbor_loads_rejects_known_rich_objects(data: bytes) -> None:
    """The specific well-known tags cbor2 decodes to rich objects are
    rejected by the post-decode type whitelist."""
    with pytest.raises(_DECLARED):
        _safe_cbor_loads(data)


# ──────────────────────────── FileHeader.deserialize ────────────────────────────


@given(data=st.binary(max_size=512))
def test_fileheader_random_bytes(data: bytes) -> None:
    _assert_safe(FileHeader.deserialize, data)


@given(data=_encoded_cbor())
def test_fileheader_valid_cbor(data: bytes) -> None:
    _assert_safe(FileHeader.deserialize, data)


@given(data=_tagged_cbor())
def test_fileheader_tagged_cbor(data: bytes) -> None:
    _assert_safe(FileHeader.deserialize, data)


def _assert_rejects_oversized(fn: Any, cap: int) -> None:
    """fn must reject any input past ``cap`` with the declared exception.

    Generating 64 KiB+ of random bytes via hypothesis blows the entropy
    budget, and the size gate keys only on *length* (it rejects before
    reading content), so this drives the branch deterministically with
    fixed buffers: raw zero-fill, and an otherwise-valid CBOR map padded
    just past the cap.
    """
    for blob in (
        b"\x00" * (cap + 1),
        b"\x00" * (cap + 257),
        # A real map whose serialization exceeds the cap — proves the gate
        # fires on size, not on un-parseability.
        cbor2.dumps({"pad": b"\x41" * (cap + 16)}, canonical=True),
    ):
        assert len(blob) > cap
        try:
            fn(blob)
        except _DECLARED:
            continue
        except BaseException as exc:  # noqa: BLE001
            raise AssertionError(
                f"{getattr(fn, '__qualname__', fn)} raised undeclared "
                f"{type(exc).__name__} on oversized input ({len(blob)} bytes)"
            ) from exc
        raise AssertionError(f"oversized payload ({len(blob)} bytes) was accepted")


def test_fileheader_oversized() -> None:
    _assert_rejects_oversized(FileHeader.deserialize, MAX_HEADER_BYTES)


# ──────────────────────────── MetadataBlob.deserialize ────────────────────────────


@given(data=st.binary(max_size=512))
def test_metadatablob_random_bytes(data: bytes) -> None:
    _assert_safe(MetadataBlob.deserialize, data)


@given(data=_encoded_cbor())
def test_metadatablob_valid_cbor(data: bytes) -> None:
    _assert_safe(MetadataBlob.deserialize, data)


@given(data=_tagged_cbor())
def test_metadatablob_tagged_cbor(data: bytes) -> None:
    _assert_safe(MetadataBlob.deserialize, data)


def test_metadatablob_oversized() -> None:
    _assert_rejects_oversized(MetadataBlob.deserialize, MAX_METADATA_BYTES)


# ──────────────── Structured near-valid maps (targeted shape fuzz) ────────────────
# Build maps that look like a header/metadata but with each field's type
# drawn from a wrong-type pool, so the per-field isinstance gates are
# actually exercised (random bytes almost never decode to a dict with the
# right keys).

_wrong_typed = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**40), max_value=2**40)
    | st.floats(allow_nan=False, allow_infinity=False, width=32)
    | st.text(max_size=8)
    | st.binary(max_size=8)
    | st.lists(st.integers(min_value=0, max_value=255), max_size=4)
)


@st.composite
def _headerish_map(draw: st.DrawFn) -> bytes:
    keys = [
        "magic",
        "version",
        "file_id",
        "chunk_size",
        "total_chunks",
        "merkle_root",
        "signature",
    ]
    obj = {k: draw(_wrong_typed) for k in keys}
    # Randomly drop some keys to also hit the missing-field path.
    for k in list(obj):
        if draw(st.booleans()):
            del obj[k]
    return cbor2.dumps(obj, canonical=True)


@st.composite
def _metaish_map(draw: st.DrawFn) -> bytes:
    keys = [
        "owner",
        "visibility",
        "shared_with",
        "created_at",
        "modified_at",
        "original_size",
        "blob_ids",
        "version_number",
    ]
    obj = {k: draw(_wrong_typed) for k in keys}
    for k in list(obj):
        if draw(st.booleans()):
            del obj[k]
    return cbor2.dumps(obj, canonical=True)


@given(data=_headerish_map())
def test_fileheader_wrong_typed_fields(data: bytes) -> None:
    _assert_safe(FileHeader.deserialize, data)


@given(data=_metaish_map())
def test_metadatablob_wrong_typed_fields(data: bytes) -> None:
    _assert_safe(MetadataBlob.deserialize, data)


# ──────────────── Deep-nesting recursion DoS (depth-64 walk guard) ────────────────
# CBOR 0x81 = array(1); N copies followed by a leaf is an N-deep nesting.
# A hostile server can hand-craft arbitrarily deep nesting to blow Python's
# C-stack via either the _walk_safe type-checker (capped at depth 64) or
# cbor2's own decoder recursion. Both must surface as MalformedRequestError,
# never RecursionError. The hypothesis ``_cbor_values`` strategy only nests
# ~6 deep, so this deterministic case is what actually exercises the guard.
#
#   200 deep  -> past the _walk_safe depth-64 cap (the post-decode walk)
#   5000 deep -> past cbor2's own decode-time recursion limit
_DEEP_NESTED = [
    b"\x81" * 200 + b"\x00",
    b"\x81" * 5000 + b"\x00",
]


@pytest.mark.parametrize(
    "decoder",
    [_safe_cbor_loads, FileHeader.deserialize, MetadataBlob.deserialize],
)
@pytest.mark.parametrize("data", _DEEP_NESTED)
def test_decoders_reject_deep_nesting(decoder: Any, data: bytes) -> None:
    """Deeply nested CBOR is rejected with the declared exception only.

    Drives each decoder past BOTH recursion limits and asserts the only
    escaping exception type is MalformedRequestError — a RecursionError (or
    any other undeclared type) escaping here would be the DoS bug this
    guards. Removing the depth-64 walk cap makes the 200-deep case escape a
    RecursionError, failing this test.
    """
    with pytest.raises(_DECLARED):
        decoder(data)
