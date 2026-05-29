"""Property tests for the metadata padding scheme.

Covers ``pad_to_size_class`` / ``unpad`` (shared.models). The padding
scheme is length-prefixed: ``[4-byte big-endian len][data][random pad]``
rounded up to the smallest size class that fits. The round-trip MUST be
exact for arbitrary payloads — including empty and sizes that sit right
on a size-class boundary, where an off-by-one in the length prefix or the
target-size selection would silently corrupt or truncate the recovered
data.

These are regression guards: each fails if the prefix width, the
boundary selection, or the unpad slice is broken.
"""

from __future__ import annotations

import struct

from hypothesis import given
from hypothesis import strategies as st

from shared.models import (
    _LENGTH_PREFIX_SIZE,
    META_PAD_CLASSES,
    pad_to_size_class,
    unpad,
)

# Largest size class drives the "over the largest bucket" branch in
# pad_to_size_class; go a little past it so multi-bucket rounding is hit.
_LARGEST_CLASS = max(META_PAD_CLASSES)


@given(data=st.binary(min_size=0, max_size=_LARGEST_CLASS + 5000))
def test_pad_unpad_roundtrips_arbitrary_bytes(data: bytes) -> None:
    """unpad(pad_to_size_class(x)) == x for any payload."""
    padded = pad_to_size_class(data)
    assert unpad(padded) == data


@given(data=st.binary(min_size=0, max_size=_LARGEST_CLASS + 5000))
def test_padded_output_reaches_a_size_class(data: bytes) -> None:
    """Padded length is a declared class (or a multiple of the largest).

    Guards the bucket-selection logic: padded output must never be the
    raw ``needed`` length when a class would fit, and must be a multiple
    of the largest class when the payload overflows every bucket. The
    upper bound runs past the largest class so the overflow ``else`` branch
    (len % _LARGEST_CLASS == 0) is actually exercised, not dead.
    """
    padded = pad_to_size_class(data)
    needed = _LENGTH_PREFIX_SIZE + len(data)
    assert len(padded) >= needed
    if needed <= _LARGEST_CLASS:
        assert len(padded) in META_PAD_CLASSES
    else:
        assert len(padded) % _LARGEST_CLASS == 0


def test_pad_unpad_empty() -> None:
    """Empty payload survives the round-trip and still gets padded."""
    padded = pad_to_size_class(b"")
    assert padded[:_LENGTH_PREFIX_SIZE] == struct.pack(">I", 0)
    assert unpad(padded) == b""
    # Even an empty payload is bucketed to the smallest class so the
    # ciphertext length leaks nothing about "is it empty".
    assert len(padded) == min(META_PAD_CLASSES)


def test_pad_unpad_near_boundary_sizes() -> None:
    """Sizes one below / at / one above each class boundary round-trip.

    The interesting payload sizes are where ``4 + len(data)`` equals a
    class exactly, or is one byte under/over it — classic off-by-one
    territory for the prefix accounting.
    """
    for sc in META_PAD_CLASSES:
        for payload_len in (
            sc - _LENGTH_PREFIX_SIZE - 1,
            sc - _LENGTH_PREFIX_SIZE,
            sc - _LENGTH_PREFIX_SIZE + 1,
        ):
            if payload_len < 0:
                continue
            data = b"\xa5" * payload_len
            padded = pad_to_size_class(data)
            assert unpad(padded) == data
