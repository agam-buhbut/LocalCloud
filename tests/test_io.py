"""Tests for shared.io.read_capped (IO-1).

``read_capped`` is the fd-bound, size-capped reader used at the client /
server file boundaries. It must return the full content of a regular file
(looping over short reads), refuse a non-regular path via an fstat on the
open fd, and enforce the byte cap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.io import read_capped


def test_read_capped_returns_full_content(tmp_path: Path) -> None:
    p = tmp_path / "data.bin"
    payload = b"hello-world" * 100  # 1100 bytes — more than one os.read may return
    p.write_bytes(payload)
    assert read_capped(p, cap=4096) == payload


def test_read_capped_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    assert read_capped(p, cap=16) == b""


def test_read_capped_exactly_at_cap(tmp_path: Path) -> None:
    p = tmp_path / "exact.bin"
    payload = b"\xa5" * 64
    p.write_bytes(payload)
    assert read_capped(p, cap=64) == payload


def test_read_capped_rejects_over_cap(tmp_path: Path) -> None:
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x00" * 65)
    with pytest.raises(ValueError):
        read_capped(p, cap=64)


def test_read_capped_refuses_non_regular_file(tmp_path: Path) -> None:
    # A directory is a non-regular file: the fstat(S_ISREG) gate must reject
    # it before any read, regardless of cap.
    d = tmp_path / "subdir"
    d.mkdir()
    with pytest.raises(ValueError):
        read_capped(d, cap=4096)
