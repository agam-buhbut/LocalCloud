"""Symlink-following protections on blob/staging data paths (SEC-M1).

The server treats its own filesystem as adversarial-adjacent: an attacker
who can plant a symlink inside the blob or staging trees (e.g. via a
separate bug, a shared mount, or a restore-from-backup race) must not be
able to make the server read from or write through that link to a path
outside the data directory.

These tests exercise the two server-side primitives directly — they take
their base directory / target path as explicit arguments, so no Quart app
or DB setup is needed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from server.storage import (
    _read_blob_chunk_nofollow,
    _safe_path,
    _write_file_bytes,
)


def _base(tmp_path: Path) -> str:
    # _safe_path expects a realpath'd base (init_storage realpath's it).
    base = tmp_path / "blobs"
    base.mkdir()
    return os.path.realpath(str(base))


def test_safe_path_allows_plain_components(tmp_path: Path):
    base = _base(tmp_path)
    # Nested, non-symlink components resolve to a path inside base.
    result = _safe_path(base, "deadbeef", "0.bin")
    assert result == os.path.join(base, "deadbeef", "0.bin")


def test_safe_path_rejects_symlink_final_component(tmp_path: Path):
    base = _base(tmp_path)
    outside = tmp_path / "secret_outside"
    outside.write_bytes(b"top secret")
    link = Path(base) / "chunk_link"
    link.symlink_to(outside)
    # A symlink planted as the final component must be rejected even though
    # realpath() would happily resolve it.
    with pytest.raises(ValueError):
        _safe_path(base, "chunk_link")


def test_safe_path_rejects_symlink_intermediate_component(tmp_path: Path):
    base = _base(tmp_path)
    real_dir = Path(base) / "real_dir"
    real_dir.mkdir()
    (real_dir / "0.bin").write_bytes(b"data")
    link_dir = Path(base) / "link_dir"
    link_dir.symlink_to(real_dir, target_is_directory=True)
    # Even when the final component is a plain name, an intermediate
    # symlinked directory component must be rejected.
    with pytest.raises(ValueError):
        _safe_path(base, "link_dir", "0.bin")


def test_safe_path_rejects_symlink_into_base(tmp_path: Path):
    # A symlink that points *back inside* base would pass a naive
    # realpath-containment check, yet it is still a symlink component and
    # must be rejected.
    base = _base(tmp_path)
    real = Path(base) / "real.bin"
    real.write_bytes(b"x")
    link = Path(base) / "inner_link"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        _safe_path(base, "inner_link")


def test_write_file_bytes_does_not_write_through_symlink(tmp_path: Path):
    # Plant a symlink at the destination path pointing to an outside file.
    # _write_file_bytes must replace the symlink with a fresh regular file
    # holding the new bytes — it must NOT clobber the outside target.
    base = _base(tmp_path)
    outside = tmp_path / "outside_target"
    outside.write_bytes(b"ORIGINAL")
    dest = Path(base) / "0.bin"
    dest.symlink_to(outside)

    _write_file_bytes(str(dest), b"NEWDATA")

    # The outside target is untouched (we did not follow the link on write).
    assert outside.read_bytes() == b"ORIGINAL"
    # The destination is now a regular file (not a symlink) with new bytes.
    assert not os.path.islink(str(dest))
    assert dest.read_bytes() == b"NEWDATA"


def test_blob_chunk_read_path_rejects_symlinked_chunk(tmp_path: Path):
    # get_chunk builds chunk_path via _safe_path(_blob_dir, file_id,
    # "<i>.bin") before opening it. A symlink planted at that chunk path is
    # therefore rejected by _safe_path before any read/send_file occurs.
    base = _base(tmp_path)
    file_dir = Path(base) / "abcd"
    file_dir.mkdir()
    outside = tmp_path / "leak_me"
    outside.write_bytes(b"plaintext-leak")
    (file_dir / "0.bin").symlink_to(outside)
    with pytest.raises(ValueError):
        _safe_path(base, "abcd", "0.bin")


def test_read_blob_chunk_nofollow_returns_plain_file_bytes(tmp_path: Path):
    # The actual read helper used by get_chunk returns the bytes of a real
    # (non-symlink) chunk file.
    base = _base(tmp_path)
    file_dir = Path(base) / "abcd"
    file_dir.mkdir()
    chunk = file_dir / "0.bin"
    chunk.write_bytes(b"ciphertext-bytes")

    assert _read_blob_chunk_nofollow(chunk) == b"ciphertext-bytes"


def test_read_blob_chunk_nofollow_rejects_symlinked_chunk(tmp_path: Path):
    # TOCTOU defense: even if a symlink is swapped in at the final chunk
    # component after _safe_path's lstat check, the O_NOFOLLOW open must
    # refuse to follow it. The helper raises FileNotFoundError (ELOOP) and
    # must NOT return the link target's bytes.
    base = _base(tmp_path)
    file_dir = Path(base) / "abcd"
    file_dir.mkdir()
    outside = tmp_path / "leak_me"
    outside.write_bytes(b"plaintext-leak")
    chunk = file_dir / "0.bin"
    chunk.symlink_to(outside)

    with pytest.raises(FileNotFoundError):
        _read_blob_chunk_nofollow(chunk)


def test_read_blob_chunk_nofollow_missing_file(tmp_path: Path):
    # A genuinely absent chunk (ENOENT) maps to FileNotFoundError so the
    # caller returns 404.
    base = _base(tmp_path)
    file_dir = Path(base) / "abcd"
    file_dir.mkdir()

    with pytest.raises(FileNotFoundError):
        _read_blob_chunk_nofollow(file_dir / "0.bin")
