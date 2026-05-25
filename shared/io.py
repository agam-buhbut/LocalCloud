"""Shared file I/O helpers used by client + server boundaries.

Kept deliberately minimal — one function (``read_capped``) that opens a
file with ``O_RDONLY | O_NOFOLLOW`` and reads at most ``cap + 1`` bytes,
rejecting anything longer. This is the *only* safe way to enforce a
size cap on an attacker-influenced path: ``stat()`` followed by
``read_bytes()`` is TOCTOU (the attacker can swap the file between the
two syscalls).
"""

from __future__ import annotations

import os
from pathlib import Path


def read_capped(path: Path, cap: int) -> bytes:
    """Read up to ``cap`` bytes from ``path`` via a single fd-bound read.

    Raises:
        ValueError: if the file is larger than ``cap`` bytes.
        OSError: on open / read failure (caller decides how to handle).
    """
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        buf = os.read(fd, cap + 1)
    finally:
        os.close(fd)
    if len(buf) > cap:
        raise ValueError(f"File {path.name!r} exceeds {cap}-byte size cap")
    return buf
