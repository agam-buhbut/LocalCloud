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
import stat
from pathlib import Path


def read_capped(path: Path, cap: int) -> bytes:
    """Read up to ``cap`` bytes from ``path`` via an fd-bound read loop.

    Opens with ``O_RDONLY | O_NOFOLLOW`` and ``fstat``s the *open* fd (not
    the path) so the regular-file check and the size cap apply to exactly the
    bytes read — the path is never re-resolved, closing the TOCTOU window a
    ``stat()`` + ``read_bytes()`` pair would leave open.

    Refuses anything that is not a regular file (directory, device, socket):
    those open without blocking but have no meaningful byte length, so the
    ``S_ISREG`` check rejects them after the open. A FIFO is the special case —
    in the default blocking mode ``os.open`` itself blocks until a writer
    appears, so a writer-less FIFO never reaches the ``S_ISREG`` check at all.
    Reads in a loop because a single ``os.read`` may short-read; at most
    ``cap + 1`` bytes are read so an over-cap file is detected and rejected
    rather than silently truncated.

    Raises:
        ValueError: if ``path`` is not a regular file, or its content is
            larger than ``cap`` bytes.
        OSError: on open / fstat / read failure (caller decides how to handle).
    """
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    chunks: list[bytes] = []
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path.name!r} is not a regular file")
        remaining = cap + 1
        while remaining > 0:
            block = os.read(fd, remaining)
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
    finally:
        os.close(fd)
    buf = b"".join(chunks)
    if len(buf) > cap:
        raise ValueError(f"File {path.name!r} exceeds {cap}-byte size cap")
    return buf
