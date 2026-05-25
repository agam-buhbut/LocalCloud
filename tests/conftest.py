"""Shared pytest fixtures.

Kept deliberately small — most tests construct their own state. This
file holds only cross-cutting fixtures (temp directory layout for the
server, deterministic seeds where appropriate, etc.).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the repository root importable so `import server`, `import client`,
# `import shared` resolve when running pytest from the project root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pytest  # noqa: E402  (must come after sys.path mutation)


@pytest.fixture()
def tmp_data_dir(tmp_path: Path) -> Path:
    """Server data directory layout under a fresh tmp_path."""
    (tmp_path / "blobs").mkdir(mode=0o700)
    (tmp_path / "staging").mkdir(mode=0o700)
    return tmp_path


@pytest.fixture()
def session_secret() -> str:
    """256-bit hex session secret meeting validate() bounds."""
    return os.urandom(32).hex()
