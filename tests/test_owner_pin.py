"""F1: download owner-pubkey TOFU pin (client/cli.py).

The pin enforces cross-download CONSISTENCY of the file owner's Ed25519
signer key against a hostile server: first contact is trusted, any later
substitution of the owner key for a given file is refused fail-closed. A
corrupt/unreadable pin store fails closed rather than silently re-TOFUing.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import cast

import pytest

from client.api_client import CloudClient
from client.cli import (
    _load_owner_pins,
    _owner_pins_path,
    _resolve_owner_pubkey,
    _save_owner_pins,
)
from shared.exceptions import CryptoError

_FID = "ab" * 16  # 32-char canonical hex file id
_PK_A = bytes(range(32))
_PK_B = bytes(range(31, -1, -1))


class _FakeClient:
    """Minimal stand-in exposing only get_owner_pubkey."""

    def __init__(self, pk: bytes | None) -> None:
        self._pk = pk

    def get_owner_pubkey(self, _file_id: str) -> bytes | None:
        return self._pk


def _resolve(client: _FakeClient, file_id: str, override: str | None, pins: dict):
    """Call the production resolver with the fake typed as a CloudClient."""
    return _resolve_owner_pubkey(cast(CloudClient, client), file_id, override, pins)


def test_pin_roundtrip_and_perms(tmp_path: Path) -> None:
    kf = tmp_path / "keys.enc"
    _save_owner_pins(kf, {_FID: _PK_A.hex()})
    assert _load_owner_pins(kf) == {_FID: _PK_A.hex()}
    mode = stat.S_IMODE(_owner_pins_path(kf).stat().st_mode)
    assert mode == 0o600, f"pin store must be 0600, got {oct(mode)}"


def test_missing_store_is_empty(tmp_path: Path) -> None:
    assert _load_owner_pins(tmp_path / "nope.enc") == {}


def test_corrupt_store_fails_closed(tmp_path: Path) -> None:
    kf = tmp_path / "keys.enc"
    _owner_pins_path(kf).write_text("{not valid json", encoding="utf-8")
    with pytest.raises(CryptoError, match="corrupt"):
        _load_owner_pins(kf)


def test_wrong_typed_store_fails_closed(tmp_path: Path) -> None:
    kf = tmp_path / "keys.enc"
    _owner_pins_path(kf).write_text(json.dumps({_FID: 5}), encoding="utf-8")
    with pytest.raises(CryptoError, match="malformed"):
        _load_owner_pins(kf)


def test_oversized_store_fails_closed(tmp_path: Path) -> None:
    kf = tmp_path / "keys.enc"
    _owner_pins_path(kf).write_text("x" * (1 << 20) + "yyyy", encoding="utf-8")
    with pytest.raises(CryptoError, match="implausibly large"):
        _load_owner_pins(kf)


def test_symlinked_store_is_refused_not_followed(tmp_path: Path) -> None:
    import os

    target = tmp_path / "real.json"
    target.write_text(json.dumps({_FID: _PK_A.hex()}), encoding="utf-8")
    kf = tmp_path / "keys.enc"
    os.symlink(target, _owner_pins_path(kf))  # plant a symlink at the pin path
    with pytest.raises(CryptoError, match="Cannot read"):
        _load_owner_pins(kf)


def test_first_use_returns_key_without_writing_pin() -> None:
    pins: dict[str, str] = {}
    pk, canon = _resolve(_FakeClient(_PK_A), _FID, None, pins)
    assert pk == _PK_A
    assert canon == _FID
    assert pins == {}, "resolve must NOT persist the pin (caller does, post-decrypt)"


def test_matching_pin_passes() -> None:
    pins = {_FID: _PK_A.hex()}
    pk, _ = _resolve(_FakeClient(_PK_A), _FID, None, pins)
    assert pk == _PK_A


def test_changed_owner_key_fails_closed() -> None:
    pins = {_FID: _PK_A.hex()}
    with pytest.raises(CryptoError, match="changed since first download"):
        _resolve(_FakeClient(_PK_B), _FID, None, pins)


def test_override_replaces_pin_with_warning(capsys: pytest.CaptureFixture[str]) -> None:
    pins = {_FID: _PK_A.hex()}
    # Explicit out-of-band override wins over the stored pin, but warns loudly.
    pk, _ = _resolve(_FakeClient(_PK_A), _FID, _PK_B.hex(), pins)
    assert pk == _PK_B
    assert "REPLACES" in capsys.readouterr().err


def test_bad_override_hex_fails_closed() -> None:
    with pytest.raises(CryptoError, match="not valid hex"):
        _resolve(_FakeClient(_PK_A), _FID, "zz", {})


def test_matching_override_does_not_warn(
    capsys: pytest.CaptureFixture[str],
) -> None:
    pins = {_FID: _PK_A.hex()}
    pk, _ = _resolve(_FakeClient(_PK_A), _FID, _PK_A.hex(), pins)  # override == pin
    assert pk == _PK_A
    assert "REPLACES" not in capsys.readouterr().err


def test_wrong_length_override_fails_closed() -> None:
    with pytest.raises(CryptoError, match="32 bytes"):
        _resolve(_FakeClient(_PK_A), _FID, (b"\x00" * 31).hex(), {})
