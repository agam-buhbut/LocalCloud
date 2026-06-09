"""ServerConfig parsing/validation for the Argon2 concurrency knob (4F)."""

from __future__ import annotations

import pytest

from server.config import ServerConfig

_VALID_SECRET = "a" * 64


def _valid_config() -> ServerConfig:
    cfg = ServerConfig()
    cfg.session_secret = _VALID_SECRET
    return cfg


def test_argon2_default_is_four() -> None:
    assert ServerConfig().argon2_max_concurrent == 4


def test_from_env_reads_argon2_max_concurrent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOCALCLOUD_SESSION_SECRET", _VALID_SECRET)
    monkeypatch.setenv("LOCALCLOUD_ARGON2_MAX_CONCURRENT", "7")
    cfg = ServerConfig.from_env()
    assert cfg.argon2_max_concurrent == 7


def test_validate_accepts_valid_argon2_value() -> None:
    cfg = _valid_config()
    cfg.argon2_max_concurrent = 2
    cfg.validate()  # must not raise


def test_validate_rejects_zero_argon2_value() -> None:
    cfg = _valid_config()
    cfg.argon2_max_concurrent = 0
    with pytest.raises(ValueError, match="argon2_max_concurrent"):
        cfg.validate()
