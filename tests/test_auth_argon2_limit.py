"""The Argon2 concurrency semaphore honours the configured ceiling (4F)."""

from __future__ import annotations

import pytest

import server.auth as auth
from server.database import Database


def test_semaphore_uses_configured_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A freshly-created semaphore reflects ``_argon2_max_concurrent``."""
    monkeypatch.setattr(auth, "_argon2_semaphore", None)
    monkeypatch.setattr(auth, "_argon2_max_concurrent", 3)
    sem = auth._get_argon2_semaphore()
    assert sem._value == 3


def test_init_auth_rejects_non_positive_concurrency(db: Database) -> None:
    with pytest.raises(ValueError, match="argon2_max_concurrent"):
        auth.init_auth(db=db, session_secret="x" * 64, argon2_max_concurrent=0)


def test_init_auth_applies_concurrency(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """init_auth records the configured ceiling for later semaphore creation.

    init_auth mutates several process globals; snapshot every one it touches
    via monkeypatch so teardown restores them and no state leaks to other
    tests (the throwaway ``db`` is closed at fixture teardown).
    """
    for name in (
        "_db",
        "_session_secret",
        "_session_lifetime",
        "_rate_limit_max",
        "_rate_limit_window",
        "_argon2_max_concurrent",
    ):
        monkeypatch.setattr(auth, name, getattr(auth, name))
    monkeypatch.setattr(auth, "_argon2_semaphore", None)

    auth.init_auth(db=db, session_secret="x" * 64, argon2_max_concurrent=2)
    assert auth._argon2_max_concurrent == 2
    assert auth._get_argon2_semaphore()._value == 2
