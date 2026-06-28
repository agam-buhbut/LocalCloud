"""KeyStore lifecycle tests (client-side identity key management).

Closes the verified coverage hole around ``client/keystore.py``: the
generate/unlock round-trip, the wrong-password and corrupt-store failure
paths, the generate-over-existing guard, lock() relocking, and the
inactivity auto-lock — the latter driven WITHOUT a real sleep by
backdating ``_last_activity`` and invoking the timer callback directly.

A real ``keycore`` is required (no mocking below the Rust boundary);
``importorskip`` is acceptable here, consistent with test_encryptor.py.
The expensive Argon2id ``generate`` runs once per module (the on-disk
store is reused read-only); each unlock still runs the genuine KDF.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

# `keycore` is the compiled Rust extension; skip the module if it is absent.
pytest.importorskip("keycore")

from client.keystore import KeyStore  # noqa: E402

_PW = "correct-pw-123456"


@pytest.fixture(scope="module")
def real_store(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """Generate one genuine encrypted key store on disk; return (path, pw).

    Generating runs the full Argon2id KDF once; the persisted file is then
    reused (read-only) by the unlock-path tests. ``lock()`` cancels the
    auto-lock timer the generate started.
    """
    path = tmp_path_factory.mktemp("ks_real") / "identity.key"
    ks = KeyStore(str(path))
    ks.generate(_PW)
    ks.lock()
    return str(path), _PW


def test_generate_unlock_roundtrip(real_store: tuple[str, str]) -> None:
    path, pw = real_store
    ks = KeyStore(path)
    assert ks.has_keys
    assert not ks.is_unlocked

    ks.unlock(pw)
    try:
        assert ks.is_unlocked
        x = ks.x25519_public_key()
        ed = ks.ed25519_public_key()
        assert len(x) == 32
        assert len(ed) == 32
        # A second instance unlocked from the same file yields the same
        # public keys — the round-trip is stable, not random per unlock.
        other = KeyStore(path)
        other.unlock(pw)
        try:
            assert other.x25519_public_key() == x
            assert other.ed25519_public_key() == ed
        finally:
            other.lock()
    finally:
        ks.lock()
    assert not ks.is_unlocked


def test_unlock_wrong_password_raises(real_store: tuple[str, str]) -> None:
    path, _pw = real_store
    ks = KeyStore(path)
    with pytest.raises(ValueError):
        ks.unlock("definitely-the-wrong-password")
    # A failed unlock leaves the store locked (keypair never assigned).
    assert not ks.is_unlocked


def test_unlock_corrupt_store_raises(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.key"
    path.write_bytes(b"this is not a valid encrypted key store")
    ks = KeyStore(str(path))
    with pytest.raises(ValueError):
        ks.unlock("any-password-here")
    assert not ks.is_unlocked


def test_unlock_missing_file_raises(tmp_path: Path) -> None:
    ks = KeyStore(str(tmp_path / "nope.key"))
    assert not ks.has_keys
    with pytest.raises(FileNotFoundError):
        ks.unlock(_PW)


def test_generate_over_existing_refused(tmp_path: Path) -> None:
    path = tmp_path / "exists.key"
    path.write_bytes(b"placeholder")  # pre-existing file blocks generate
    ks = KeyStore(str(path))
    with pytest.raises(FileExistsError):
        ks.generate(_PW)
    # The existing file is left untouched (no clobber).
    assert path.read_bytes() == b"placeholder"


def test_lock_relocks_and_is_idempotent(real_store: tuple[str, str]) -> None:
    path, pw = real_store
    ks = KeyStore(path)
    ks.unlock(pw)
    assert ks.is_unlocked

    ks.lock()
    assert not ks.is_unlocked
    # Calling lock() again on an already-locked store is a no-op, not an error.
    ks.lock()
    assert not ks.is_unlocked


def test_auto_lock_after_timeout_without_sleep(real_store: tuple[str, str]) -> None:
    path, pw = real_store
    ks = KeyStore(path, inactivity_timeout=300)
    ks.unlock(pw)
    try:
        assert ks.is_unlocked
        # Simulate the inactivity window elapsing WITHOUT sleeping: backdate
        # the last-activity stamp past the timeout, then drive the timer
        # callback the real Timer would have invoked.
        ks._last_activity = time.time() - (ks.inactivity_timeout + 1)
        ks._auto_lock()
        assert not ks.is_unlocked
    finally:
        ks.lock()


def test_auto_lock_keeps_unlocked_when_activity_recent(
    real_store: tuple[str, str],
) -> None:
    """Race guard (#F30): a timer firing right after fresh activity must NOT
    lock a store the user just touched."""
    path, pw = real_store
    ks = KeyStore(path)
    ks.unlock(pw)
    try:
        ks._last_activity = time.time()  # activity is current
        ks._auto_lock()  # timer fired, but the inactivity window has not passed
        assert ks.is_unlocked
    finally:
        ks.lock()
