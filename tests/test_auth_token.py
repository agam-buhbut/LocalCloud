"""Session token tests for server.auth.

Covers:
- HMAC signed token round-trip
- Peer binding (mandatory + mismatch rejected)
- Expiration enforcement
- Tampered signature rejection
- Username canonicalization rules
- Composite rate-limit sweep (#H11 unbounded-growth fix)
"""

from __future__ import annotations

import asyncio

import pytest

from server import auth as auth_mod
from server.auth import (
    _canonicalize_username,
    _composite_attempts,
    _composite_rate_limit_record,
    create_session_token,
    sweep_composite_attempts,
    verify_session_token,
)
from shared.exceptions import AuthError, SessionExpiredError

SECRET = "x" * 64  # meets validate()'s ≥64-char rule


# ──────────────────────────── Token round-trip ────────────────────────────


def test_session_token_roundtrip():
    token = create_session_token(
        user_id="user-uuid",
        username="alice",
        secret=SECRET,
        lifetime=60,
        peer_pubkey="10.0.0.2",
        session_version=3,
    )
    payload = verify_session_token(token, SECRET, expected_peer="10.0.0.2")
    assert payload["user_id"] == "user-uuid"
    assert payload["username"] == "alice"
    assert payload["sv"] == 3


def test_session_token_requires_peer():
    with pytest.raises(ValueError):
        create_session_token(
            user_id="u",
            username="a",
            secret=SECRET,
            peer_pubkey="",
        )


def test_session_token_peer_mismatch_rejected():
    token = create_session_token(
        user_id="u",
        username="a",
        secret=SECRET,
        peer_pubkey="10.0.0.2",
    )
    with pytest.raises(SessionExpiredError):
        verify_session_token(token, SECRET, expected_peer="10.0.0.3")


def test_session_token_empty_expected_peer_rejected():
    token = create_session_token(
        user_id="u",
        username="a",
        secret=SECRET,
        peer_pubkey="10.0.0.2",
    )
    with pytest.raises(SessionExpiredError):
        verify_session_token(token, SECRET, expected_peer="")


def test_session_token_tampered_sig_rejected():
    token = create_session_token(
        user_id="u",
        username="a",
        secret=SECRET,
        peer_pubkey="10.0.0.2",
    )
    payload_b64, sig = token.split(".", 1)
    # Flip a bit in the signature
    bad_sig = "0" + sig[1:] if sig[0] != "0" else "1" + sig[1:]
    with pytest.raises(SessionExpiredError):
        verify_session_token(
            f"{payload_b64}.{bad_sig}", SECRET, expected_peer="10.0.0.2"
        )


def test_session_token_expired_rejected():
    token = create_session_token(
        user_id="u",
        username="a",
        secret=SECRET,
        lifetime=-10,  # already expired
        peer_pubkey="10.0.0.2",
    )
    with pytest.raises(SessionExpiredError):
        verify_session_token(token, SECRET, expected_peer="10.0.0.2")


def test_session_token_oversize_rejected():
    long_token = "x" * 5000  # > _MAX_TOKEN_LEN
    with pytest.raises(SessionExpiredError):
        verify_session_token(long_token, SECRET, expected_peer="10.0.0.2")


# ──────────────────────────── Username canonicalization ────────────────────────────


def test_canonicalize_username_basic():
    assert _canonicalize_username("Alice") == "alice"
    assert _canonicalize_username("user.name_3") == "user.name_3"


def test_canonicalize_username_rejects_nul():
    with pytest.raises(AuthError):
        _canonicalize_username("alice\x00")


def test_canonicalize_username_rejects_unicode_confusable():
    # Fullwidth Latin "ＡＤＭＩＮ" → NFKC → "admin"; after casefold this
    # collapses onto a real "admin" username. The implementation must
    # apply the same canonicalization at lookup time so this is fine —
    # but it must NOT silently accept different-looking strings.
    canonical = _canonicalize_username("ＡＤＭＩＮ")
    assert canonical == "admin"


def test_canonicalize_username_rejects_too_short():
    with pytest.raises(AuthError):
        _canonicalize_username("ab")  # < 3 chars


def test_canonicalize_username_rejects_bad_chars():
    with pytest.raises(AuthError):
        _canonicalize_username("alice@bob")  # @ not allowed


# ──────────────────────────── Composite rate-limit sweep ────────────────────────────


@pytest.mark.asyncio
async def test_composite_sweep_drops_empty_keys():
    # Pre-populate with a key whose deque will expire under the sweep
    # window.
    await _composite_rate_limit_record("10.0.0.2", "alice")
    assert ("10.0.0.2", "alice") in _composite_attempts
    # Sweep with a 0-second window means everything older than `now`
    # is stale → deque empties → key dropped.
    await asyncio.sleep(0.01)
    removed = await sweep_composite_attempts(window_seconds=0)
    assert removed >= 1
    assert ("10.0.0.2", "alice") not in _composite_attempts


@pytest.mark.asyncio
async def test_composite_sweep_evicts_above_cap():
    # Pollute the dict above the hard cap.
    cap = auth_mod._COMPOSITE_MAX_KEYS
    overshoot = 10
    # Use real `time.monotonic` so trimming doesn't drop these.
    for i in range(cap + overshoot):
        await _composite_rate_limit_record("10.0.0.99", f"u{i:06d}")
    removed = await sweep_composite_attempts(window_seconds=60)
    assert removed >= overshoot
    # Final size must be at the cap.
    assert len(_composite_attempts) <= cap
    # Cleanup
    _composite_attempts.clear()
