"""Key-rotation guarantees (Phase 7, rev key-rotation task).

The runbook (docs/runbooks/key-rotation.md) claims session-secret rotation
cleanly invalidates every outstanding token. That holds *by construction* —
the token signature is HMAC(secret, payload), so a new secret makes every old
signature fail to verify — but the audit checklist requires it TESTED, not just
asserted. These tests pin it.
"""

from __future__ import annotations

import pytest

from server.auth import create_session_token, verify_session_token
from shared.exceptions import SessionExpiredError

_PEER = "wg-peer-pubkey-aaaaaaaaaaaaaaaaaaaaaaaa="
_OLD = "old-secret-" + "a" * 64
_NEW = "new-secret-" + "b" * 64


def _token(secret: str) -> str:
    return create_session_token(
        user_id="u1",
        username="alice",
        secret=secret,
        lifetime=3600,
        peer_pubkey=_PEER,
        session_version=1,
    )


def test_token_verifies_under_its_own_secret() -> None:
    tok = _token(_OLD)
    claims = verify_session_token(tok, _OLD, expected_peer=_PEER)
    assert claims["user_id"] == "u1"


def test_rotated_secret_invalidates_outstanding_token() -> None:
    """A token minted under the OLD secret must fail under the NEW secret."""
    tok = _token(_OLD)
    with pytest.raises(SessionExpiredError):
        verify_session_token(tok, _NEW, expected_peer=_PEER)


def test_old_secret_rejects_new_token() -> None:
    """Rotation is symmetric: a NEW-secret token is dead under the OLD secret,
    so there is no window where both secrets accept the same token."""
    tok = _token(_NEW)
    with pytest.raises(SessionExpiredError):
        verify_session_token(tok, _OLD, expected_peer=_PEER)


def test_distinct_secrets_produce_distinct_signatures() -> None:
    """Sanity: the signature actually depends on the secret (no silent
    fixed-key fallback that would survive rotation)."""
    sig_old = _token(_OLD).rsplit(".", 1)[1]
    sig_new = _token(_NEW).rsplit(".", 1)[1]
    assert sig_old != sig_new
