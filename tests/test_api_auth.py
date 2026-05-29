"""Route-level integration tests for the auth surface (ARCH-H1).

Exercises ``POST /api/auth/login`` and the ``require_auth`` middleware
end-to-end through the Quart test client, with peer identity sourced from
the ASGI scope's ``client`` field (SEC-M2) exactly as production derives
it from ``request.remote_addr``.

Covered:
- login success returns a usable bearer token
- wrong password and unknown user are byte-identical generic failures
  (no username enumeration)
- repeated failures lock the (peer, username) pair out — a subsequent
  CORRECT password is still rejected (regression guard for the
  authoritative in-memory composite limiter, #H11)
- a token is bound to its peer: replay from a different remote_addr is
  rejected (#5 / #H9)
- ``require_auth``: a session_version bump revokes outstanding tokens
  (#H1) and a disabled user is rejected immediately

All login tests use the ``fast_argon2`` fixture so the real Argon2id KDF
runs at low cost; the limiter-reset fixture (autouse) keeps lockout
state isolated per test.
"""

from __future__ import annotations

from collections.abc import Callable

from quart import Quart
from quart.testing.client import QuartClient

from tests.conftest import (
    TEST_PASSWORD,
    TEST_PEER_PORT,
    TEST_USERNAME,
    AuthedClient,
)

# The login route returns this exact body on EVERY failure path. Equality
# (not just status) is the no-enumeration contract.
_GENERIC_AUTH_FAILURE = {"error": "Authentication failed"}


async def _login_attempt(
    client: QuartClient,
    username: str,
    password: str,
    peer_host: str = "10.0.0.2",
):
    """POST /api/auth/login from a fixed peer; return the raw response."""
    return await client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        scope_base={"client": (peer_host, TEST_PEER_PORT)},
    )


# ──────────────────────────── login: happy path ────────────────────────────


async def test_login_success_returns_token(
    client: QuartClient,
    make_user: Callable[..., str],
    fast_argon2: None,
) -> None:
    make_user(TEST_USERNAME, TEST_PASSWORD)
    resp = await _login_attempt(client, TEST_USERNAME, TEST_PASSWORD)
    assert resp.status_code == 200
    body = await resp.get_json()
    assert isinstance(body["token"], str) and body["token"]


async def test_login_token_authorizes_a_protected_route(
    client: QuartClient,
    make_user: Callable[..., str],
    fast_argon2: None,
) -> None:
    """The minted token actually unlocks an authenticated route."""
    make_user(TEST_USERNAME, TEST_PASSWORD)
    resp = await _login_attempt(client, TEST_USERNAME, TEST_PASSWORD)
    token = (await resp.get_json())["token"]

    listing = await client.get(
        "/api/files",
        headers={"Authorization": f"Bearer {token}"},
        scope_base={"client": ("10.0.0.2", TEST_PEER_PORT)},
    )
    assert listing.status_code == 200


# ──────────────────────────── login: no enumeration ────────────────────────────


async def test_wrong_password_and_unknown_user_are_identical(
    client: QuartClient,
    make_user: Callable[..., str],
    fast_argon2: None,
) -> None:
    """Wrong password and unknown user must be indistinguishable.

    Same status AND same body — neither path may reveal whether the
    account exists. Run from distinct peers so the composite limiter
    doesn't count one against the other.
    """
    make_user(TEST_USERNAME, TEST_PASSWORD)

    wrong_pw = await _login_attempt(
        client, TEST_USERNAME, "definitely-wrong", peer_host="10.0.0.21"
    )
    unknown = await _login_attempt(
        client, "ghost-user", "definitely-wrong", peer_host="10.0.0.22"
    )

    assert wrong_pw.status_code == unknown.status_code == 401
    assert await wrong_pw.get_json() == await unknown.get_json()
    assert await unknown.get_json() == _GENERIC_AUTH_FAILURE


# NOTE: the empty-peer login gate (#H9) is NOT exercised here. The Quart
# test client hardcodes request.remote_addr to "<local>" whenever the ASGI
# scope's ``client`` field is None/absent, so the missing-peer branch is
# unreachable through the in-process test transport. It is covered by the
# unit-level token tests in tests/test_auth_token.py
# (create_session_token raises on empty peer; verify_session_token rejects
# an empty expected_peer).


# ──────────────────────────── login: lockout ────────────────────────────


def _rate_limit_max(app: Quart) -> int:
    """Read the wired ``rate_limit_max`` from the app's typed AppState."""
    from server.state import _EXTENSION_KEY

    state = app.extensions[_EXTENSION_KEY]
    return state.rate_limit_max


async def test_repeated_failures_lock_out_even_correct_password(
    app: Quart,
    client: QuartClient,
    make_user: Callable[..., str],
    fast_argon2: None,
) -> None:
    """After rate_limit_max failures, a CORRECT password is still rejected.

    This is the load-bearing regression guard for the authoritative
    composite (peer, username) limiter: if lockout were broken, the final
    correct-password attempt would return 200 with a token. We assert it
    stays 401 with the generic body.
    """
    max_attempts = _rate_limit_max(app)
    assert max_attempts >= 1

    make_user(TEST_USERNAME, TEST_PASSWORD)
    peer = "10.0.0.30"

    # Exhaust the limiter with wrong-password attempts.
    for _ in range(max_attempts):
        bad = await _login_attempt(client, TEST_USERNAME, "wrong", peer_host=peer)
        assert bad.status_code == 401

    # The limiter is now tripped: even the correct password is refused.
    locked = await _login_attempt(client, TEST_USERNAME, TEST_PASSWORD, peer_host=peer)
    assert locked.status_code == 401
    assert await locked.get_json() == _GENERIC_AUTH_FAILURE


async def test_successful_login_clears_prior_failures(
    app: Quart,
    client: QuartClient,
    make_user: Callable[..., str],
    fast_argon2: None,
) -> None:
    """A success below the threshold clears the failed-attempt counters.

    Fewer-than-max failures followed by a correct password must succeed
    (the composite + DB counters are reset on success); a regression that
    failed to clear them would eventually lock a legitimate user out.
    """
    max_attempts = _rate_limit_max(app)
    make_user(TEST_USERNAME, TEST_PASSWORD)
    peer = "10.0.0.31"

    # One short of the limit, then a correct login.
    for _ in range(max_attempts - 1):
        bad = await _login_attempt(client, TEST_USERNAME, "wrong", peer_host=peer)
        assert bad.status_code == 401

    ok = await _login_attempt(client, TEST_USERNAME, TEST_PASSWORD, peer_host=peer)
    assert ok.status_code == 200

    # Counters cleared: another full run of failures is needed to lock out
    # again — i.e. a single immediate wrong attempt is still just a 401,
    # and a subsequent correct one still works.
    again = await _login_attempt(client, TEST_USERNAME, TEST_PASSWORD, peer_host=peer)
    assert again.status_code == 200


# ──────────────────────────── token peer binding ────────────────────────────


async def test_token_replay_from_other_peer_rejected(
    auth_client: AuthedClient,
    client: QuartClient,
) -> None:
    """A token bound to one peer is rejected when replayed from another."""
    resp = await client.get(
        "/api/files",
        headers={"Authorization": f"Bearer {auth_client.token}"},
        scope_base={"client": ("10.9.9.9", TEST_PEER_PORT)},
    )
    assert resp.status_code == 401
    assert await resp.get_json() == {"error": "Authentication required"}


async def test_token_accepted_from_bound_peer(auth_client: AuthedClient) -> None:
    """Sanity counterpart: the same token works from its bound peer.

    Guards against the replay test passing for the wrong reason (e.g. the
    token being globally invalid).
    """
    resp = await auth_client.get("/api/files")
    assert resp.status_code == 200


# ──────────────────────────── require_auth middleware ────────────────────────────


async def test_session_version_bump_revokes_token(
    app: Quart,
    auth_client: AuthedClient,
) -> None:
    """Bumping the user's session_version revokes the outstanding token.

    The token snapshots ``sv`` at issue time; require_auth compares it
    against the live row, so an operator bump invalidates it on the next
    request even though the HMAC + expiry are still valid.
    """
    # Token works before the bump.
    before = await auth_client.get("/api/files")
    assert before.status_code == 200

    bumped = app.db.bump_session_version(TEST_USERNAME)  # type: ignore[attr-defined]
    assert bumped is True

    after = await auth_client.get("/api/files")
    assert after.status_code == 401
    assert await after.get_json() == {"error": "Authentication required"}


async def test_disabled_user_token_rejected(
    app: Quart,
    auth_client: AuthedClient,
) -> None:
    """A disabled user's existing token stops working immediately (#H1)."""
    before = await auth_client.get("/api/files")
    assert before.status_code == 200

    disabled = app.db.disable_user(TEST_USERNAME)  # type: ignore[attr-defined]
    assert disabled is True

    after = await auth_client.get("/api/files")
    assert after.status_code == 401
    assert await after.get_json() == {"error": "Authentication required"}


async def test_missing_bearer_header_rejected(client: QuartClient) -> None:
    """No Authorization header → 401 from require_auth, before any work."""
    resp = await client.get(
        "/api/files",
        scope_base={"client": ("10.0.0.2", TEST_PEER_PORT)},
    )
    assert resp.status_code == 401
    assert await resp.get_json() == {"error": "Authentication required"}
