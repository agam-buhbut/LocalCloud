"""Route-level smoke tests through the Quart test client.

A thin proof that the real app boots via create_app and that the core
auth + file-list routes behave at the HTTP boundary. This is the
safety-net layer for the upcoming AppState refactor (module-global
singletons → typed state); it is intentionally NOT the full integration
suite.

Peer identity: the login route and require_auth derive the peer from
request.remote_addr (SEC-M2). Under Quart's test client this is sourced
from the ASGI scope's ``client`` field, which the auth_client / login
fixtures pin to a fixed test address. (Note: the test client DOES
populate remote_addr — unlike test_request_context, which does not. See
tests/test_startup_invariants.py.)
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from quart import Quart
from quart.testing.client import QuartClient

from tests.conftest import (
    TEST_PASSWORD,
    TEST_PEER_PORT,
    TEST_USERNAME,
    AuthedClient,
)

# Generic failure body the login route returns on EVERY failure path.
# Asserting equality (not just status) guards the no-user-enumeration
# contract: bad password and unknown user must be byte-identical.
_GENERIC_AUTH_FAILURE = {"error": "Authentication failed"}


def test_app_constructs(app: Quart) -> None:
    """create_app produced a real Quart app wired to a live DB."""
    assert isinstance(app, Quart)
    assert getattr(app, "db", None) is not None


async def test_unknown_path_returns_404(client: QuartClient) -> None:
    """An unrouted path returns the generic 404 JSON body."""
    response = await client.get("/no/such/route")
    assert response.status_code == 404
    body = await response.get_json()
    assert body == {"error": "Not found"}


async def test_login_with_correct_credentials_returns_token(
    client: QuartClient,
    make_user: Callable[..., str],
) -> None:
    """Valid credentials yield a 200 with a non-empty session token."""
    make_user(TEST_USERNAME, TEST_PASSWORD)
    response = await client.post(
        "/api/auth/login",
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        scope_base={"client": ("10.0.0.2", TEST_PEER_PORT)},
    )
    assert response.status_code == 200
    body = await response.get_json()
    assert isinstance(body.get("token"), str)
    assert body["token"]


async def test_login_with_wrong_password_is_generic_failure(
    client: QuartClient,
    make_user: Callable[..., str],
) -> None:
    """A wrong password returns the generic 401 failure body."""
    make_user(TEST_USERNAME, TEST_PASSWORD)
    response = await client.post(
        "/api/auth/login",
        json={"username": TEST_USERNAME, "password": "wrong-password"},
        scope_base={"client": ("10.0.0.2", TEST_PEER_PORT)},
    )
    assert response.status_code == 401
    body = await response.get_json()
    assert body == _GENERIC_AUTH_FAILURE


async def test_login_unknown_user_matches_wrong_password(
    client: QuartClient,
    make_user: Callable[..., str],
) -> None:
    """Unknown user and wrong password are indistinguishable (no enum).

    Same status code AND same body — the route must not leak whether the
    username exists.
    """
    make_user(TEST_USERNAME, TEST_PASSWORD)

    wrong_pw = await client.post(
        "/api/auth/login",
        json={"username": TEST_USERNAME, "password": "wrong-password"},
        scope_base={"client": ("10.0.0.2", TEST_PEER_PORT)},
    )
    unknown_user = await client.post(
        "/api/auth/login",
        json={"username": "ghost", "password": "wrong-password"},
        scope_base={"client": ("10.0.0.2", TEST_PEER_PORT)},
    )

    assert wrong_pw.status_code == unknown_user.status_code == 401
    assert await wrong_pw.get_json() == await unknown_user.get_json()
    assert await unknown_user.get_json() == _GENERIC_AUTH_FAILURE


async def test_file_list_requires_auth(client: QuartClient) -> None:
    """GET /api/files without a bearer token is rejected with 401."""
    response = await client.get(
        "/api/files",
        scope_base={"client": ("10.0.0.2", TEST_PEER_PORT)},
    )
    assert response.status_code == 401
    body = await response.get_json()
    assert body == {"error": "Authentication required"}


async def test_file_list_succeeds_with_token(auth_client: AuthedClient) -> None:
    """GET /api/files with a valid token returns an (empty) file list."""
    response = await auth_client.get("/api/files")
    assert response.status_code == 200
    body = await response.get_json()
    assert body["files"] == []
    assert body["offset"] == 0


async def test_token_rejected_from_different_peer(
    auth_client: AuthedClient,
    client: QuartClient,
) -> None:
    """A token bound to one peer is rejected when presented from another.

    Exercises the mandatory session peer-binding (#5 / #H9): the token is
    minted for TEST_PEER_HOST; replaying it from a different source
    address must fail closed with 401.
    """
    response = await client.get(
        "/api/files",
        headers={"Authorization": f"Bearer {auth_client.token}"},
        scope_base={"client": ("10.9.9.9", TEST_PEER_PORT)},
    )
    assert response.status_code == 401
    body = await response.get_json()
    assert body == {"error": "Authentication required"}


def test_login_helper_fixture_available(
    login: Callable[..., Awaitable[str]],
) -> None:
    """The raw login helper fixture is exposed for custom-flow tests."""
    assert callable(login)
