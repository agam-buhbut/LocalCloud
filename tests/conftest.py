"""Shared pytest fixtures.

Kept deliberately small — most tests construct their own state. This
file holds only cross-cutting fixtures (temp directory layout for the
server, deterministic seeds where appropriate, etc.).
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

# Make the repository root importable so `import server`, `import client`,
# `import shared` resolve when running pytest from the project root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pytest  # noqa: E402  (must come after sys.path mutation)
from quart import Quart  # noqa: E402
from quart.testing.client import QuartClient  # noqa: E402

from server.database import Database  # noqa: E402

# Fixed peer address supplied to the test client. The login route and
# require_auth derive peer identity from request.remote_addr (SEC-M2);
# under the test client this comes from the ASGI scope's ``client``
# field. We pin it so session peer-binding is deterministic across tests.
TEST_PEER_HOST = "10.0.0.2"
TEST_PEER_PORT = 51820

# Credentials for the canonical authenticated user created by auth_client.
TEST_USERNAME = "alice"
TEST_PASSWORD = "correct-horse-battery-staple"


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


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    """A connected metadata Database backed by a fresh tmp file.

    Canonical version of the fixture that was previously duplicated,
    byte-for-byte, in test_database.py and test_storage_share.py.
    """
    d = Database(str(tmp_path / "meta.db"))
    d.connect()
    return d


def _test_server_config(tmp_data_dir: Path, session_secret: str):
    """Build a ServerConfig wired to the tmp data dir + test secret.

    Mirrors the wiring used by the create_app integration tests in
    tests/test_startup_invariants.py.
    """
    from server.config import ServerConfig

    return ServerConfig(
        bind_host="10.0.0.1",
        data_dir=str(tmp_data_dir),
        blob_dir=str(tmp_data_dir / "blobs"),
        staging_dir=str(tmp_data_dir / "staging"),
        db_path=str(tmp_data_dir / "meta.db"),
        session_secret=session_secret,
    )


@pytest.fixture()
def app(
    tmp_data_dir: Path,
    session_secret: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Quart]:
    """The real Quart app wired to a tmp data dir + fixed test secret.

    Clears the worker-count environment variables so the single-worker
    startup invariant (SEC-M3, assert_single_worker) passes under the
    test runner regardless of the host environment. The forwarded-header
    invariant (SEC-M2) already passes for a stock Quart app. The DB
    connection opened by create_app is closed on teardown.
    """
    for var in ("WEB_CONCURRENCY", "HYPERCORN_WORKERS", "LOCALCLOUD_WORKERS"):
        monkeypatch.delenv(var, raising=False)

    from server.app import create_app

    application = create_app(_test_server_config(tmp_data_dir, session_secret))
    try:
        yield application
    finally:
        database = getattr(application, "db", None)
        if database is not None:
            database.close()


@pytest.fixture()
def client(app: Quart) -> QuartClient:
    """Quart test client for the wired app."""
    return app.test_client()


@dataclass
class AuthedClient:
    """A logged-in test client bundle.

    Bundles the underlying Quart test client, the issued bearer token,
    and the peer host the token is bound to. ``get``/``post``/``delete``
    forward to the client with the Authorization header and the bound
    peer address pre-populated in the ASGI scope, so authenticated
    requests just work.
    """

    client: QuartClient
    token: str
    peer_host: str = TEST_PEER_HOST

    def _scope_base(self) -> dict:
        return {"client": (self.peer_host, TEST_PEER_PORT)}

    def _auth_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.token}"}
        if extra:
            headers.update(extra)
        return headers

    async def get(self, path: str, *, headers: dict[str, str] | None = None):
        return await self.client.get(
            path,
            headers=self._auth_headers(headers),
            scope_base=self._scope_base(),
        )

    async def post(
        self,
        path: str,
        *,
        json: object | None = None,
        headers: dict[str, str] | None = None,
    ):
        return await self.client.post(
            path,
            json=json,
            headers=self._auth_headers(headers),
            scope_base=self._scope_base(),
        )

    async def delete(self, path: str, *, headers: dict[str, str] | None = None):
        return await self.client.delete(
            path,
            headers=self._auth_headers(headers),
            scope_base=self._scope_base(),
        )


async def _login(
    client: QuartClient,
    username: str,
    password: str,
    peer_host: str = TEST_PEER_HOST,
) -> str:
    """Log in through the test client and return the session token.

    Raises:
        AssertionError: if the login response is not 200 or omits a token.
    """
    response = await client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        scope_base={"client": (peer_host, TEST_PEER_PORT)},
    )
    assert response.status_code == 200, f"login failed: {response.status_code}"
    body = await response.get_json()
    token = body["token"]
    assert isinstance(token, str) and token
    return token


@pytest.fixture()
def make_user(app: Quart) -> Callable[..., str]:
    """Factory that inserts a user directly into the app's DB.

    Bypasses the admin CLI: hashes the password with the same
    shared.crypto primitive the server uses and writes the row via the
    live Database the app is wired to. Returns the new user_id.
    """
    from shared.crypto import hash_password

    def _make(
        username: str = TEST_USERNAME,
        password: str = TEST_PASSWORD,
        quota_bytes: int = 10 * 1024 * 1024,
    ) -> str:
        database: Database = app.db  # type: ignore[attr-defined]
        return database.create_user(
            username=username,
            password_hash=hash_password(password),
            quota_bytes=quota_bytes,
        )

    return _make


@pytest.fixture()
async def auth_client(
    client: QuartClient,
    make_user: Callable[..., str],
) -> AsyncIterator[AuthedClient]:
    """A test client already authenticated as a fresh canonical user.

    Creates the user, logs in over the test client with the fixed test
    peer address, and yields an AuthedClient that injects the bearer
    token and bound peer address on every request.
    """
    make_user(TEST_USERNAME, TEST_PASSWORD)
    token = await _login(client, TEST_USERNAME, TEST_PASSWORD)
    yield AuthedClient(client=client, token=token)


@pytest.fixture()
def login() -> Callable[..., Awaitable[str]]:
    """Expose the raw login helper for tests that need custom flows."""
    return _login
