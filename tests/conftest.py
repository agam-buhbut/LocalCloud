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

    ``ed25519_pubkey`` is forwarded so route-level tests that exercise the
    ``/owner_pubkey`` endpoint and download signature verification can pin
    a real owner identity key on the user row.
    """
    from shared.crypto import hash_password

    def _make(
        username: str = TEST_USERNAME,
        password: str = TEST_PASSWORD,
        quota_bytes: int = 10 * 1024 * 1024,
        ed25519_pubkey: bytes = b"",
    ) -> str:
        database: Database = app.db  # type: ignore[attr-defined]
        return database.create_user(
            username=username,
            password_hash=hash_password(password),
            quota_bytes=quota_bytes,
            ed25519_pubkey=ed25519_pubkey,
        )

    return _make


@pytest.fixture(autouse=True)
def reset_composite_rate_limiter() -> Iterator[None]:
    """Clear the process-global composite rate-limiter between tests.

    ``server.auth._composite_attempts`` is module-level in-memory state
    keyed by ``(peer_ip, username)``. It is NOT reset by building a fresh
    app, so failed-login attempts recorded by one test would otherwise
    leak into the next and make lockout assertions non-deterministic.
    Autouse so every test in the suite starts from a clean limiter.
    """
    from server.auth import _composite_attempts

    _composite_attempts.clear()
    yield
    _composite_attempts.clear()


@pytest.fixture()
def fast_argon2(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Swap the server password hasher for a low-cost (but real) Argon2id.

    The production parameters (128 MiB / t=3) make a single hash+verify
    cost well over a second, which is prohibitive for tests that drive
    several failed logins (lockout) through the real route. This patches
    the single module-level ``shared.crypto._password_hasher`` so BOTH
    ``hash_password`` (used by ``make_user``) and ``verify_password``
    (used by the login route) share the same cheap-but-genuine Argon2id
    instance — still a real KDF, no new dependency, deterministic.

    The cached unknown-user dummy hash is reset so the enumeration-
    equalisation path also recomputes under the cheap params.
    """
    import argon2

    import shared.crypto as crypto_mod
    from server import auth as auth_mod

    cheap = argon2.PasswordHasher(
        memory_cost=8,  # 8 KiB
        time_cost=1,
        parallelism=1,
        type=argon2.Type.ID,
    )
    monkeypatch.setattr(crypto_mod, "_password_hasher", cheap)
    # Force the dummy-hash cache to recompute under the cheap hasher so the
    # unknown-user path doesn't pay (or mismatch against) the full cost.
    monkeypatch.setattr(auth_mod, "_DUMMY_PASSWORD_HASH", None, raising=False)
    yield


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


@dataclass
class KeyedClient:
    """A logged-in :class:`AuthedClient` plus the user's real keypair.

    The user row in the DB was created with this keystore's Ed25519 public
    key registered, so ``/owner_pubkey`` and download signature
    verification work end-to-end for files this client uploads.
    """

    authed: AuthedClient
    keystore: object
    user_id: str
    username: str


@pytest.fixture()
def make_keyed_client(
    client: QuartClient,
    make_user: Callable[..., str],
    make_keystore: Callable[..., object],
    fast_argon2: None,
) -> Callable[..., Awaitable[KeyedClient]]:
    """Factory: create a user with a real Ed25519 identity and log in.

    Each call generates a fresh keypair, registers its Ed25519 pubkey on a
    new user row, logs in over the test client from a distinct peer
    address (so per-peer rate-limit / session-binding state never
    collides between two keyed clients in the same test), and returns a
    :class:`KeyedClient`.

    Depends on ``fast_argon2`` so the many logins these integration tests
    perform use a cheap (but still real) Argon2id; these are not auth
    timing tests, so the production KDF cost is unnecessary here.
    """
    counter = {"n": 0}

    async def _make(
        username: str | None = None,
        password: str = TEST_PASSWORD,
        quota_bytes: int = 10 * 1024 * 1024,
    ) -> KeyedClient:
        counter["n"] += 1
        if username is None:
            username = f"user{counter['n']}"
        peer_host = f"10.0.0.{10 + counter['n']}"
        ks = make_keystore()
        pubkey = ks.ed25519_public_key()  # type: ignore[attr-defined]
        user_id = make_user(
            username=username,
            password=password,
            quota_bytes=quota_bytes,
            ed25519_pubkey=pubkey,
        )
        token = await _login(client, username, password, peer_host=peer_host)
        authed = AuthedClient(client=client, token=token, peer_host=peer_host)
        return KeyedClient(
            authed=authed, keystore=ks, user_id=user_id, username=username
        )

    return _make


# ──────────────────────── Real-upload helpers ────────────────────────
#
# Two complementary helpers, both using GENUINE encrypted bytes produced
# by the client's FileEncryptor (real per-chunk BLAKE2b hashes, a signed
# Merkle-root header, and an encrypted metadata blob):
#
#   * ``http_upload`` drives the live upload state machine over the test
#     client (init -> chunk -> finalize). Used by the upload-state-machine
#     tests to exercise the real ingest path and its validation gates.
#
#   * ``seed_file`` installs a *finalized* file directly into the DB +
#     blob filesystem exactly the way a correct finalize would (canonical
#     file_id directory, ``<i>.bin`` chunk files, quota committed). Used by
#     the download / list / delete / share route tests so they exercise
#     those routes WITHOUT depending on the upload ingest path.


# The encryptor's chunk size for tests. Small so a few-KiB payload spans
# multiple chunks; >= the server's MIN_CHUNK_SIZE (1 KiB) so non-final
# chunks are accepted by the real upload route.
_TEST_CHUNK_SIZE = 1024


@dataclass
class EncryptedUpload:
    """The raw product of encrypting a file with FileEncryptor.

    Everything needed to drive the upload API or to install the file
    directly, plus the per-file keys and plaintext for a decrypt round-trip.
    """

    file_id_hex: str  # canonical 32-char hex (no hyphens)
    plaintext: bytes
    header_bytes: bytes
    encrypted_metadata: bytes
    chunk_hashes: list[bytes]
    chunk_blobs: list[bytes]
    file_key: bytes
    meta_key: bytes
    total_chunks: int


@dataclass
class UploadedFile:
    """A file present on the server plus everything to drive download.

    ``file_id`` is the canonical 32-char hex the server stored.
    ``plaintext`` is the exact original bytes so a round-trip decrypt can
    be asserted equal. ``owner_keystore`` exposes the owner's identity for
    signature verification and key wrapping.
    """

    file_id: str
    plaintext: bytes
    header_bytes: bytes
    encrypted_metadata: bytes
    chunk_hashes: list[bytes]
    chunk_blobs: list[bytes]
    file_key: bytes
    meta_key: bytes
    visibility: int
    owner_keystore: object  # client.keystore.KeyStore (avoid import cycle)


def _make_keystore(key_dir: Path, password: str = "key-pw-123456") -> object:
    """Build an unlocked KeyStore backed by a real generated keypair."""
    from client.keystore import KeyStore

    ks = KeyStore(str(key_dir / "identity.key"))
    ks.generate(password)
    return ks


@pytest.fixture()
def make_keystore(tmp_path: Path) -> Callable[..., object]:
    """Factory returning fresh, unlocked KeyStores under unique subdirs."""
    counter = {"n": 0}

    def _make() -> object:
        counter["n"] += 1
        sub = tmp_path / f"ks{counter['n']}"
        sub.mkdir(mode=0o700)
        return _make_keystore(sub)

    return _make


def _encrypt_real_file(
    keystore: object,
    data: bytes,
    src_path: Path,
    filename: str,
    visibility: int,
    owner: str,
) -> EncryptedUpload:
    """Encrypt ``data`` with a real FileEncryptor; return the upload bundle."""
    from client.encryptor import FileEncryptor
    from shared.models import Visibility

    src_path.write_bytes(data)
    encryptor = FileEncryptor(keystore, chunk_size=_TEST_CHUNK_SIZE)  # type: ignore[arg-type]
    blobs: dict[int, bytes] = {}
    result = encryptor.encrypt_file(
        input_path=src_path,
        filename=filename,
        on_chunk=lambda idx, blob: blobs.__setitem__(idx, blob),
        visibility=Visibility(visibility),
        owner=owner,
    )
    ordered = [blobs[i] for i in range(len(blobs))]
    assert result.header.total_chunks == len(ordered)
    return EncryptedUpload(
        file_id_hex=result.header.file_id.hex(),
        plaintext=data,
        header_bytes=result.header.serialize(),
        encrypted_metadata=result.encrypted_metadata,
        chunk_hashes=list(result.chunk_hashes),
        chunk_blobs=ordered,
        file_key=result.file_key,
        meta_key=result.meta_key,
        total_chunks=result.header.total_chunks,
    )


@pytest.fixture()
def encrypt_file(tmp_path: Path) -> Callable[..., EncryptedUpload]:
    """Factory that encrypts bytes into a real :class:`EncryptedUpload`."""
    counter = {"n": 0}

    def _make(
        keystore: object,
        data: bytes,
        *,
        filename: str | None = None,
        visibility: int = 0,
        owner: str = "owner",
    ) -> EncryptedUpload:
        counter["n"] += 1
        name = filename or f"file{counter['n']}.bin"
        src = tmp_path / f"plain{counter['n']}.bin"
        return _encrypt_real_file(keystore, data, src, name, visibility, owner)

    return _make


@pytest.fixture()
def http_upload(
    encrypt_file: Callable[..., EncryptedUpload],
) -> Callable[..., Awaitable[tuple[EncryptedUpload, str]]]:
    """Drive the real init -> chunk -> finalize HTTP path.

    Returns ``(EncryptedUpload, upload_id)`` after init + all chunks, and
    leaves finalize to the caller so upload-state-machine tests can craft
    a bespoke finalize body. Each HTTP step up to and including the chunks
    is asserted to succeed.
    """

    async def _upload(
        authed: AuthedClient,
        keystore: object,
        data: bytes,
        *,
        filename: str | None = None,
        visibility: int = 0,
    ) -> tuple[EncryptedUpload, str]:
        enc = encrypt_file(keystore, data, filename=filename, visibility=visibility)
        init = await authed.post(
            "/api/files/upload/init",
            json={
                "filename": filename or "file.bin",
                "expected_chunks": enc.total_chunks,
            },
        )
        assert init.status_code == 201, await init.get_data()
        upload_id = (await init.get_json())["upload_id"]
        for idx, blob in enumerate(enc.chunk_blobs):
            chunk = await authed.client.post(
                f"/api/files/upload/{upload_id}/chunk/{idx}",
                data=blob,
                headers={
                    "Authorization": f"Bearer {authed.token}",
                    "Content-Type": "application/octet-stream",
                },
                scope_base={"client": (authed.peer_host, TEST_PEER_PORT)},
            )
            assert chunk.status_code == 200, await chunk.get_data()
        return enc, upload_id

    return _upload


@pytest.fixture()
def seed_file(
    app: Quart,
    tmp_data_dir: Path,
    encrypt_file: Callable[..., EncryptedUpload],
) -> Callable[..., UploadedFile]:
    """Install a finalized file directly into the DB + blob filesystem.

    Reproduces exactly what a correct ``upload_finalize`` produces: the
    ``files`` row (with the real header + encrypted-metadata blobs), the
    per-chunk ciphertext files at ``<blob_dir>/<file_id>/<i>.bin``, and the
    committed quota usage — all keyed on the canonical (no-hyphen) file_id
    the server uses. This lets the download / list / delete / share route
    tests run against genuine encrypted bytes without going through the
    upload ingest path.
    """
    # Use the public app.db handle (same as make_user) and derive blob_dir
    # from the test config this fixture's app is wired to (see
    # _test_server_config: blob_dir = tmp_data_dir / "blobs"), rather than
    # reaching into server.state internals.
    db: Database = app.db  # type: ignore[attr-defined]
    blob_dir = tmp_data_dir / "blobs"

    def _seed(
        owner_id: str,
        keystore: object,
        data: bytes,
        *,
        filename: str | None = None,
        visibility: int = 0,
        self_share: bool = False,
    ) -> UploadedFile:
        enc = encrypt_file(keystore, data, filename=filename, visibility=visibility)
        file_id = enc.file_id_hex  # already canonical 32-hex
        total_bytes = sum(len(b) for b in enc.chunk_blobs)
        total_bytes += len(enc.encrypted_metadata) + len(enc.header_bytes)

        # Write blob chunks to <blob_dir>/<file_id>/<i>.bin (finalize layout).
        blob_path = blob_dir / file_id
        blob_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        for idx, blob in enumerate(enc.chunk_blobs):
            (blob_path / f"{idx}.bin").write_bytes(blob)
            os.chmod(blob_path / f"{idx}.bin", 0o600)

        # Optionally install the owner's self-share row (item 2A) so route
        # tests can exercise the unified /wrapped_keys acquisition path for
        # the owner exactly as a real upload (which POSTs /self_keys) would.
        self_bundle: bytes | None = None
        if self_share:
            self_bundle = keystore.wrap_file_keys(  # type: ignore[attr-defined]
                enc.file_key,
                enc.meta_key,
                bytes.fromhex(file_id),
                keystore.x25519_public_key(),  # type: ignore[attr-defined]
            )

        # DB row + quota commit in one transaction, mirroring finalize.
        with db.transaction():
            db.create_file(
                file_id=file_id,
                owner_id=owner_id,
                filename=filename or f"{file_id}.bin",
                visibility=visibility,
                total_chunks=enc.total_chunks,
                total_bytes=total_bytes,
                encrypted_metadata=enc.encrypted_metadata,
                file_header=enc.header_bytes,
            )
            db.increment_usage(owner_id, total_bytes)
            if self_bundle is not None:
                db.add_file_share(
                    file_id=file_id,
                    shared_with_id=owner_id,
                    wrapped_keys=self_bundle,
                )

        return UploadedFile(
            file_id=file_id,
            plaintext=data,
            header_bytes=enc.header_bytes,
            encrypted_metadata=enc.encrypted_metadata,
            chunk_hashes=enc.chunk_hashes,
            chunk_blobs=enc.chunk_blobs,
            file_key=enc.file_key,
            meta_key=enc.meta_key,
            visibility=visibility,
            owner_keystore=keystore,
        )

    return _seed
