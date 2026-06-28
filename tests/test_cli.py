"""CLI orchestration tests (Phase 2 review-gap closure).

Drives the Click command group through ``click.testing.CliRunner`` with a
``tmp_path`` fake home, a REAL local ``KeyStore`` (genuine keycore keypair
+ wrap/sign), and the HTTP boundary mocked at exactly one seam: the
``CloudClient`` instance returned by ``client.cli._get_client``. Nothing
below the HTTP boundary is faked, so these pin the real client-side
orchestration (self-wrap, fail-closed key acquisition, enroll signing).

The single most safety-critical property here is the migrate-keys
fail-closed behaviour (``test_migrate_keys_fail_closed_leaves_json``): a
legacy ``<file_id>.keys.json`` is the user's ONLY copy of those keys, so a
regression that unlinked it before a confirmed ``/self_keys`` POST would
destroy them. That test asserts the JSON survives a failed POST.

Determinism / cost: the real KeyStore Argon2id KDF (in keycore) costs
several seconds per generate AND per unlock. We generate ONE genuine
keystore for the whole module (session fixture) and, per command, hand the
CLI that already-unlocked instance with ``unlock``/``lock`` patched to
no-ops. This is the same trade-off as the suite's ``fast_argon2`` fixture
(skip the redundant KDF, keep the real crypto): every wrap / unwrap / sign
below still runs through genuine keycore. No network, no sleeps.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner

from client.cli import _load_recipient_pins, _recipient_pins_path, cli
from client.keystore import KeyStore
from shared.crypto import blake2b_hash
from shared.exceptions import AuthError, StorageError
from shared.usernames import build_enroll_signing_input, canonicalize_username

_KEY_PW = "key-pw-123456"
_FILE_ID = "abcd1234abcd1234abcd1234abcd1234"  # canonical 32-hex
_FAKE_TOKEN = "session-token-xyz"


# ──────────────────────────── fixtures ────────────────────────────


@pytest.fixture(scope="module")
def _shared_keystore(tmp_path_factory: pytest.TempPathFactory) -> KeyStore:
    """One genuine, unlocked KeyStore for the whole module.

    Generating + unlocking a real keystore each pays a multi-second
    Argon2id KDF; generating once and reusing the in-memory keypair (only
    read-only ops — sign / wrap — are exercised) keeps the suite fast while
    staying a REAL keystore. Never mutated, so reuse is deterministic.
    """
    key_dir = tmp_path_factory.mktemp("cli_ks")
    ks = KeyStore(str(key_dir / "identity.key"))
    ks.generate(_KEY_PW)
    return ks


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    """A fake home / key-file directory with a saved session.

    The CLI's ``_load_session`` requires a ``.session`` file next to the
    key file before any authenticated command runs, so we plant one. The
    key file itself need not exist on disk because ``_get_keystore`` is
    patched to return the shared real keystore.
    """
    lc = tmp_path / ".localcloud"
    lc.mkdir(mode=0o700)
    (lc / ".session").write_text(_FAKE_TOKEN)
    return lc


@pytest.fixture()
def keyfile(home: Path) -> str:
    return str(home / "keys.enc")


class FakeCloudClient:
    """Hand fake for ``CloudClient`` — the sole mocked HTTP boundary.

    Records calls and lets each test set return values / raises. Computing
    the genuine BLAKE2b chunk hash in ``upload_chunk`` lets a REAL upload
    drive end-to-end (the CLI rejects a mismatched server hash).
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self.token: str | None = None
        # Configurable behaviour.
        self.wrapped_keys_return: bytes | None = b"\x00" * 136
        self.owner_pubkey_return: bytes | None = None
        self.post_self_keys_raises: Exception | None = None
        self.metadata_return: dict | None = None
        self.unwrap_hook: Callable[[bytes], tuple[bytes, bytes]] | None = None
        # login / ls / quota / rm / unshare orchestration knobs.
        self.login_return: str = "session-token-from-server"
        self.login_raises: Exception | None = None
        self.list_files_return: list[dict] = []
        self.list_files_raises: Exception | None = None
        self.quota_return: dict = {
            "used_bytes": 1024,
            "available_bytes": 9216,
            "quota_bytes": 10240,
        }
        self.quota_raises: Exception | None = None
        self.delete_raises: Exception | None = None
        self.unshare_raises: Exception | None = None
        self.enroll_raises: Exception | None = None
        # Recipient directory lookup (share path). Empty dict ⇒ "not enrolled".
        self.pubkeys_return: dict[str, bytes] = {}
        # Captured payloads for assertions.
        self.self_keys_calls: list[tuple[str, bytes]] = []
        self.enroll_calls: list[tuple[bytes, bytes]] = []
        self.pubkeys_calls: list[str] = []
        self.share_calls: list[tuple[str, str, bytes]] = []
        self.login_calls: list[tuple[str, str]] = []
        self.list_files_calls: list[tuple[int, int]] = []
        self.delete_calls: list[str] = []
        self.unshare_calls: list[tuple[str, str]] = []

    # transport lifecycle
    def set_token(self, token: str) -> None:
        self.token = token

    def close(self) -> None:
        self.calls.append(("close", ()))

    # auth
    def login(self, username: str, password: str) -> str:
        self.login_calls.append((username, password))
        if self.login_raises is not None:
            raise self.login_raises
        return self.login_return

    # file management
    def list_files(self, limit: int = 50, offset: int = 0) -> list[dict]:
        self.list_files_calls.append((limit, offset))
        if self.list_files_raises is not None:
            raise self.list_files_raises
        return self.list_files_return

    def delete_file(self, file_id: str) -> None:
        self.delete_calls.append(file_id)
        if self.delete_raises is not None:
            raise self.delete_raises

    def get_quota(self) -> dict:
        if self.quota_raises is not None:
            raise self.quota_raises
        return self.quota_return

    def unshare_file(self, file_id: str, recipient: str) -> None:
        self.unshare_calls.append((file_id, recipient))
        if self.unshare_raises is not None:
            raise self.unshare_raises

    # upload path
    def upload_init(self, filename: str, expected_chunks: int) -> str:
        self.calls.append(("upload_init", (filename, expected_chunks)))
        return "upload-id-1"

    def upload_chunk(self, upload_id: str, idx: int, blob: bytes) -> str:
        self.calls.append(("upload_chunk", (upload_id, idx, len(blob))))
        # Echo back the genuine hash so the CLI's MITM check passes.
        return blake2b_hash(blob).hex()

    def upload_finalize(self, **kwargs) -> str:
        self.calls.append(("upload_finalize", (kwargs.get("file_id"),)))
        return kwargs["file_id"]

    def post_self_keys(self, file_id: str, bundle: bytes) -> None:
        self.self_keys_calls.append((file_id, bundle))
        if self.post_self_keys_raises is not None:
            raise self.post_self_keys_raises

    # download path
    def get_file_metadata(self, file_id: str) -> dict:
        self.calls.append(("get_file_metadata", (file_id,)))
        assert self.metadata_return is not None, "metadata_return not configured"
        return self.metadata_return

    def get_wrapped_keys(self, file_id: str) -> bytes | None:
        self.calls.append(("get_wrapped_keys", (file_id,)))
        return self.wrapped_keys_return

    def get_owner_pubkey(self, file_id: str) -> bytes | None:
        self.calls.append(("get_owner_pubkey", (file_id,)))
        return self.owner_pubkey_return

    # directory path
    def enroll_x25519(self, x25519_pubkey: bytes, self_sig: bytes) -> None:
        self.enroll_calls.append((x25519_pubkey, self_sig))
        if self.enroll_raises is not None:
            raise self.enroll_raises

    def get_pubkeys(self, username: str) -> dict[str, bytes]:
        self.pubkeys_calls.append(username)
        return dict(self.pubkeys_return)

    # sharing path
    def share_file(self, file_id: str, recipient: str, wrapped: bytes) -> None:
        self.share_calls.append((file_id, recipient, wrapped))


@pytest.fixture()
def fake_client() -> FakeCloudClient:
    return FakeCloudClient()


@pytest.fixture()
def patched_cli(
    monkeypatch: pytest.MonkeyPatch,
    _shared_keystore: KeyStore,
    fake_client: FakeCloudClient,
) -> Iterator[FakeCloudClient]:
    """Patch the two CLI seams: keystore factory + client factory.

    ``_get_keystore`` returns the shared real keystore (with ``unlock`` /
    ``lock`` neutered so the CLI doesn't re-run the KDF or zeroize the
    shared keypair). ``_get_client`` returns the per-test fake. The HTTP
    boundary is the ONLY thing mocked; all crypto is real.
    """
    import client.cli as cli_mod

    monkeypatch.setattr(cli_mod, "_get_keystore", lambda _kf: _shared_keystore)
    monkeypatch.setattr(cli_mod, "_get_client", lambda _srv: fake_client)
    # The shared keystore is already unlocked and must survive the module;
    # the CLI calls unlock() then lock() per command, so neuter both.
    monkeypatch.setattr(_shared_keystore, "unlock", lambda _pw: None)
    monkeypatch.setattr(_shared_keystore, "lock", lambda: None)
    yield fake_client


def _no_keys_json_anywhere(root: Path) -> bool:
    return not list(root.rglob("*.keys.json"))


def _write_cache(home: Path, file_id: str, ks: KeyStore) -> Path:
    """Write a legacy plaintext key cache the way the pre-2A client did."""
    cache = {
        "file_id": file_id,
        "file_key": (b"\x11" * 32).hex(),
        "meta_key": (b"\x22" * 32).hex(),
    }
    path = home / f"{file_id}.keys.json"
    path.write_text(json.dumps(cache))
    return path


# ──────────────────────────── migrate-keys ────────────────────────────


def test_migrate_keys_fail_closed_leaves_json(
    patched_cli: FakeCloudClient,
    home: Path,
    keyfile: str,
    _shared_keystore: KeyStore,
) -> None:
    """HIGH / addendum-mandated: a failed /self_keys POST LEAVES the JSON.

    The legacy cache is the user's only copy of these keys. If the POST
    raises (here: StorageError), the JSON must remain on disk — a
    regression that unlinked before a confirmed POST would destroy the
    user's keys irrecoverably.
    """
    cache_path = _write_cache(home, _FILE_ID, _shared_keystore)
    patched_cli.post_self_keys_raises = StorageError("server unavailable")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "migrate-keys"], input=f"{_KEY_PW}\n"
    )

    assert result.exit_code == 0, result.output
    # The single safety-critical assertion: the JSON survives the failure.
    assert cache_path.exists()
    assert "SKIP" in result.output
    assert "left 1 intact" in result.output
    assert "Migrated 0" in result.output
    # A POST was attempted (it raised) — the unlink simply never followed.
    assert len(patched_cli.self_keys_calls) == 1


def test_migrate_keys_success_wraps_then_unlinks(
    patched_cli: FakeCloudClient,
    home: Path,
    keyfile: str,
    _shared_keystore: KeyStore,
) -> None:
    """SUCCESS: wrap to own X25519 → 136-byte POST → THEN unlink the JSON."""
    cache_path = _write_cache(home, _FILE_ID, _shared_keystore)

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "migrate-keys"], input=f"{_KEY_PW}\n"
    )

    assert result.exit_code == 0, result.output
    assert not cache_path.exists()  # unlinked only after the POST succeeded
    assert "Migrated 1" in result.output
    assert "left 0 intact" in result.output
    # Exactly one self-share POST, carrying a 136-byte v2 bundle.
    assert len(patched_cli.self_keys_calls) == 1
    posted_id, bundle = patched_cli.self_keys_calls[0]
    assert posted_id == _FILE_ID
    assert len(bundle) == 136


def test_migrate_keys_rejects_invalid_file_id_before_url(
    patched_cli: FakeCloudClient,
    home: Path,
    keyfile: str,
) -> None:
    """An invalid file_id in the cache is rejected BEFORE any POST; JSON kept.

    The file_id is attacker-influenceable (it lived on disk) and feeds a
    server URL, so it must be validated first. The cache is left intact and
    no /self_keys call is made.
    """
    bad_id = "../../etc/passwd"
    path = home / "bad.keys.json"
    path.write_text(
        json.dumps(
            {
                "file_id": bad_id,
                "file_key": (b"\x11" * 32).hex(),
                "meta_key": (b"\x22" * 32).hex(),
            }
        )
    )

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "migrate-keys"], input=f"{_KEY_PW}\n"
    )

    assert result.exit_code == 0, result.output
    assert path.exists()  # left intact
    assert "SKIP" in result.output
    assert "Migrated 0" in result.output
    # Validation happened before any URL was built — no POST attempted.
    assert patched_cli.self_keys_calls == []


def test_migrate_keys_skips_corrupt_json_without_deleting(
    patched_cli: FakeCloudClient,
    home: Path,
    keyfile: str,
) -> None:
    """A malformed JSON cache is skipped (not deleted), not crashed on."""
    path = home / "corrupt.keys.json"
    path.write_text("{not valid json")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "migrate-keys"], input=f"{_KEY_PW}\n"
    )

    assert result.exit_code == 0, result.output
    assert path.exists()  # not deleted
    assert "SKIP" in result.output
    assert "Migrated 0" in result.output
    assert patched_cli.self_keys_calls == []


def test_migrate_keys_transport_error_clean_message(
    patched_cli: FakeCloudClient,
    home: Path,
    keyfile: str,
    _shared_keystore: KeyStore,
) -> None:
    """ERR-2: migrate-keys against an unreachable server → clean exit 1.

    A transport-level error from ``post_self_keys`` is not one of the typed
    errors the per-cache handler catches, so before the fix it escaped the
    outer try as a raw traceback. It must now surface a clean 'Migration
    failed' message + exit 1, and — fail-closed — leave the cache intact since
    the POST never completed.
    """
    cache_path = _write_cache(home, _FILE_ID, _shared_keystore)
    patched_cli.post_self_keys_raises = ConnectionRefusedError("connection refused")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "migrate-keys"], input=f"{_KEY_PW}\n"
    )

    assert result.exit_code == 1
    assert "Migration failed" in result.output
    assert "Traceback" not in result.output
    # Fail-closed: the user's only copy of the keys survives the failure.
    assert cache_path.exists()


# ──────────────────────────── upload ────────────────────────────


def test_upload_self_wraps_and_writes_no_cache(
    patched_cli: FakeCloudClient,
    tmp_path: Path,
    keyfile: str,
) -> None:
    """upload POSTs a 136-byte self-bundle and writes NO *.keys.json.

    Drives a real upload (real FileEncryptor through the CLI); only the
    HTTP boundary is faked. Pins item 2A: keys are self-wrapped to the
    owner's own X25519 and never persisted as plaintext on disk.
    """
    src = tmp_path / "payload.txt"
    src.write_bytes(b"hello world, this is a small upload payload")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--key-file", keyfile, "upload", str(src), "--visibility", "private"],
        input=f"{_KEY_PW}\n",
    )

    assert result.exit_code == 0, result.output
    assert "Upload complete" in result.output
    # Exactly one self-share POST with a 136-byte v2 bundle.
    assert len(patched_cli.self_keys_calls) == 1
    _posted_id, bundle = patched_cli.self_keys_calls[0]
    assert len(bundle) == 136
    # No plaintext key cache was written anywhere under the fake home.
    assert _no_keys_json_anywhere(tmp_path)


# ──────────────────────────── download ────────────────────────────


def _real_header(ks: KeyStore, tmp_path: Path, file_id_hex: str) -> dict:
    """Encrypt a 1-chunk file with a real encryptor → server metadata dict.

    Produces a genuine, deserializable FileHeader whose file_id matches
    ``file_id_hex`` so ``download`` passes its header/URL binding check and
    reaches the key-acquisition step (the thing under test).
    """
    from client.encryptor import FileEncryptor
    from shared.models import FileHeader, Visibility

    src = tmp_path / "dl_src.bin"
    src.write_bytes(b"download-source-bytes")
    enc = FileEncryptor(ks)
    res = enc.encrypt_file(
        input_path=src,
        filename="dl.bin",
        on_chunk=lambda _i, _b: None,
        visibility=Visibility.PRIVATE,
        owner="",
    )
    # Pin the header's file_id to the requested id so the URL/header
    # binding check passes; validate() (which does not check the signature)
    # still succeeds, and download fails at acquisition — before any
    # signature verification — which is the path under test.
    header: FileHeader = res.header
    header.file_id = bytes.fromhex(file_id_hex)
    return {
        "file_header": header.serialize().hex(),
        "encrypted_metadata": res.encrypted_metadata.hex(),
        "total_chunks": header.total_chunks,
    }


def test_download_fail_closed_no_cache_fallback(
    patched_cli: FakeCloudClient,
    tmp_path: Path,
    keyfile: str,
    _shared_keystore: KeyStore,
) -> None:
    """T-2A.3: no wrapped bundle → non-zero exit, NO plaintext-cache fallback.

    The server returns no self-share/recipient bundle, so
    ``acquire_file_keys`` (reached via the unified ``/wrapped_keys`` path)
    must fail closed. There is no plaintext keys.json fallback: even with a
    cache present on disk the command must NOT recover keys from it. We
    assert the command went through ``get_wrapped_keys`` (the unified path),
    failed non-zero, and wrote no output.
    """
    patched_cli.metadata_return = _real_header(_shared_keystore, tmp_path, _FILE_ID)
    patched_cli.wrapped_keys_return = None  # server has no bundle

    # A leftover cache that a (buggy) fallback might read — it must not let
    # the download succeed.
    _write_cache(tmp_path, _FILE_ID, _shared_keystore)

    out = tmp_path / "restored.bin"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--key-file", keyfile, "download", _FILE_ID, str(out)],
        input=f"{_KEY_PW}\n",
    )

    assert result.exit_code != 0
    assert "Download failed" in result.output
    assert not out.exists()
    # The unified key path was taken (and returned nothing) — not a cache read.
    methods = [c[0] for c in patched_cli.calls]
    assert "get_wrapped_keys" in methods


# ──────────────────────────── share ────────────────────────────


def test_share_fail_closed_without_owner_bundle(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    """share fails closed when acquire_file_keys cannot get the owner bundle.

    Uses ``--recipient-pubkey`` (a valid 32-byte hex) to bypass the
    directory lookup and isolate the failure at key acquisition: the caller
    has no self-share row, so ``get_wrapped_keys`` returns None and share
    must fail closed (no file_key to wrap) — never share an unkeyed file.
    """
    patched_cli.wrapped_keys_return = None  # no self-share row for the owner
    recipient_pk = (b"\x07" * 32).hex()

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--key-file",
            keyfile,
            "share",
            _FILE_ID,
            "bob",
            "--recipient-pubkey",
            recipient_pk,
        ],
        input=f"{_KEY_PW}\n",
    )

    assert result.exit_code != 0
    assert "Share failed" in result.output
    # Nothing was shared (no wrapped bundle ever uploaded).
    assert patched_cli.share_calls == []


def _install_owner_self_share(fake: FakeCloudClient, ks: KeyStore) -> None:
    """Set up a GENUINE owner self-share bundle so acquire_file_keys succeeds.

    Mirrors a real upload's ``/self_keys`` row: file_key+meta_key wrapped to the
    owner's own X25519, with ``/owner_pubkey`` returning the owner's Ed25519, so
    the CLI's unified key acquisition unwraps it for real (no plaintext cache).
    """
    raw_id = bytes.fromhex(_FILE_ID)
    fake.wrapped_keys_return = ks.wrap_file_keys(
        file_key=b"\x11" * 32,
        meta_key=b"\x22" * 32,
        file_id=raw_id,
        recipient_pubkey=ks.x25519_public_key(),
    )
    fake.owner_pubkey_return = ks.ed25519_public_key()


def _recipient_triple(username: str) -> dict[str, bytes]:
    """A GENUINE {ed25519, x25519, self_sig} directory triple for ``username``.

    Minted from a throwaway ``keycore.KeyPair`` (only ``KeyStore.generate`` pays
    the Argon2id KDF — raw ``KeyPair.generate`` is free), so the self-signature
    genuinely verifies under a DISTINCT identity each call. This is exactly what
    a hostile server returns when it substitutes a recipient's identity: a fully
    self-consistent triple it controls.
    """
    import keycore

    kp = keycore.KeyPair.generate()  # type: ignore[reportAttributeAccessIssue]
    ed = bytes(kp.ed25519_public_key())
    x = bytes(kp.x25519_public_key())
    canonical = canonicalize_username(username)
    sig = bytes(kp.sign(build_enroll_signing_input(canonical, x)))
    return {"ed25519": ed, "x25519": x, "self_sig": sig}


def test_share_directory_first_use_pins_recipient_and_succeeds(
    patched_cli: FakeCloudClient,
    keyfile: str,
    _shared_keystore: KeyStore,
) -> None:
    """(a) A first directory share to a new recipient pins their Ed25519.

    The verified directory triple lets the share proceed (TOFU first contact),
    and the recipient's Ed25519 is recorded under the canonical username only
    after the share POST succeeds.
    """
    _install_owner_self_share(patched_cli, _shared_keystore)
    triple = _recipient_triple("bob")
    patched_cli.pubkeys_return = triple

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "share", _FILE_ID, "bob"], input=f"{_KEY_PW}\n"
    )

    assert result.exit_code == 0, result.output
    assert len(patched_cli.share_calls) == 1
    # The directory was consulted under the canonical username, and the
    # recipient's Ed25519 is now TOFU-pinned for that username.
    assert patched_cli.pubkeys_calls == ["bob"]
    assert _load_recipient_pins(keyfile) == {"bob": triple["ed25519"].hex()}


def test_share_directory_rejects_substituted_recipient_key(
    patched_cli: FakeCloudClient,
    keyfile: str,
    _shared_keystore: KeyStore,
) -> None:
    """(b) CORE REGRESSION: a later share returning a DIFFERENT Ed25519 for the
    same recipient is refused fail-closed.

    A hostile server that substitutes the recipient's identity returns a fresh,
    fully self-consistent triple (so ``verify_x25519_self_sig`` passes), but the
    Ed25519 differs from the pinned one — the TOFU pin catches it. Fails before
    the fix (the share path never consulted any pin) and passes after.
    """
    _install_owner_self_share(patched_cli, _shared_keystore)
    runner = CliRunner()

    # First share: genuine identity A → pins bob→edA, succeeds.
    triple_a = _recipient_triple("bob")
    patched_cli.pubkeys_return = triple_a
    first = runner.invoke(
        cli, ["--key-file", keyfile, "share", _FILE_ID, "bob"], input=f"{_KEY_PW}\n"
    )
    assert first.exit_code == 0, first.output
    assert _load_recipient_pins(keyfile) == {"bob": triple_a["ed25519"].hex()}

    # Second share: server mints a FRESH identity B for the same username.
    triple_b = _recipient_triple("bob")
    assert triple_b["ed25519"] != triple_a["ed25519"]
    patched_cli.pubkeys_return = triple_b
    second = runner.invoke(
        cli, ["--key-file", keyfile, "share", _FILE_ID, "bob"], input=f"{_KEY_PW}\n"
    )

    assert second.exit_code != 0
    assert "Share failed" in second.output
    assert "changed since the first share" in second.output
    # Only the first share was ever uploaded; the pin still holds identity A.
    assert len(patched_cli.share_calls) == 1
    assert _load_recipient_pins(keyfile) == {"bob": triple_a["ed25519"].hex()}


def test_share_recipient_pubkey_override_skips_pin_store(
    patched_cli: FakeCloudClient,
    keyfile: str,
    _shared_keystore: KeyStore,
) -> None:
    """(c) The --recipient-pubkey path neither reads nor writes the recipient
    pin store, and never consults the directory.

    Proof it does not READ the store: a pre-planted CORRUPT store would
    fail-closed if consulted, yet the override share still succeeds. Proof it
    does not WRITE: the corrupt bytes are left exactly as written, and the
    directory was never called.
    """
    _install_owner_self_share(patched_cli, _shared_keystore)
    recipient_pk = _shared_keystore.x25519_public_key().hex()
    # A corrupt store that WOULD fail-closed on the directory path.
    _recipient_pins_path(keyfile).write_text("{ not json", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--key-file",
            keyfile,
            "share",
            _FILE_ID,
            "bob",
            "--recipient-pubkey",
            recipient_pk,
        ],
        input=f"{_KEY_PW}\n",
    )

    assert result.exit_code == 0, result.output
    assert len(patched_cli.share_calls) == 1
    # Directory NOT consulted, and the (corrupt) pin store NEITHER read NOR
    # written — left byte-for-byte as planted.
    assert patched_cli.pubkeys_calls == []
    assert _recipient_pins_path(keyfile).read_text(encoding="utf-8") == "{ not json"


# ──────────────────────────── enroll ────────────────────────────


def test_enroll_signs_canonical_username_and_posts(
    patched_cli: FakeCloudClient,
    keyfile: str,
    _shared_keystore: KeyStore,
) -> None:
    """enroll signs over the CANONICAL username and POSTs 32B key + 64B sig.

    A non-canonical input ('BOB') must be canonicalized ('bob') before the
    signing input is built, and the resulting self-signature must verify
    against the keystore's Ed25519 over exactly that canonical input.
    """
    import keycore

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "enroll", "BOB"], input=f"{_KEY_PW}\n"
    )

    assert result.exit_code == 0, result.output
    assert len(patched_cli.enroll_calls) == 1
    x25519_pub, self_sig = patched_cli.enroll_calls[0]
    assert len(x25519_pub) == 32
    assert len(self_sig) == 64
    assert x25519_pub == _shared_keystore.x25519_public_key()

    canonical = canonicalize_username("BOB")
    assert canonical == "bob"
    signing_input = build_enroll_signing_input(canonical, x25519_pub)
    # keycore native extension: no .pyi stub, verify_signature exists at
    # runtime (same suppression as client/keymgmt.py + server/users.py).
    assert keycore.verify_signature(  # type: ignore[reportAttributeAccessIssue]
        _shared_keystore.ed25519_public_key(), signing_input, self_sig
    )


def test_enroll_transport_error_clean_message(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    """ERR-2: enroll against an unreachable server → clean message + exit 1.

    A transport-level failure (connection refused / DNS / timeout) is NOT one
    of the typed (StorageError/CryptoError/AuthError/ProtocolError) errors, so
    before the fix it escaped as a raw traceback. It must now surface a clean
    'Enroll failed' line and exit 1.
    """
    patched_cli.enroll_raises = ConnectionRefusedError("connection refused")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "enroll", "bob"], input=f"{_KEY_PW}\n"
    )

    assert result.exit_code == 1
    assert "Enroll failed" in result.output
    assert "Traceback" not in result.output
    # The POST was attempted (it raised the transport error).
    assert len(patched_cli.enroll_calls) == 1


# ════════════════════ CLI-1 orchestration + UX fixes ════════════════════
#
# init / login / ls / rm / quota / unshare driven through CliRunner with the
# HTTP boundary mocked (FakeCloudClient), plus the cross-cutting UX fixes:
# RM-1 (--force/confirm), ERR-1 (clean unlock error), STDIO-1 (stdout/stderr
# split), ORDER-1 (session before password), VAL-1 (bounds), TLS-1 (warn).


class FakeKeyStore:
    """Lightweight KeyStore stand-in for ``init`` (avoids the Argon2 KDF).

    ``init`` orchestrates: has_keys check → password prompts → generate →
    print public keys → lock. None of that needs a real keypair, so this
    fake records ``generate`` and returns fixed public keys.
    """

    def __init__(self, has_keys: bool = False) -> None:
        self.has_keys = has_keys
        self.generated_with: str | None = None
        self.locked = False

    def generate(self, password: str) -> None:
        self.generated_with = password

    def x25519_public_key(self) -> bytes:
        return b"\x11" * 32

    def ed25519_public_key(self) -> bytes:
        return b"\x22" * 32

    def lock(self) -> None:
        self.locked = True


# ──────────────────────────── init ────────────────────────────


def test_init_writes_pubkeys_to_stdout_status_to_stderr(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import client.cli as cli_mod

    fake_ks = FakeKeyStore(has_keys=False)
    monkeypatch.setattr(cli_mod, "_get_keystore", lambda _kf: fake_ks)
    kf = tmp_path / ".localcloud" / "keys.enc"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--key-file", str(kf), "init"],
        input="pw-123456\npw-123456\n",
    )

    assert result.exit_code == 0, result.stderr
    assert fake_ks.generated_with == "pw-123456"
    # Public keys (data) → stdout.
    assert (b"\x11" * 32).hex() in result.stdout
    assert (b"\x22" * 32).hex() in result.stdout
    # Progress / status → stderr, never stdout.
    assert "Generating identity keypair" in result.stderr
    assert "Keys generated and saved" in result.stderr
    assert "Generating identity keypair" not in result.stdout


def test_init_password_mismatch_aborts_before_generate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import client.cli as cli_mod

    fake_ks = FakeKeyStore(has_keys=False)
    monkeypatch.setattr(cli_mod, "_get_keystore", lambda _kf: fake_ks)
    kf = tmp_path / ".localcloud" / "keys.enc"

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", str(kf), "init"], input="pw-one\npw-two\n"
    )

    assert result.exit_code == 1
    assert "Passwords do not match" in result.output
    assert fake_ks.generated_with is None  # never generated


def test_init_refuses_when_keys_exist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import client.cli as cli_mod

    fake_ks = FakeKeyStore(has_keys=True)
    monkeypatch.setattr(cli_mod, "_get_keystore", lambda _kf: fake_ks)
    kf = tmp_path / ".localcloud" / "keys.enc"

    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", str(kf), "init"])

    assert result.exit_code == 1
    assert "Keys already exist" in result.output
    assert fake_ks.generated_with is None


# ──────────────────────────── login ────────────────────────────


def test_login_saves_session_and_status_to_stderr(
    patched_cli: FakeCloudClient,
    home: Path,
    keyfile: str,
) -> None:
    patched_cli.login_return = "tok-abc"

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "login", "alice"], input="password\n"
    )

    assert result.exit_code == 0, result.stderr
    assert patched_cli.login_calls == [("alice", "password")]
    assert (home / ".session").read_text() == "tok-abc"
    # Status line is not machine data → stderr only.
    assert "Login successful" in result.stderr
    assert "Login successful" not in result.stdout


def test_login_failure_maps_clean_error(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    patched_cli.login_raises = AuthError("bad credentials")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "login", "alice"], input="password\n"
    )

    assert result.exit_code == 1
    assert "Login failed" in result.output
    assert "Traceback" not in result.output


# ──────────────────────────── ls ────────────────────────────


def test_ls_lists_rows_on_stdout(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    patched_cli.list_files_return = [
        {
            "file_id": _FILE_ID,
            "filename": "a.txt",
            "total_bytes": 2048,
            "visibility": 0,
        }
    ]

    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "ls"])

    assert result.exit_code == 0, result.stderr
    assert _FILE_ID in result.stdout
    assert "a.txt" in result.stdout
    assert patched_cli.list_files_calls == [(50, 0)]


def test_ls_empty_reports_no_files(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    patched_cli.list_files_return = []
    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "ls"])
    assert result.exit_code == 0
    assert "No files found" in result.output


@pytest.mark.parametrize("arg", ["--limit=0", "--limit=201", "--offset=-1"])
def test_ls_rejects_out_of_range_bounds(
    patched_cli: FakeCloudClient,
    keyfile: str,
    arg: str,
) -> None:
    """VAL-1: IntRange bounds are enforced by Click before the command runs."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "ls", arg])
    assert result.exit_code == 2  # Click usage error
    assert "Invalid value" in result.output
    assert patched_cli.list_files_calls == []  # never reached the client


def test_ls_malformed_response_clean_error(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    """ERR-2: a row missing required keys → clean message, no traceback."""
    patched_cli.list_files_return = [{"filename": "no-file-id"}]
    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "ls"])
    assert result.exit_code == 1
    assert "unexpected error" in result.output
    assert "Traceback" not in result.output


# ──────────────────────────── rm (RM-1) ────────────────────────────


def test_rm_force_skips_prompt_and_deletes(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "rm", _FILE_ID, "--force"])

    assert result.exit_code == 0, result.output
    assert patched_cli.delete_calls == [_FILE_ID]
    assert "Deleted" in result.output
    assert "cannot be undone" not in result.output  # no prompt was shown


def test_rm_declined_aborts_without_api_call(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "rm", _FILE_ID], input="n\n")

    assert result.exit_code != 0  # click.Abort
    assert patched_cli.delete_calls == []  # destructive call never made
    assert "cannot be undone" in result.output  # prompt was shown


def test_rm_confirmed_deletes(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "rm", _FILE_ID], input="y\n")

    assert result.exit_code == 0, result.output
    assert patched_cli.delete_calls == [_FILE_ID]
    assert "Deleted" in result.output


# ──────────────────────────── quota ────────────────────────────


def test_quota_numbers_on_stdout(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    patched_cli.quota_return = {
        "used_bytes": 1024,
        "available_bytes": 9216,
        "quota_bytes": 10240,
    }
    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "quota"])

    assert result.exit_code == 0, result.stderr
    assert "Used:" in result.stdout
    assert "Available:" in result.stdout
    assert "Total:" in result.stdout


def test_quota_malformed_response_clean_error(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    patched_cli.quota_return = {}  # missing keys → KeyError → broad fallback
    runner = CliRunner()
    result = runner.invoke(cli, ["--key-file", keyfile, "quota"])
    assert result.exit_code == 1
    assert "unexpected error" in result.output
    assert "Traceback" not in result.output


# ──────────────────────────── unshare (RM-1) ────────────────────────────


def test_unshare_force_skips_prompt(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "unshare", _FILE_ID, "bob", "--force"]
    )

    assert result.exit_code == 0, result.output
    assert patched_cli.unshare_calls == [(_FILE_ID, "bob")]
    assert "Unshared" in result.output


def test_unshare_declined_aborts_without_api_call(
    patched_cli: FakeCloudClient,
    keyfile: str,
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli, ["--key-file", keyfile, "unshare", _FILE_ID, "bob"], input="n\n"
    )

    assert result.exit_code != 0
    assert patched_cli.unshare_calls == []


# ──────────────────────── ORDER-1: session before password ────────────────


def test_download_no_session_exits_before_password_prompt(
    monkeypatch: pytest.MonkeyPatch,
    fake_client: FakeCloudClient,
    tmp_path: Path,
) -> None:
    """ORDER-1: with no session, the command exits BEFORE prompting for the
    key password (so the user never pays the ~1s Argon2 unlock)."""
    import client.cli as cli_mod

    monkeypatch.setattr(cli_mod, "_get_client", lambda _s: fake_client)
    kf = tmp_path / ".localcloud" / "keys.enc"
    kf.parent.mkdir(parents=True)
    # Deliberately NO .session file next to the key file.

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--key-file", str(kf), "download", _FILE_ID, str(tmp_path / "out.bin")],
    )

    assert result.exit_code != 0
    assert "No session" in result.output
    assert "Key password" not in result.output  # prompt never reached


# ──────────────────────── ERR-1: clean unlock failure ────────────────────


def test_download_wrong_password_clean_error_no_traceback(
    monkeypatch: pytest.MonkeyPatch,
    fake_client: FakeCloudClient,
    _shared_keystore: KeyStore,
) -> None:
    """ERR-1: a wrong key password yields a clean stderr error + exit 1,
    not an uncaught ValueError traceback."""
    import client.cli as cli_mod

    monkeypatch.setattr(cli_mod, "_get_client", lambda _s: fake_client)
    # Use the shared keystore's REAL on-disk file so unlock runs the genuine
    # KDF and fails on a wrong password. _get_keystore is intentionally NOT
    # patched here, so the CLI builds a real KeyStore over this file.
    key_file = Path(_shared_keystore.key_file)
    (key_file.parent / ".session").write_text(_FAKE_TOKEN)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--key-file",
            str(key_file),
            "download",
            _FILE_ID,
            str(key_file.parent / "out.bin"),
        ],
        input="the-wrong-password\n",
    )

    assert result.exit_code == 1
    assert "wrong password or unreadable key store" in result.output
    assert "Traceback" not in result.output


# ──────────────────────── STDIO-1: stdout/stderr split ────────────────────


def test_upload_progress_to_stderr_file_id_to_stdout(
    patched_cli: FakeCloudClient,
    tmp_path: Path,
    keyfile: str,
) -> None:
    src = tmp_path / "payload.txt"
    src.write_bytes(b"hello world payload for the stdout/stderr split test")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--key-file", keyfile, "upload", str(src), "--visibility", "private"],
        input=f"{_KEY_PW}\n",
    )

    assert result.exit_code == 0, result.stderr
    # Data: the final file_id line is on stdout.
    assert "Upload complete. File ID:" in result.stdout
    # Progress is on stderr, NOT stdout.
    for progress in (
        "Initializing upload",
        "uploaded chunk",
        "Encrypting + uploading",
        "Finalizing",
    ):
        assert progress not in result.stdout
        assert progress in result.stderr


# ──────────────────────── TLS-1: insecure-server warning ──────────────────
#
# The warning now fires at connection-open (CloudClient.__init__), at most
# once per process — not from the CLI group callback. The connection-level
# "warns exactly once / silent for loopback" behaviour is pinned in
# tests/test_api_client.py against the REAL client; here we pin the CLI-level
# property that a purely-local command (``init``) never opens a connection and
# therefore emits NO warning, even against a non-loopback plain-http server.


def test_init_emits_no_insecure_warning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import client.cli as cli_mod

    fake_ks = FakeKeyStore(has_keys=False)
    monkeypatch.setattr(cli_mod, "_get_keystore", lambda _kf: fake_ks)
    kf = tmp_path / ".localcloud" / "keys.enc"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--server", "http://10.0.0.1", "--key-file", str(kf), "init"],
        input="pw-123456\npw-123456\n",
    )

    assert result.exit_code == 0, result.output
    # init opens no connection → no insecure-server warning at all.
    assert "plain HTTP to a non-loopback host" not in result.output


# ──────────────────────── VAL-1: filename-length guard ────────────────────


def test_check_filename_len_rejects_overlong() -> None:
    from client.cli import _check_filename_len

    with pytest.raises(ValueError):
        _check_filename_len("a" * 256)


def test_check_filename_len_rejects_empty() -> None:
    from client.cli import _check_filename_len

    with pytest.raises(ValueError):
        _check_filename_len("")


def test_check_filename_len_accepts_valid() -> None:
    from client.cli import _check_filename_len

    _check_filename_len("normal-file.txt")  # no raise
    _check_filename_len("a" * 255)  # boundary length is accepted
