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

from client.cli import cli
from client.keystore import KeyStore
from shared.crypto import blake2b_hash
from shared.exceptions import StorageError
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
        # Captured payloads for assertions.
        self.self_keys_calls: list[tuple[str, bytes]] = []
        self.enroll_calls: list[tuple[bytes, bytes]] = []
        self.share_calls: list[tuple[str, str, bytes]] = []

    # transport lifecycle
    def set_token(self, token: str) -> None:
        self.token = token

    def close(self) -> None:
        self.calls.append(("close", ()))

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
