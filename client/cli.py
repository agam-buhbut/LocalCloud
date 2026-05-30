# LocalCloud - Client CLI
#
# Command-line interface for LocalCloud operations.
# Uses Click for argument parsing and the client modules for crypto/API.

from __future__ import annotations

import contextlib
import hmac
import json
import os
import sys
from pathlib import Path

import click

from client.api_client import CloudClient
from client.encryptor import FileEncryptor
from client.keystore import KeyStore
from shared.crypto import blake2b_hash
from shared.exceptions import AuthError, CryptoError, StorageError
from shared.file_ids import canonicalize_file_id
from shared.io import read_capped
from shared.models import FileHeader, Visibility

# Default paths
DEFAULT_KEY_FILE = str(Path.home() / ".localcloud" / "keys.enc")
DEFAULT_SERVER = "http://10.0.0.1:8443"

_VIS_MAP: dict[str, Visibility] = {
    "private": Visibility.PRIVATE,
    "shared": Visibility.SHARED,
    "public": Visibility.PUBLIC,
}


def _get_keystore(key_file: str) -> KeyStore:
    return KeyStore(key_file)


def _get_client(server: str) -> CloudClient:
    return CloudClient(server)


def _atomic_write_secret(path: Path, data: str) -> None:
    """Write a secret-bearing string to ``path`` with mode 0o600.

    Uses O_CREAT|O_EXCL|O_NOFOLLOW + chmod-at-create so the file is
    never world-readable, even briefly. (#F3, #32)
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Best-effort: tighten parent dir even if it pre-existed with a
    # broader mode. We swallow the error because a pre-existing dir we
    # don't own is the operator's call to make.
    with contextlib.suppress(OSError):
        os.chmod(path.parent, 0o700)
    # Randomized tempfile in the same dir: closes the TOCTOU window
    # where an attacker could plant a symlink between the exists() probe
    # and the O_EXCL open at a deterministic path. (Round-2 H10)
    import tempfile as _tempfile

    fd, tmp_name = _tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
        # tempfile.mkstemp already creates with mode 0o600. (Round-8 INFO #4)
        os.replace(tmp_name, str(path))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


@click.group()
@click.option(
    "--key-file",
    default=DEFAULT_KEY_FILE,
    envvar="LOCALCLOUD_KEY_FILE",
    help="Path to encrypted key file",
)
@click.option(
    "--server",
    default=DEFAULT_SERVER,
    envvar="LOCALCLOUD_SERVER",
    help="Server URL",
)
@click.pass_context
def cli(ctx, key_file: str, server: str):
    """LocalCloud — Encrypted personal cloud storage."""
    ctx.ensure_object(dict)
    ctx.obj["key_file"] = key_file
    ctx.obj["server"] = server


@cli.command()
@click.pass_context
def init(ctx):
    """Generate a new identity keypair."""
    ks = _get_keystore(ctx.obj["key_file"])
    if ks.has_keys:
        click.echo("Error: Keys already exist. Delete the key file first.", err=True)
        sys.exit(1)

    password = click.prompt("Enter password for key encryption", hide_input=True)
    confirm = click.prompt("Confirm password", hide_input=True)
    if password != confirm:
        click.echo("Error: Passwords do not match.", err=True)
        sys.exit(1)

    click.echo(
        "Generating identity keypair (this may take a moment due to Argon2id)..."
    )
    try:
        ks.generate(password)
        click.echo(f"Keys generated and saved to {ctx.obj['key_file']}")
        click.echo(f"X25519 public key: {ks.x25519_public_key().hex()}")
        click.echo(f"Ed25519 public key: {ks.ed25519_public_key().hex()}")
    finally:
        ks.lock()


@cli.command()
@click.argument("username")
@click.pass_context
def login(ctx, username: str):
    """Authenticate with the server."""
    password = click.prompt("Password", hide_input=True)
    client = _get_client(ctx.obj["server"])
    try:
        token = client.login(username, password)
        token_path = Path(ctx.obj["key_file"]).parent / ".session"
        _atomic_write_secret(token_path, token)
        click.echo("Login successful. Session saved.")
    except (AuthError, StorageError) as e:
        click.echo(f"Login failed: {e}", err=True)
        sys.exit(1)
    except Exception:
        click.echo("Login failed: unexpected error", err=True)
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.argument("username")
@click.pass_context
def enroll(ctx, username: str):
    """Enroll your X25519 key in the server directory (item 2C).

    Derives the X25519 public key from your keystore, signs the
    domain-separated, username-bound enroll input with your Ed25519 key,
    and POSTs both to the server. After enrolling, other users can wrap
    file keys to you via the directory (no out-of-band key exchange).

    ``username`` must be the account name you log in as; it is bound into
    the self-signature so the key cannot be lifted onto another account.
    """
    from client.keymgmt import build_enroll_signing_input
    from shared.usernames import canonicalize_username

    ks = _get_keystore(ctx.obj["key_file"])
    if not ks.has_keys:
        click.echo("Error: No keys found. Run 'localcloud init' first.", err=True)
        sys.exit(1)
    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)
    try:
        try:
            canonical = canonicalize_username(username)
        except Exception as e:
            raise CryptoError(f"Invalid username: {username!r}") from e
        x25519_pub = ks.x25519_public_key()
        signing_input = build_enroll_signing_input(canonical, x25519_pub)
        self_sig = ks.sign(signing_input)
        client.enroll_x25519(x25519_pub, self_sig)
        click.echo(f"Enrolled X25519 key for {canonical}.")
    except (StorageError, CryptoError, AuthError) as e:
        click.echo(f"Enroll failed: {e}", err=True)
        sys.exit(1)
    finally:
        ks.lock()
        client.close()


def _resolve_owner_pubkey(
    client: CloudClient, file_id: str, override_hex: str | None
) -> bytes:
    """Resolve the signer pubkey for downloading.

    Priority: explicit --sender-pubkey override > server lookup. The
    server-returned pubkey is the one registered against the file
    owner's account; the client treats it as a TOFU-pinnable identity.
    """
    if override_hex:
        try:
            pk = bytes.fromhex(override_hex)
        except ValueError as e:
            raise CryptoError("--sender-pubkey is not valid hex") from e
        if len(pk) != 32:
            raise CryptoError("--sender-pubkey must be 32 bytes")
        return pk

    pk = client.get_owner_pubkey(file_id)
    if pk is None or len(pk) != 32:
        raise CryptoError(
            "Server has no registered identity key for this file's owner; "
            "pass --sender-pubkey explicitly if you trust an out-of-band key."
        )
    return pk


def _encrypt_and_upload(
    client: CloudClient, encryptor: FileEncryptor, src: Path, vis: Visibility
):
    """Init the upload, stream-encrypt + upload every chunk, finalize.

    Returns the ``EncryptedFile`` result (carrying file_key/meta_key for the
    subsequent self-wrap) and the server-confirmed ``file_id``. Behavior is
    unchanged from the inline body: the per-chunk hash is cross-checked
    against the server echo, and the authoritative ``expected_hashes`` sent
    to finalize are the CLIENT-computed hashes (never the server echoes).
    """
    import math

    filename = src.name
    size = src.stat().st_size
    # Pre-compute total chunks so upload_init can pass expected_chunks
    # (the server enforces the count at finalize).
    total_chunks = max(1, math.ceil(size / encryptor.chunk_size))

    click.echo(
        f"Initializing upload: {filename} ({size} bytes, {total_chunks} chunks)..."
    )
    upload_id = client.upload_init(filename, total_chunks)

    def on_chunk(idx: int, blob: bytes) -> None:
        # Upload the chunk and verify the server's echoed-back BLAKE2b hash
        # matches the locally computed one — defense in depth. The
        # authoritative expected-hashes list passed to finalize comes from
        # ``encrypted.chunk_hashes`` (the CLIENT view), not from server
        # returns; using server returns there would make the integrity
        # check a tautology the server could trivially defeat. (Round-3
        # CRITICAL fix)
        server_hash = client.upload_chunk(upload_id, idx, blob)
        local_hash = blake2b_hash(blob).hex()
        if not hmac.compare_digest(server_hash, local_hash):
            raise CryptoError(
                "Server echoed a different chunk hash than the client "
                "computed — possible MITM or storage corruption"
            )
        click.echo(f"  uploaded chunk {idx + 1}/{total_chunks}")

    click.echo("Encrypting + uploading...")
    encrypted = encryptor.encrypt_file(
        src,
        filename,
        on_chunk,
        visibility=vis,
        owner="",
    )

    # Authoritative hash list: the client's locally computed BLAKE2b over
    # each (nonce || ciphertext) chunk blob, captured during encrypt_file.
    # The server compares ITS own stored hash against this — any divergence
    # (server tampered, disk corruption, network bit-flip) causes finalize
    # to reject.
    client_hashes = [h.hex() for h in encrypted.chunk_hashes]
    click.echo("Finalizing...")
    file_id = client.upload_finalize(
        upload_id=upload_id,
        file_id=encrypted.header.file_id.hex(),
        total_chunks=encrypted.header.total_chunks,
        file_header=encrypted.header.serialize(),
        encrypted_metadata=encrypted.encrypted_metadata,
        visibility=int(vis),
        expected_hashes=client_hashes,
    )
    return encrypted, file_id


def _register_owner_self_keys(
    client: CloudClient, ks: KeyStore, encrypted, file_id: str
) -> None:
    """Wrap the file's keys to the owner's OWN X25519 and register them (2A).

    The wrap uses the LOCAL keypair (own X25519 as recipient, own Ed25519 as
    the internal sender binding) — it does NOT depend on directory
    enrollment. No plaintext key is written to disk; the owner later acquires
    the keys through the same server path as any recipient.
    """
    own_x25519 = ks.x25519_public_key()
    self_bundle = ks.wrap_file_keys(
        file_key=encrypted.file_key,
        meta_key=encrypted.meta_key,
        file_id=encrypted.header.file_id,
        recipient_pubkey=own_x25519,
    )
    client.post_self_keys(file_id, self_bundle)


@cli.command()
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--visibility",
    type=click.Choice(["private", "shared", "public"]),
    default="private",
)
@click.pass_context
def upload(ctx, filepath: str, visibility: str):
    """Encrypt and upload a file (streaming).

    After upload the owner's file_key/meta_key are wrapped to the owner's
    OWN X25519 key and registered server-side as a self-share (item 2A);
    no plaintext key is written to disk. The owner later acquires the keys
    through the same server path as any recipient.
    """
    ks = _get_keystore(ctx.obj["key_file"])
    if not ks.has_keys:
        click.echo("Error: No keys found. Run 'localcloud init' first.", err=True)
        sys.exit(1)

    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        vis = _VIS_MAP[visibility]
        encryptor = FileEncryptor(ks)
        encrypted, file_id = _encrypt_and_upload(client, encryptor, Path(filepath), vis)
        _register_owner_self_keys(client, ks, encrypted, file_id)
        click.echo(f"Upload complete. File ID: {file_id}")
    except (StorageError, CryptoError, AuthError) as e:
        click.echo(f"Upload failed: {e}", err=True)
        sys.exit(1)
    except Exception:
        click.echo("Upload failed: unexpected error", err=True)
        sys.exit(1)
    finally:
        ks.lock()
        client.close()


def _fetch_metadata_and_header(
    client: CloudClient, file_id: str
) -> tuple[bytes, bytes, int, FileHeader]:
    """Fetch file metadata, parse the header, and verify the file_id binding.

    Returns ``(header_bytes, encrypted_metadata, total_chunks, header)``.

    Defense in depth: the URL file_id MUST match the cryptographic file_id
    inside the header so a hostile server cannot substitute a different
    file. Both sides are canonicalized to lowercase, hyphen-free before
    compare (URLs are case-insensitive; Python ``str ==`` is not). (Round-3
    H8)
    """
    click.echo(f"Fetching metadata for {file_id}...")
    metadata = client.get_file_metadata(file_id)
    header_bytes = bytes.fromhex(metadata["file_header"])
    enc_meta = bytes.fromhex(metadata["encrypted_metadata"])
    total_chunks = int(metadata["total_chunks"])

    header = FileHeader.deserialize(header_bytes)
    url_canon = file_id.lower().replace("-", "")
    if header.file_id.hex() != url_canon:
        raise CryptoError("Header file_id does not match requested file_id")
    return header_bytes, enc_meta, total_chunks, header


@cli.command()
@click.argument("file_id")
@click.argument("output", type=click.Path(dir_okay=False))
@click.option(
    "--sender-pubkey",
    default=None,
    help="Hex-encoded Ed25519 public key of the file owner (overrides server lookup).",
)
@click.pass_context
def download(
    ctx,
    file_id: str,
    output: str,
    sender_pubkey: str | None,
):
    """Download and decrypt a file (streaming).

    Keys are acquired through the unified server path (item 2A): the
    wrapped bundle is fetched and unwrapped with the local X25519 key — the
    same path for an owner (self-share) and a recipient. There is no
    plaintext key cache on disk.
    """
    from client.keymgmt import acquire_file_keys

    ks = _get_keystore(ctx.obj["key_file"])
    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        header_bytes, enc_meta, total_chunks, _header = _fetch_metadata_and_header(
            client, file_id
        )

        # 2A unified acquisition: fetch + unwrap the bundle for THIS caller
        # (owner self-share or recipient share alike). The Merkle signature
        # is verified against the file OWNER's Ed25519 key, which is also
        # the wrap's sender binding; _resolve_owner_pubkey honors an
        # explicit --sender-pubkey override and otherwise pins the
        # server-returned key (TOFU). One path, fail-closed.
        click.echo("Acquiring and unwrapping file keys...")
        file_key, meta_key = acquire_file_keys(client, ks, file_id)
        sig_pubkey = _resolve_owner_pubkey(client, file_id, sender_pubkey)

        click.echo("Decrypting and verifying...")
        encryptor = FileEncryptor(ks)
        encryptor.decrypt_file(
            input_chunks=client.iter_chunks(file_id, total_chunks),
            header_data=header_bytes,
            encrypted_metadata=enc_meta,
            file_key=file_key,
            meta_key=meta_key,
            signer_pubkey=sig_pubkey,
            output_path=Path(output),
        )
        click.echo(f"Saved to {output}")
    except (StorageError, CryptoError, AuthError) as e:
        click.echo(f"Download failed: {e}", err=True)
        sys.exit(1)
    except Exception:
        click.echo("Download failed: unexpected error", err=True)
        sys.exit(1)
    finally:
        ks.lock()
        client.close()


@cli.command("ls")
@click.option("--limit", default=50, type=int, help="Page size (max 200).")
@click.option("--offset", default=0, type=int)
@click.pass_context
def list_files(ctx, limit: int, offset: int):
    """List accessible files."""
    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        files = client.list_files(limit=limit, offset=offset)
        if not files:
            click.echo("No files found.")
            return

        click.echo(f"{'File ID':<40} {'Filename':<30} {'Size':>12} {'Visibility':<10}")
        click.echo("-" * 95)
        for f in files:
            vis_idx = int(f.get("visibility", 0))
            vis = ["private", "shared", "public"][vis_idx] if 0 <= vis_idx <= 2 else "?"
            tb = f.get("total_bytes")
            size = _format_size(tb) if tb is not None else "—"
            click.echo(f"{f['file_id']:<40} {f['filename']:<30} {size:>12} {vis:<10}")
    except (StorageError, AuthError) as e:
        click.echo(f"Failed: {e}", err=True)
        sys.exit(1)
    finally:
        client.close()


@cli.command("rm")
@click.argument("file_id")
@click.pass_context
def remove_file(ctx, file_id: str):
    """Delete a file."""
    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        client.delete_file(file_id)
        click.echo(f"Deleted {file_id}")
    except (StorageError, AuthError) as e:
        click.echo(f"Delete failed: {e}", err=True)
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.pass_context
def quota(ctx):
    """Show storage quota."""
    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        info = client.get_quota()
        click.echo(f"Used:      {_format_size(info['used_bytes'])}")
        click.echo(f"Available: {_format_size(info['available_bytes'])}")
        click.echo(f"Total:     {_format_size(info['quota_bytes'])}")
    except (StorageError, AuthError) as e:
        click.echo(f"Failed: {e}", err=True)
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.argument("file_id")
@click.argument("recipient")
@click.option(
    "--recipient-pubkey",
    default=None,
    help=(
        "Optional out-of-band override of the recipient's X25519 public "
        "key (hex). Skips the directory lookup — only use if you trust "
        "this key from an out-of-band channel. By default the recipient's "
        "key is resolved AND verified via the server directory."
    ),
)
@click.pass_context
def share(
    ctx,
    file_id: str,
    recipient: str,
    recipient_pubkey: str | None,
):
    """Share a file with another user.

    Resolves the recipient's X25519 public key from the server directory
    and verifies the recipient's Ed25519 self-signature over it before
    wrapping (so a hostile server cannot substitute its own key). The
    client wraps file_key+meta_key for the verified recipient and uploads
    the wrapped bundle; the server never sees plaintext keys.

    Pass ``--recipient-pubkey`` to override the directory with an
    out-of-band key (explicit trust; the self-signature check is skipped
    because there is no directory entry to verify).
    """
    from client.keymgmt import acquire_file_keys, resolve_recipient

    ks = _get_keystore(ctx.obj["key_file"])
    if not ks.has_keys:
        click.echo("Error: No keys found.", err=True)
        sys.exit(1)
    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)
    try:
        if recipient_pubkey is not None:
            # Explicit out-of-band override: the operator vouches for this
            # key directly, so we do not consult (or trust) the directory.
            try:
                recipient_pk = bytes.fromhex(recipient_pubkey)
            except ValueError as e:
                raise CryptoError("--recipient-pubkey is not valid hex") from e
            if len(recipient_pk) != 32:
                raise CryptoError("--recipient-pubkey must be 32 bytes")
        else:
            # Default: resolve + MANDATORILY verify via the directory.
            # resolve_recipient fails closed on a missing/invalid self-sig.
            recipient_pk = resolve_recipient(client, recipient)

        # 2A: the owner re-acquires their own file_key/meta_key through the
        # unified server path (own self-share row) — no plaintext cache.
        # Only the owner has a self-share bundle, so a non-owner fails
        # closed here.
        file_key, meta_key = acquire_file_keys(client, ks, file_id)

        try:
            raw_id = bytes.fromhex(file_id.replace("-", ""))
        except ValueError as e:
            raise CryptoError("file_id is not valid hex") from e
        if len(raw_id) != 16:
            raise CryptoError("file_id must encode 16 bytes")

        wrapped = ks.wrap_file_keys(
            file_key=file_key,
            meta_key=meta_key,
            file_id=raw_id,
            recipient_pubkey=recipient_pk,
        )
        client.share_file(file_id, recipient, wrapped)
        click.echo(f"Shared {file_id} with {recipient}")
    except (StorageError, CryptoError, AuthError) as e:
        click.echo(f"Share failed: {e}", err=True)
        sys.exit(1)
    finally:
        ks.lock()
        client.close()


@cli.command()
@click.argument("file_id")
@click.argument("recipient")
@click.pass_context
def unshare(ctx, file_id: str, recipient: str):
    """Revoke a previously-granted share for a recipient.

    Server-side revocation only — anyone who already downloaded the
    wrapped keys still has them offline. For true revocation, re-upload
    the file (which generates a new file_key). (Round-3 M9)
    """
    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)
    try:
        client.unshare_file(file_id, recipient)
        click.echo(f"Unshared {file_id} from {recipient}")
    except (StorageError, AuthError) as e:
        click.echo(f"Unshare failed: {e}", err=True)
        sys.exit(1)
    finally:
        client.close()


@cli.command("migrate-keys")
@click.option(
    "--key-cache",
    default=None,
    help=(
        "Extra directory or single <file_id>.keys.json to migrate, in "
        "addition to the default key-file directory."
    ),
)
@click.pass_context
def migrate_keys(ctx, key_cache: str | None):
    """Retire legacy plaintext <file_id>.keys.json caches (item 2A).

    For each cached file, wrap the cached file_key/meta_key to your OWN
    X25519 key and register it server-side as a self-share, then delete the
    JSON. This converts the only plaintext-key-at-rest path into the
    unified server-delivered bundle.

    Fail-closed: a cache whose self-keys POST fails is LEFT INTACT (never
    deleted). Each file_id is validated BEFORE it is used in a URL.

    SECURITY: deletion is a plain ``os.unlink`` — NOT a secure wipe. An
    in-place overwrite is not reliable on copy-on-write / SSD / journaled
    filesystems, so any keys.json that ever existed should be treated as
    potentially already compromised (e.g. captured in a backup or by a
    second local user). Migration removes the live file; it cannot
    guarantee no copy survives elsewhere.
    """
    ks = _get_keystore(ctx.obj["key_file"])
    if not ks.has_keys:
        click.echo("Error: No keys found. Run 'localcloud init' first.", err=True)
        sys.exit(1)
    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        own_x25519 = ks.x25519_public_key()
        caches = _discover_key_caches(Path(ctx.obj["key_file"]).parent, key_cache)
        if not caches:
            click.echo("No keys.json caches found to migrate.")
            return

        migrated = 0
        failed = 0
        for cache_path in caches:
            try:
                cache = _load_owner_key_cache(cache_path)
                cached_id = cache["file_id"]
                # Validate the file_id BEFORE building any /self_keys URL —
                # the cache content is attacker-influenceable (it lived on
                # disk) and feeds straight into a server path.
                safe_id = _validate_file_id_local(cached_id)
                raw_id = bytes.fromhex(safe_id)
                file_key = bytes.fromhex(cache["file_key"])
                meta_key = bytes.fromhex(cache["meta_key"])
                bundle = ks.wrap_file_keys(
                    file_key=file_key,
                    meta_key=meta_key,
                    file_id=raw_id,
                    recipient_pubkey=own_x25519,
                )
                client.post_self_keys(safe_id, bundle)
            except (StorageError, CryptoError, AuthError, ValueError, KeyError) as e:
                # Fail-closed: leave the JSON intact so the keys are not lost.
                failed += 1
                click.echo(f"  SKIP {cache_path.name}: {e}", err=True)
                continue
            # POST succeeded — best-effort plain unlink (see docstring).
            with contextlib.suppress(OSError):
                os.unlink(cache_path)
            migrated += 1
            click.echo(f"  migrated + removed {cache_path.name}")

        click.echo(f"Done. Migrated {migrated}, left {failed} intact.")
    finally:
        ks.lock()
        client.close()


# ──────────── Helpers ────────────


def _discover_key_caches(key_dir: Path, extra: str | None) -> list[Path]:
    """Collect legacy ``*.keys.json`` cache files to migrate.

    Globs ``key_dir`` for ``*.keys.json`` and, if ``extra`` is given,
    adds either that single file or every ``*.keys.json`` under that
    directory. Returns a de-duplicated, sorted list of existing paths.
    """
    found: set[Path] = set()
    if key_dir.is_dir():
        found.update(p for p in key_dir.glob("*.keys.json") if p.is_file())
    if extra:
        extra_path = Path(extra)
        if extra_path.is_dir():
            found.update(p for p in extra_path.glob("*.keys.json") if p.is_file())
        elif extra_path.is_file():
            found.add(extra_path)
    return sorted(found)


def _validate_file_id_local(file_id: str) -> str:
    """Validate a server-supplied file_id before using it as part of
    a local filesystem name. Without this, a hostile file_id with
    path separators or ``..`` could escape the keys-cache directory.
    Returns the canonical 32-char hex form. (Round-10 M5)

    Thin wrapper over the shared ``canonicalize_file_id`` (Phase 3B dedup)
    that re-raises the shared ``ValueError`` as the client's ``CryptoError``
    so the existing caller contract is unchanged.
    """
    try:
        return canonicalize_file_id(file_id)
    except ValueError as e:
        raise CryptoError(f"Invalid file_id format: {file_id!r}") from e


def _load_owner_key_cache(cache_path: Path) -> dict:
    """Read an owner key-cache JSON with a single-syscall size cap.
    Cap = 4 KiB; legitimate cache is < 1 KiB.
    """
    try:
        data = read_capped(cache_path, 4 * 1024)
    except ValueError as e:
        raise CryptoError(str(e)) from e
    return json.loads(data)


def _load_session(ctx, client: CloudClient) -> None:
    """Load saved session token with a single-syscall size cap."""
    token_path = Path(ctx.obj["key_file"]).parent / ".session"
    if not token_path.exists():
        click.echo("No session found. Run 'localcloud login' first.", err=True)
        sys.exit(1)
    try:
        data = read_capped(token_path, 16 * 1024)
    except (ValueError, OSError) as e:
        click.echo(f"Session file unreadable: {e}", err=True)
        sys.exit(1)
    client.set_token(data.decode("utf-8", errors="strict").strip())


def _format_size(bytes_val: int) -> str:
    """Format bytes into human-readable size."""
    size = float(bytes_val)
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PiB"


def main():
    # `cli` is a click.Group; calling it dispatches via click's __call__,
    # which reads sys.argv and supplies ctx/params itself. pylint (astroid)
    # doesn't model the @click.group decorator transform, so it sees the
    # undecorated cli(ctx, key_file, server) signature — a false positive.
    cli()  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    main()
