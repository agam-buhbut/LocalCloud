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


@cli.command()
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--visibility",
    type=click.Choice(["private", "shared", "public"]),
    default="private",
)
@click.option(
    "--key-cache",
    default=None,
    help=(
        "Where to save the owner's file_key/meta_key as a local JSON "
        "cache (so the owner can decrypt their own file). Default: "
        "next to the encrypted key file, named <file_id>.keys.json"
    ),
)
@click.pass_context
def upload(ctx, filepath: str, visibility: str, key_cache: str | None):
    """Encrypt and upload a file (streaming)."""
    ks = _get_keystore(ctx.obj["key_file"])
    if not ks.has_keys:
        click.echo("Error: No keys found. Run 'localcloud init' first.", err=True)
        sys.exit(1)

    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        src = Path(filepath)
        filename = src.name
        size = src.stat().st_size
        encryptor = FileEncryptor(ks)
        # Pre-compute total chunks so we can call upload_init with
        # expected_chunks (server uses it to enforce the count at
        # finalize).
        import math

        total_chunks = max(1, math.ceil(size / encryptor.chunk_size))

        click.echo(
            f"Initializing upload: {filename} ({size} bytes, {total_chunks} chunks)..."
        )
        upload_id = client.upload_init(filename, total_chunks)

        def on_chunk(idx: int, blob: bytes) -> None:
            # We upload the chunk and also verify that the server's
            # echoed-back BLAKE2b hash matches the one we computed
            # locally — defense in depth. The authoritative expected-
            # hashes list passed to finalize comes from `encrypted.
            # chunk_hashes` (the CLIENT view), not from server returns;
            # using server returns there would make the integrity check
            # a tautology the server could trivially defeat. (Round-3
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
            visibility=_VIS_MAP[visibility],
            owner="",
        )

        file_id_hex = encrypted.header.file_id.hex()
        # Authoritative hash list: the client's locally computed BLAKE2b
        # over each (nonce || ciphertext) chunk blob, captured during
        # encrypt_file. The server compares ITS own stored hash against
        # this — any divergence (server tampered, disk corruption,
        # network bit-flip) causes finalize to reject.
        client_hashes = [h.hex() for h in encrypted.chunk_hashes]
        click.echo("Finalizing...")
        file_id = client.upload_finalize(
            upload_id=upload_id,
            file_id=file_id_hex,
            total_chunks=encrypted.header.total_chunks,
            file_header=encrypted.header.serialize(),
            encrypted_metadata=encrypted.encrypted_metadata,
            visibility=int(_VIS_MAP[visibility]),
            expected_hashes=client_hashes,
        )

        # Persist owner key cache so the owner can later decrypt their
        # own file. Cache file is mode 0o600. Validate file_id locally
        # before using it as part of a filesystem name. (Round-10 M5)
        safe_id = _validate_file_id_local(file_id)
        cache_path = (
            Path(key_cache)
            if key_cache
            else Path(ctx.obj["key_file"]).parent / f"{safe_id}.keys.json"
        )
        cache_payload = json.dumps(
            {
                "file_id": file_id,
                "file_key": encrypted.file_key.hex(),
                "meta_key": encrypted.meta_key.hex(),
            }
        )
        _atomic_write_secret(cache_path, cache_payload)
        click.echo(f"Upload complete. File ID: {file_id}")
        click.echo(f"Owner key cache: {cache_path}")
    except (StorageError, CryptoError, AuthError) as e:
        click.echo(f"Upload failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        # Surface the type to aid debugging while not leaking values.
        click.echo(
            f"Upload failed: unexpected error ({type(e).__name__})",
            err=True,
        )
        sys.exit(1)
    finally:
        ks.lock()
        client.close()


@cli.command()
@click.argument("file_id")
@click.argument("output", type=click.Path(dir_okay=False))
@click.option(
    "--key-cache",
    default=None,
    help="Owner key cache (for files you uploaded). JSON with file_key/meta_key.",
)
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
    key_cache: str | None,
    sender_pubkey: str | None,
):
    """Download and decrypt a file (streaming)."""
    ks = _get_keystore(ctx.obj["key_file"])
    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        click.echo(f"Fetching metadata for {file_id}...")
        metadata = client.get_file_metadata(file_id)
        header_bytes = bytes.fromhex(metadata["file_header"])
        enc_meta = bytes.fromhex(metadata["encrypted_metadata"])
        total_chunks = int(metadata["total_chunks"])

        # Parse header to get binding info for the per-recipient unwrap.
        header = FileHeader.deserialize(header_bytes)
        # Defense in depth: the URL file_id must match the cryptographic
        # file_id inside the header so a hostile server can't substitute
        # a different file. Canonicalize both to lowercase no-hyphens
        # before compare — URLs are case-insensitive but Python str ==
        # is not. (Round-3 H8)
        url_canon = file_id.lower().replace("-", "")
        if header.file_id.hex() != url_canon:
            raise CryptoError("Header file_id does not match requested file_id")

        wrapped = client.get_wrapped_keys(file_id)
        file_key: bytes | None = None
        meta_key: bytes | None = None

        if wrapped is not None:
            # Shared / public file delivered with a wrapped-keys bundle.
            # Look up the sender's pinned pubkey (or use override).
            sender_pk = _resolve_owner_pubkey(client, file_id, sender_pubkey)
            click.echo("Unwrapping shared file keys...")
            file_key, meta_key = ks.unwrap_file_keys(
                wrapped,
                header.file_id,
                sender_pubkey=sender_pk,
            )
            sig_pubkey = sender_pk
        else:
            # Owner case — load file_key + meta_key from local cache.
            safe_id = _validate_file_id_local(file_id)
            cache_path = (
                Path(key_cache)
                if key_cache
                else Path(ctx.obj["key_file"]).parent / f"{safe_id}.keys.json"
            )
            if not cache_path.exists():
                raise CryptoError(
                    f"No wrapped keys from server and no key cache at "
                    f"{cache_path}. For owned files, supply --key-cache."
                )
            cache = _load_owner_key_cache(cache_path)
            file_key = bytes.fromhex(cache["file_key"])
            meta_key = bytes.fromhex(cache["meta_key"])
            sig_pubkey = ks.ed25519_public_key()

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
    except Exception as e:
        click.echo(
            f"Download failed: unexpected error ({type(e).__name__})",
            err=True,
        )
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
    required=True,
    help="Recipient's X25519 public key (hex). Obtain out-of-band or via a future directory.",
)
@click.option(
    "--key-cache",
    default=None,
    help="Local owner key cache for this file (defaults next to key file).",
)
@click.pass_context
def share(
    ctx,
    file_id: str,
    recipient: str,
    recipient_pubkey: str,
    key_cache: str | None,
):
    """Share a file with another user.

    Requires the recipient's X25519 public key. The client wraps the
    file_key+meta_key for the recipient and uploads the wrapped bundle;
    the server never sees plaintext keys.
    """
    ks = _get_keystore(ctx.obj["key_file"])
    if not ks.has_keys:
        click.echo("Error: No keys found.", err=True)
        sys.exit(1)
    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)
    try:
        try:
            recipient_pk = bytes.fromhex(recipient_pubkey)
        except ValueError as e:
            raise CryptoError("--recipient-pubkey is not valid hex") from e
        if len(recipient_pk) != 32:
            raise CryptoError("--recipient-pubkey must be 32 bytes")

        safe_id = _validate_file_id_local(file_id)
        cache_path = (
            Path(key_cache)
            if key_cache
            else Path(ctx.obj["key_file"]).parent / f"{safe_id}.keys.json"
        )
        if not cache_path.exists():
            raise CryptoError(
                f"Owner key cache not found: {cache_path}. "
                f"Only the owner can share their own files."
            )
        cache = _load_owner_key_cache(cache_path)
        file_key = bytes.fromhex(cache["file_key"])
        meta_key = bytes.fromhex(cache["meta_key"])

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


# ──────────── Helpers ────────────


_SAFE_FILE_ID_RE = __import__("re").compile(
    r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$"
)


def _validate_file_id_local(file_id: str) -> str:
    """Validate a server-supplied file_id before using it as part of
    a local filesystem name. Without this, a hostile file_id with
    path separators or ``..`` could escape the keys-cache directory.
    Returns the canonical 32-char hex form. (Round-10 M5)
    """
    if not _SAFE_FILE_ID_RE.match(file_id):
        raise CryptoError(f"Invalid file_id format: {file_id!r}")
    return file_id.lower().replace("-", "")


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
    cli()


if __name__ == "__main__":
    main()
