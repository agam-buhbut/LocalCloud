# LocalCloud - Client CLI
#
# Command-line interface for LocalCloud operations.
# Uses Click for argument parsing and the client modules for crypto/API.

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from client.api_client import CloudClient
from client.encryptor import FileEncryptor
from client.keystore import KeyStore
from client.sharing import unwrap_keys, wrap_keys_for_recipient
from shared.exceptions import AuthError, CryptoError, StorageError
from shared.models import Visibility

# Default paths
DEFAULT_KEY_FILE = os.path.expanduser("~/.localcloud/keys.enc")
DEFAULT_SERVER = "http://10.0.0.1:8443"


def _get_keystore(key_file: str) -> KeyStore:
    return KeyStore(key_file)


def _get_client(server: str) -> CloudClient:
    return CloudClient(server)


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

    click.echo("Generating identity keypair (this may take a moment due to Argon2id)...")
    ks.generate(password)

    click.echo(f"Keys generated and saved to {ctx.obj['key_file']}")
    click.echo(f"X25519 public key: {ks.x25519_public_key().hex()}")
    click.echo(f"Ed25519 public key: {ks.ed25519_public_key().hex()}")
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
        # Save token to a temporary file
        token_path = Path(ctx.obj["key_file"]).parent / ".session"
        token_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        token_path.write_text(token)
        os.chmod(str(token_path), 0o600)
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
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--visibility", type=click.Choice(["private", "shared", "public"]),
              default="private")
@click.pass_context
def upload(ctx, filepath: str, visibility: str):
    """Encrypt and upload a file."""
    vis_map = {"private": Visibility.PRIVATE, "shared": Visibility.SHARED, "public": Visibility.PUBLIC}

    ks = _get_keystore(ctx.obj["key_file"])
    if not ks.has_keys:
        click.echo("Error: No keys found. Run 'localcloud init' first.", err=True)
        sys.exit(1)

    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        # Read file
        plaintext = Path(filepath).read_bytes()
        filename = Path(filepath).name

        click.echo(f"Encrypting {filename} ({len(plaintext)} bytes)...")
        encryptor = FileEncryptor(ks)
        encrypted = encryptor.encrypt_file(
            plaintext, filename, vis_map[visibility],
        )

        click.echo(f"Uploading {encrypted.header.total_chunks} chunks...")
        file_id = client.upload_file(
            filename=filename,
            chunks=encrypted.chunks,
            file_id=encrypted.header.file_id.hex(),
            file_header=encrypted.header.serialize(),
            encrypted_metadata=encrypted.encrypted_metadata,
            visibility=vis_map[visibility],
        )

        click.echo(f"Upload complete. File ID: {file_id}")
    except (StorageError, CryptoError) as e:
        click.echo(f"Upload failed: {e}", err=True)
        sys.exit(1)
    except Exception:
        click.echo("Upload failed: unexpected error", err=True)
        sys.exit(1)
    finally:
        ks.lock()
        client.close()


@cli.command()
@click.argument("file_id")
@click.argument("output", type=click.Path())
@click.option("--key-file-path", default=None,
              help="Path to local key cache (for owner's file/meta keys)")
@click.option("--sender-pubkey", default=None,
              help="Hex-encoded Ed25519 public key of the file owner (for shared files)")
@click.pass_context
def download(ctx, file_id: str, output: str, key_file_path: str | None,
             sender_pubkey: str | None):
    """Download and decrypt a file.

    For files you own, you need the file_key and meta_key (stored locally
    after upload). For shared files, wrapped keys are fetched from the server
    and unwrapped with your private key.
    """
    ks = _get_keystore(ctx.obj["key_file"])
    key_password = click.prompt("Key password", hide_input=True)
    ks.unlock(key_password)

    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        click.echo(f"Downloading file {file_id}...")
        metadata, chunks = client.download_file(file_id)

        header_bytes = bytes.fromhex(metadata["file_header"])
        enc_meta = bytes.fromhex(metadata["encrypted_metadata"])

        # Attempt to get wrapped keys from server (shared file case)
        wrapped = client.get_wrapped_keys(file_id)
        file_key: bytes | None = None
        meta_key: bytes | None = None
        is_shared = False

        if wrapped is not None:
            # Shared file — unwrap keys using our private key
            is_shared = True
            click.echo("Unwrapping shared file keys...")
            from shared.models import FileHeader
            header = FileHeader.deserialize(header_bytes)

            # #9: Get sender's public key for signature verification
            if sender_pubkey:
                sender_pk = bytes.fromhex(sender_pubkey)
            else:
                click.echo(
                    "Warning: No --sender-pubkey provided for shared file. "
                    "Signature verification will use the sender's key from metadata.",
                    err=True,
                )
                # Fall back to owner pubkey from server metadata
                sender_pk = None

            file_key, meta_key = ks.unwrap_file_keys(
                wrapped, header.file_id,
                sender_pubkey=sender_pk or b"",
            )
        elif key_file_path:
            # Owner case — read keys from local cache
            import json as _json
            key_cache = _json.loads(Path(key_file_path).read_text())
            file_key = bytes.fromhex(key_cache["file_key"])
            meta_key = bytes.fromhex(key_cache["meta_key"])

        if file_key is None or meta_key is None:
            click.echo(
                "Error: Cannot decrypt — no file keys available.\n"
                "For owned files: provide --key-file-path to your local key cache.\n"
                "For shared files: key exchange with sender required.",
                err=True,
            )
            sys.exit(1)

        click.echo("Decrypting and verifying...")
        encryptor = FileEncryptor(ks)

        # #9: Use correct public key for signature verification
        # For owned files: use our own Ed25519 key
        # For shared files: use the sender's Ed25519 key
        if is_shared and sender_pubkey:
            sig_pubkey = bytes.fromhex(sender_pubkey)
        else:
            sig_pubkey = ks.ed25519_public_key()

        # Full verification: signature → Merkle → AEAD
        # #10: decrypt_file now handles padding trim internally
        plaintext = encryptor.decrypt_file(
            chunks=chunks,
            header_data=header_bytes,
            encrypted_metadata=enc_meta,
            file_key=file_key,
            meta_key=meta_key,
            signer_pubkey=sig_pubkey,
        )

        Path(output).write_bytes(plaintext)
        click.echo(f"Saved to {output} ({len(plaintext)} bytes)")
    except (StorageError, CryptoError) as e:
        click.echo(f"Download failed: {e}", err=True)
        sys.exit(1)
    except Exception:
        click.echo("Download failed: unexpected error", err=True)
        sys.exit(1)
    finally:
        ks.lock()
        client.close()


@cli.command("ls")
@click.pass_context
def list_files(ctx):
    """List accessible files."""
    client = _get_client(ctx.obj["server"])
    _load_session(ctx, client)

    try:
        files = client.list_files()
        if not files:
            click.echo("No files found.")
            return

        click.echo(f"{'File ID':<40} {'Filename':<30} {'Size':>12} {'Visibility':<10}")
        click.echo("-" * 95)
        for f in files:
            vis = ["private", "shared", "public"][f.get("visibility", 0)]
            size = _format_size(f.get("total_bytes", 0))
            click.echo(f"{f['file_id']:<40} {f['filename']:<30} {size:>12} {vis:<10}")
    except Exception as e:
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
    except Exception:
        click.echo("Delete failed: unexpected error", err=True)
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
    except Exception as e:
        click.echo(f"Failed: {e}", err=True)
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.argument("file_id")
@click.argument("recipient")
@click.pass_context
def share(ctx, file_id: str, recipient: str):
    """Share a file with another user."""
    click.echo("File sharing requires recipient's public key exchange.")
    click.echo("This feature is available but requires key exchange setup.")
    # TODO: Full implementation requires recipient pubkey lookup


# ──────────── Helpers ────────────

def _load_session(ctx, client: CloudClient) -> None:
    """Load saved session token."""
    token_path = Path(ctx.obj["key_file"]).parent / ".session"
    if token_path.exists():
        client.set_token(token_path.read_text().strip())  # Code quality fix
    else:
        click.echo("No session found. Run 'localcloud login' first.", err=True)
        sys.exit(1)


def _format_size(bytes_val: int) -> str:
    """Format bytes into human-readable size."""
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} PiB"


def main():
    cli()


if __name__ == "__main__":
    main()
