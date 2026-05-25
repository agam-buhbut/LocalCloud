"""Operator admin CLI for LocalCloud server.

Provides the operator-side surface that the README §7 calls for:

    create-user, disable-user, set-quota, register-pubkey, list-users,
    bump-session, run-cleanup

This is the ONLY way to create or modify user accounts. By design (spec
§"physical-console-only administration") there is no HTTP endpoint that
mutates user state — the operator runs this script directly against the
configured database file.

Usage::

    python -m server.admin create-user alice
    python -m server.admin set-quota alice 5368709120     # 5 GiB
    python -m server.admin register-pubkey alice <hex>
    python -m server.admin disable-user alice
    python -m server.admin list-users
    python -m server.admin run-cleanup
"""

from __future__ import annotations

import argparse
import getpass
import re
import sys
import time
import unicodedata
from collections.abc import Sequence

from server.config import ServerConfig
from server.database import Database
from shared.crypto import hash_password

_USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")


def _canonicalize_username(raw: str) -> str:
    """Same normalization rules the login path uses. Reject up front
    so the operator can't accidentally create an unreachable user.
    """
    if "\x00" in raw:
        raise ValueError("username contains NUL")
    norm = unicodedata.normalize("NFKC", raw).casefold().strip()
    if "\x00" in norm or not _USERNAME_RE.match(norm):
        raise ValueError("username must match [a-z0-9._-]{3,64} after NFKC casefold")
    return norm


def _open_db(config: ServerConfig) -> Database:
    db = Database(config.db_path)
    db.connect()
    return db


def _print_user(row: dict) -> None:
    print(
        f"{row['username']:<32} "
        f"uid={row['user_id']} "
        f"active={'yes' if row['is_active'] else 'no'} "
        f"sv={row['session_version']} "
        f"quota={row['quota_bytes']} "
        f"used={row['used_bytes']} "
        f"pk={row['ed25519_pubkey'].hex() if row['ed25519_pubkey'] else '(unset)'}"
    )


# ────────────────────────────── Commands ──────────────────────────────


def cmd_create_user(args: argparse.Namespace, db: Database) -> int:
    username = _canonicalize_username(args.username)
    if db.get_user_by_username(username) is not None:
        print(f"User {username!r} already exists.", file=sys.stderr)
        return 1
    password = getpass.getpass("Password (will not echo): ")
    confirm = getpass.getpass("Confirm: ")
    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    if len(password) < 12:
        print("Password too short (require >=12 chars).", file=sys.stderr)
        return 1
    password_hash = hash_password(password)
    quota = int(args.quota) if args.quota is not None else 1 * 1024 * 1024 * 1024
    if quota < 0:
        print("quota must be >= 0.", file=sys.stderr)
        return 1
    user_id = db.create_user(
        username=username,
        password_hash=password_hash,
        quota_bytes=quota,
    )
    print(f"Created user {username!r} with user_id={user_id} quota={quota}")
    return 0


def cmd_register_pubkey(args: argparse.Namespace, db: Database) -> int:
    """Register an Ed25519 identity public key for a user.

    Run after the user has generated keys with ``localcloud init`` and
    given the operator their Ed25519 public key out-of-band. The key is
    used server-side to seed ``/api/files/<id>/owner_pubkey`` so other
    clients can verify file signatures from this owner.
    """
    username = _canonicalize_username(args.username)
    try:
        pubkey = bytes.fromhex(args.pubkey)
    except ValueError:
        print("pubkey must be 32 bytes of hex.", file=sys.stderr)
        return 1
    if len(pubkey) != 32:
        print("pubkey must be exactly 32 bytes.", file=sys.stderr)
        return 1
    user = db.get_user_by_username(username)
    if user is None:
        print(f"User {username!r} not found.", file=sys.stderr)
        return 1
    with db.transaction() as conn:
        cursor = conn.execute(
            "UPDATE users SET ed25519_pubkey = ?, "
            "session_version = session_version + 1, "
            "updated_at = ? "
            "WHERE username = ?",
            (pubkey, time.time(), username),
        )
        if cursor.rowcount == 0:
            print(f"Failed to update {username!r}.", file=sys.stderr)
            return 1
    print(f"Registered Ed25519 pubkey for {username!r} (session bumped).")
    return 0


def cmd_disable_user(args: argparse.Namespace, db: Database) -> int:
    username = _canonicalize_username(args.username)
    if not db.disable_user(username):
        print(f"User {username!r} not found.", file=sys.stderr)
        return 1
    print(f"Disabled {username!r} (sessions revoked).")
    return 0


def cmd_set_quota(args: argparse.Namespace, db: Database) -> int:
    username = _canonicalize_username(args.username)
    quota = int(args.quota)
    if quota < 0:
        print("quota must be >= 0.", file=sys.stderr)
        return 1
    if not db.update_quota(username, quota):
        print(f"User {username!r} not found.", file=sys.stderr)
        return 1
    print(f"Set quota for {username!r} to {quota} bytes.")
    return 0


def cmd_bump_session(args: argparse.Namespace, db: Database) -> int:
    username = _canonicalize_username(args.username)
    if not db.bump_session_version(username):
        print(f"User {username!r} not found.", file=sys.stderr)
        return 1
    print(f"Bumped session_version for {username!r} — all tokens revoked.")
    return 0


def cmd_list_users(args: argparse.Namespace, db: Database) -> int:
    # Hold the Database lock to honor the connection-property contract
    # (Round-3 M8). Admin runs single-threaded, but another process
    # touching the same DB file would still need this for correctness.
    with db._lock:  # noqa: SLF001 — admin is allowed to access _lock
        rows = db.conn.execute(
            "SELECT user_id, username, is_active, session_version, "
            "quota_bytes, used_bytes, ed25519_pubkey "
            "FROM users ORDER BY username"
        ).fetchall()
    if not rows:
        print("No users.")
        return 0
    for row in rows:
        _print_user(dict(row))
    return 0


def cmd_run_cleanup(args: argparse.Namespace, db: Database) -> int:
    """Manually trigger the background cleanup tasks (one shot).

    Useful after operator changes to staging settings or for diagnosing
    accumulating stale rows.
    """
    from server.storage import (
        cleanup_expired_uploads,
        cleanup_orphan_staging_dirs,
        init_storage,
    )

    config = ServerConfig.from_env()
    init_storage(
        db=db,
        blob_dir=config.blob_dir,
        staging_dir=config.staging_dir,
        staging_expiry=config.staging_expiry_seconds,
    )
    db.cleanup_old_attempts(config.rate_limit_window_seconds)
    expired = cleanup_expired_uploads()
    orphans = cleanup_orphan_staging_dirs()
    print(
        f"Cleaned: rate-limit attempts pruned, "
        f"expired staging={expired}, orphan dirs={orphans}"
    )
    return 0


# ────────────────────────────── Entry ──────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="localcloud-admin",
        description="Operator admin CLI for LocalCloud (physical-console-only).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("create-user", help="Create a new user account.")
    sp.add_argument("username")
    sp.add_argument(
        "--quota",
        type=int,
        default=None,
        help="Quota in bytes (default: 1 GiB).",
    )
    sp.set_defaults(func=cmd_create_user)

    sp = sub.add_parser(
        "register-pubkey",
        help="Register Ed25519 identity pubkey for a user.",
    )
    sp.add_argument("username")
    sp.add_argument("pubkey", help="32-byte hex Ed25519 public key")
    sp.set_defaults(func=cmd_register_pubkey)

    sp = sub.add_parser("disable-user", help="Disable a user account.")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_disable_user)

    sp = sub.add_parser("set-quota", help="Set a user's quota.")
    sp.add_argument("username")
    sp.add_argument("quota", type=int, help="Quota in bytes")
    sp.set_defaults(func=cmd_set_quota)

    sp = sub.add_parser(
        "bump-session",
        help="Bump session_version to revoke all live tokens for a user.",
    )
    sp.add_argument("username")
    sp.set_defaults(func=cmd_bump_session)

    sp = sub.add_parser("list-users", help="List all users.")
    sp.set_defaults(func=cmd_list_users)

    sp = sub.add_parser(
        "run-cleanup",
        help="Run all background cleanup tasks once (diagnostic).",
    )
    sp.set_defaults(func=cmd_run_cleanup)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    config = ServerConfig.from_env()
    db = _open_db(config)
    try:
        return args.func(args, db)
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
