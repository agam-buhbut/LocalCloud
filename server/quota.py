# LocalCloud - Server Quota Accounting
#
# Ciphertext-only quota enforcement with atomic transactions.
# The server never infers plaintext size — only tracks ciphertext bytes.

from __future__ import annotations

from server.database import Database
from shared.exceptions import QuotaExceededError


def check_quota(db: Database, user_id: str, additional_bytes: int) -> None:
    """Check if a user has enough quota for additional bytes.

    Must be called within a database transaction for atomicity.
    Raises QuotaExceededError if quota would be exceeded.
    """
    used, quota = db.get_user_usage(user_id)
    if used + additional_bytes > quota:
        raise QuotaExceededError()


def commit_usage(db: Database, user_id: str, bytes_added: int) -> None:
    """Atomically increment user's used bytes after finalization.

    Must be called within a database transaction.
    """
    db.increment_usage(user_id, bytes_added)


def release_usage(db: Database, user_id: str, bytes_removed: int) -> None:
    """Atomically decrement user's used bytes after deletion.

    Must be called within a database transaction.
    """
    db.decrement_usage(user_id, bytes_removed)


def get_quota_info(db: Database, user_id: str) -> dict:
    """Get quota information for a user.

    Returns dict with used_bytes, quota_bytes, and available_bytes.
    """
    used, quota = db.get_user_usage(user_id)
    return {
        "used_bytes": used,
        "quota_bytes": quota,
        "available_bytes": max(0, quota - used),
    }
