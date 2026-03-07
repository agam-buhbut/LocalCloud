# LocalCloud - Server Access Control Policy
#
# Enforces file visibility rules: private, shared, public.
# The server enforces policy WITHOUT reading encrypted metadata —
# visibility is stored in plaintext alongside encrypted blobs.

from __future__ import annotations

from typing import Optional

from server.database import Database
from shared.exceptions import AuthError
from shared.models import Visibility


def check_file_access(
    db: Database,
    file_id: str,
    user_id: str,
) -> dict:
    """Check if a user has access to a file.

    Returns the file record if access is granted.
    Raises AuthError if access is denied.
    Error messages are deliberately generic.
    """
    file_record = db.get_file(file_id)
    if file_record is None:
        # Same error as access denied to prevent file existence enumeration
        raise AuthError()

    visibility = file_record["visibility"]

    # Owner always has access
    if file_record["owner_id"] == user_id:
        return file_record

    # Public files accessible to all authenticated users
    if visibility == Visibility.PUBLIC:
        return file_record

    # Shared files — use indexed existence check (#12)
    if visibility == Visibility.SHARED:
        if db.check_share_exists(file_id, user_id):
            return file_record

    # Private or not in share list
    raise AuthError()


def check_file_ownership(
    db: Database,
    file_id: str,
    user_id: str,
) -> dict:
    """Check if a user owns a file.

    Returns the file record if the user is the owner.
    Raises AuthError if not the owner.
    """
    file_record = db.get_file(file_id)
    if file_record is None or file_record["owner_id"] != user_id:
        raise AuthError()
    return file_record
