# LocalCloud - Shared file_id canonicalization
#
# Single source of truth for the file_id / upload_id format rule, mirroring
# shared/usernames.py. Both the server (storage._validate_id) and the client
# (cli._validate_file_id_local) MUST agree byte-for-byte on what a valid id
# is and on its canonical form, so a UUID-with-hyphens and the equivalent
# 32-hex string can never map to two distinct filesystem paths or DB rows
# for the same logical id.
#
# The client must NOT import from server.*; this module is the shared home
# (Phase 3B dedup). The function is behavior-identical to the two validators
# it replaces: it accepts a UUID4 with hyphens OR a 32-char lowercase-hex
# string and returns the canonical 32-char hex (no hyphens) form.

from __future__ import annotations

import re

# Strict patterns for file_id / upload_id. A UUID4 with hyphens, or a bare
# 32-char lowercase hex string. Anchored full-string so no substring of a
# hostile value can slip through and reach a path or DB key.
_SAFE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_SAFE_HEX_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def is_canonical_id(value: str) -> bool:
    """Return True iff ``value`` matches the hyphenated-UUID or 32-hex form.

    Pure predicate (no canonicalization, no raising) for callers — e.g. the
    orphan-staging scan — that only need to recognise a well-formed id.
    """
    return bool(_SAFE_ID_RE.match(value) or _SAFE_HEX_ID_RE.match(value))


def canonicalize_file_id(value: str) -> str:
    """Validate and canonicalize a file_id / upload_id.

    Accepts a UUID4 with hyphens OR a 32-char lowercase hex string and
    returns the canonical 32-char hex (hyphen-free) form, so two different
    encodings of the same logical id cannot produce distinct filesystem
    paths or DB rows.

    Args:
        value: The raw, caller-supplied identifier.

    Returns:
        The canonical 32-char lowercase-hex identifier.

    Raises:
        ValueError: if ``value`` is not a valid identifier. Callers that
            need a different exception type (e.g. the client's CryptoError)
            wrap this and re-raise.
    """
    if _SAFE_ID_RE.match(value):
        return value.replace("-", "")
    if _SAFE_HEX_ID_RE.match(value):
        return value
    raise ValueError("Invalid identifier format")
