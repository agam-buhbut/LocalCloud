# LocalCloud - Shared username canonicalization + enrollment signing input
#
# Single source of truth for the username normalization rule and the
# domain-separated X25519-enrollment signing input. Both the server
# (auth/admin/directory) and the client (keymgmt/enroll) MUST agree
# byte-for-byte on these — the enroll self-signature is computed over the
# canonical username on the client and re-verified on the server, so any
# divergence would silently break enrollment or, worse, let a self-sig be
# lifted onto a different account.
#
# The client must NOT import from server.*; this module is the shared
# home (converges with the Phase 3B dedup).

from __future__ import annotations

import re
import struct
import unicodedata

from shared.exceptions import AuthError

# Username canonicalization regex (post-NFKC + casefold + strip).
# Anchored: full-string match. Charset is intentionally narrow so
# confusable Unicode cannot impersonate an existing account.
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")

# Domain separation tag for the Ed25519 self-signature a user makes over
# their enrolled X25519 key. Distinct from MERKLE_SIG_CONTEXT
# (shared.models) so a Merkle-root signature can never satisfy this
# verifier and vice-versa (T-N3 cross-protocol replay).
ENROLL_SIG_CONTEXT: bytes = b"localcloud-x25519-enroll-v1"

# An X25519 public key is exactly 32 bytes.
X25519_PUBKEY_LEN: int = 32


def canonicalize_username(raw: str) -> str:
    """Normalize and validate a username.

    Applies NFKC normalization, casefold, and surrounding-whitespace
    strip, then enforces a narrow charset. This prevents confusable
    Unicode (e.g. fullwidth ``ＡＤＭＩＮ``) from impersonating an existing
    account and rejects control characters like NUL.

    The output is the canonical form bound into the enroll self-signature
    and used for every server-side user lookup, so it MUST be identical on
    client and server.

    Args:
        raw: The raw, user-supplied username.

    Returns:
        The canonical username.

    Raises:
        AuthError: with a generic message on any rejection.
    """
    if not isinstance(raw, str):
        raise AuthError("Authentication failed")
    # NUL byte rejection BEFORE normalization — NFKC could otherwise
    # collapse certain compositions and obscure the embedded NUL.
    if "\x00" in raw:
        raise AuthError("Authentication failed")
    normalized = unicodedata.normalize("NFKC", raw).casefold().strip()
    if "\x00" in normalized:
        raise AuthError("Authentication failed")
    if not USERNAME_RE.match(normalized):
        raise AuthError("Authentication failed")
    return normalized


def build_enroll_signing_input(canonical_username: str, x25519_pub: bytes) -> bytes:
    """Build the Ed25519 self-signature input for X25519 enrollment.

    Format (every field fixed-width or length-prefixed, so the encoding
    is unambiguous)::

        ENROLL_SIG_CONTEXT
            || u16_be(len(canonical_username_utf8))
            || canonical_username (UTF-8, NFKC+casefold canonical form)
            || x25519_pub (32 bytes)

    Binding the canonical username makes the X25519 key cryptographically
    tied to the account it is enrolled under, so a hostile server cannot
    lift one user's self-signed key onto another user's row (L9).

    Args:
        canonical_username: The already-canonicalized username (the caller
            is responsible for canonicalizing — this function does NOT
            re-canonicalize so the exact signed bytes are explicit).
        x25519_pub: The 32-byte X25519 public key being enrolled.

    Returns:
        The bytes to be signed / verified.

    Raises:
        ValueError: if ``x25519_pub`` is not 32 bytes or the username's
            UTF-8 encoding exceeds the u16 length prefix.
    """
    if len(x25519_pub) != X25519_PUBKEY_LEN:
        raise ValueError("x25519_pub must be 32 bytes")
    name_bytes = canonical_username.encode("utf-8")
    if len(name_bytes) > 0xFFFF:
        raise ValueError("canonical_username too long for u16 length prefix")
    return (
        ENROLL_SIG_CONTEXT
        + struct.pack(">H", len(name_bytes))
        + name_bytes
        + x25519_pub
    )
