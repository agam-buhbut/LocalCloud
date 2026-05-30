# LocalCloud - Client key-management glue (X25519 enrollment + directory)
#
# Item 2C client side. This module is the home for the key-wrapping
# directory verification glue. It is deliberately NOT client/sharing.py
# (which Phase 3C still deletes); the new helpers live here.
#
# The security property of the whole directory rests on the client
# re-verifying the recipient's Ed25519 self-signature over their X25519
# key before wrapping. The server is hostile and may lie about any field;
# a verified (ed25519, x25519, self_sig) triple authenticates the X25519
# key as strongly as the recipient's Ed25519 pin (transitive trust).

from __future__ import annotations

import keycore

from shared.exceptions import CryptoError
from shared.usernames import (
    ENROLL_SIG_CONTEXT,
    build_enroll_signing_input,
    canonicalize_username,
)

# Re-exported so callers/tests use a single byte-identical implementation
# (the server builds the same input in server/users.py).
__all__ = [
    "ENROLL_SIG_CONTEXT",
    "build_enroll_signing_input",
    "verify_x25519_self_sig",
    "resolve_recipient",
]

_X25519_LEN = 32
_ED25519_LEN = 32
_SELF_SIG_LEN = 64


def verify_x25519_self_sig(
    ed25519_pub: bytes,
    x25519_pub: bytes,
    self_sig: bytes,
    canonical_username: str,
) -> bool:
    """Verify a recipient's Ed25519 self-signature over their X25519 key.

    Rebuilds the domain-separated, username-bound signing input and checks
    it against the recipient's Ed25519 key via ``keycore.verify_signature``.
    A substituted X25519 key (with the victim's real Ed25519) fails here
    because the server cannot forge the self-signature without the
    recipient's private key.

    Returns False (never raises) on any malformed/absent field or a bad
    signature, so callers get a clean fail-closed boolean.

    Args:
        ed25519_pub: Recipient's 32-byte Ed25519 identity public key.
        x25519_pub: Recipient's 32-byte X25519 key-agreement public key.
        self_sig: The 64-byte Ed25519 self-signature to verify.
        canonical_username: The recipient's canonical username, bound into
            the signed input (must already be canonical).
    """
    if (
        len(ed25519_pub) != _ED25519_LEN
        or len(x25519_pub) != _X25519_LEN
        or len(self_sig) != _SELF_SIG_LEN
    ):
        return False
    try:
        signing_input = build_enroll_signing_input(canonical_username, x25519_pub)
    except ValueError:
        return False
    try:
        # keycore native extension: no .pyi stub, verify_signature exists
        # at runtime.
        return bool(
            keycore.verify_signature(  # type: ignore[reportAttributeAccessIssue]
                ed25519_pub, signing_input, self_sig
            )
        )
    except Exception:
        # A malformed key surfaces as "not verified", not a crash.
        return False


def resolve_recipient(api_client: object, username: str) -> bytes:
    """Resolve and verify a recipient's X25519 key via the directory.

    Fetches ``{ed25519, x25519, self_sig}`` from the server's pubkey
    directory, MANDATORILY verifies the self-signature binds the
    recipient's canonical username, and returns the verified 32-byte
    X25519 key. This is what lets ``share`` drop the out-of-band
    ``--recipient-pubkey``: the verified key is authenticated by the
    recipient's Ed25519 identity, not trusted from the hostile server.

    Fail-closed: raises ``CryptoError`` if the recipient is not enrolled
    (any field absent) or the self-signature does not verify. The caller
    MUST NOT wrap to an unverified key.

    Args:
        api_client: A ``CloudClient`` exposing ``get_pubkeys(username)``.
        username: The raw recipient username (canonicalized here so the
            signature check binds the exact canonical bytes the server
            stored the self-sig under).

    Returns:
        The verified 32-byte X25519 public key.

    Raises:
        CryptoError: if the username is invalid, the recipient is not
            enrolled, or the self-signature fails verification.
    """
    try:
        canonical = canonicalize_username(username)
    except Exception as exc:
        raise CryptoError(f"Invalid recipient username: {username!r}") from exc

    # get_pubkeys returns a dict of raw bytes (empty/zero bytes for absent
    # fields), or raises StorageError/AuthError on transport failure.
    entry = api_client.get_pubkeys(canonical)  # type: ignore[attr-defined]
    ed = entry.get("ed25519", b"")
    x = entry.get("x25519", b"")
    sig = entry.get("self_sig", b"")

    if len(ed) != _ED25519_LEN or len(x) != _X25519_LEN or len(sig) != _SELF_SIG_LEN:
        raise CryptoError(
            f"Recipient {canonical!r} is not enrolled (no usable X25519 key "
            "in the directory)"
        )

    if not verify_x25519_self_sig(ed, x, sig, canonical):
        raise CryptoError(
            f"X25519 self-signature for {canonical!r} is invalid — refusing "
            "to wrap to a potentially server-substituted key"
        )
    return x
