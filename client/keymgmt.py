# LocalCloud - Client key-management glue (X25519 enrollment + directory)
#
# Item 2C client side. This module is the home for the key-wrapping
# directory verification glue.
#
# The security property of the whole directory rests on the client
# re-verifying the recipient's Ed25519 self-signature over their X25519
# key before wrapping. The server is hostile and may lie about any field;
# a verified (ed25519, x25519, self_sig) triple authenticates the X25519
# key as strongly as the recipient's Ed25519 pin (transitive trust).

from __future__ import annotations

import keycore

from shared.exceptions import AuthError, CryptoError
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
    "acquire_file_keys",
]

_X25519_LEN = 32
_ED25519_LEN = 32
_SELF_SIG_LEN = 64
_FILE_ID_LEN = 16


def acquire_file_keys(
    api_client: object, keystore: object, file_id: str
) -> tuple[bytes, bytes]:
    """Acquire (file_key, meta_key) for a file via the server (item 2A).

    The SINGLE key-acquisition path for both the owner and any shared
    recipient: fetch the wrapped bundle from ``GET /wrapped_keys`` and
    unwrap it with the local keystore's X25519 PRIVATE key (the keystore
    re-derives its own X25519 public key from that private key — the wrap's
    recipient binding). The wrap also binds the SENDER's Ed25519 identity,
    which for both an owner self-share and a recipient share is the FILE
    OWNER's Ed25519 key, so it is resolved here from ``/owner_pubkey``.

    Fail-closed: raises ``CryptoError`` if the server has no bundle for this
    (file, caller), if the owner has no registered identity key, or if the
    unwrap fails (a hostile-server tamper surfaces as an AEAD failure).
    No plaintext key is ever read from disk.

    Note: the wrap AAD binds the recipient X25519 public key, so a future
    X25519 rotation would orphan existing self-share/recipient bundles
    wrapped to the old key — that is a Phase 7 key-rotation concern, out of
    scope here.

    Args:
        api_client: A ``CloudClient`` exposing ``get_wrapped_keys(file_id)``
            and ``get_owner_pubkey(file_id)``.
        keystore: An unlocked ``KeyStore`` whose X25519 private key wraps
            the bundle (its public key is the bundle's recipient).
        file_id: The file id as a hex string (with or without hyphens); the
            16-byte form is bound into the unwrap AAD.

    Returns:
        ``(file_key, meta_key)`` — both 32 bytes.

    Raises:
        CryptoError: no bundle, no owner identity key, malformed file_id, or
            an unwrap/AEAD failure.
    """
    try:
        file_id_bytes = bytes.fromhex(file_id.replace("-", ""))
    except ValueError as exc:
        raise CryptoError("file_id is not valid hex") from exc
    if len(file_id_bytes) != _FILE_ID_LEN:
        raise CryptoError("file_id must encode 16 bytes")

    wrapped = api_client.get_wrapped_keys(file_id)  # type: ignore[attr-defined]
    if not wrapped:
        # Fail-closed: an owner who never registered a self-share row, or a
        # recipient with no share, gets nothing — never a silent fallback.
        raise CryptoError(
            "No wrapped keys for this file and user; the owner must register "
            "self-keys (upload / migrate-keys) or share with this recipient"
        )

    sender_ed25519 = api_client.get_owner_pubkey(file_id)  # type: ignore[attr-defined]
    if sender_ed25519 is None or len(sender_ed25519) != _ED25519_LEN:
        raise CryptoError(
            "Server has no registered identity key for this file's owner; "
            "cannot verify the wrapped-key sender binding"
        )

    try:
        file_key, meta_key = keystore.unwrap_file_keys(  # type: ignore[attr-defined]
            wrapped, file_id_bytes, sender_pubkey=sender_ed25519
        )
    except Exception as exc:
        # A tampered bundle / wrong recipient surfaces as an AEAD failure
        # from keycore; collapse to a fail-closed CryptoError.
        raise CryptoError("Failed to unwrap file keys (bundle invalid)") from exc
    return file_key, meta_key


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
    except AuthError as exc:
        # canonicalize_username only ever raises AuthError; narrowing the
        # catch here keeps any unexpected error type from being silently
        # collapsed into "invalid username". Still fail-closed (CryptoError).
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
