# LocalCloud - Client Sharing Module
#
# Key wrapping for file sharing. Delegates all crypto to
# the Rust keycore module via the KeyStore wrapper.

from __future__ import annotations

from client.keystore import KeyStore


def wrap_keys_for_recipient(
    keystore: KeyStore,
    file_key: bytes,
    meta_key: bytes,
    file_id: bytes,
    recipient_pubkey: bytes,
) -> bytes:
    """Wrap file keys for a specific recipient.

    Performs: X25519 ECDH → HKDF (domain separated) → AEAD wrap
    All crypto happens in Rust — keys never exist in Python.

    Args:
        keystore: Unlocked key store with sender's private key
        file_key: 32-byte file encryption key
        meta_key: 32-byte metadata encryption key
        file_id: File identifier for domain separation
        recipient_pubkey: Recipient's X25519 public key (32 bytes)

    Returns:
        Wrapped key bundle bytes (nonce || AEAD ciphertext)
    """
    return keystore.wrap_file_keys(
        file_key, meta_key, file_id, recipient_pubkey
    )


def unwrap_keys(
    keystore: KeyStore,
    wrapped_bundle: bytes,
    file_id: bytes,
    sender_pubkey: bytes,
) -> tuple[bytes, bytes]:
    """Unwrap file keys from a wrapped bundle.

    Args:
        keystore: Unlocked key store with recipient's private key
        wrapped_bundle: Output from wrap_keys_for_recipient
        file_id: File identifier for domain separation
        sender_pubkey: Sender's X25519 public key (32 bytes)

    Returns:
        (file_key, meta_key) tuple
    """
    return keystore.unwrap_file_keys(
        wrapped_bundle, file_id, sender_pubkey
    )
