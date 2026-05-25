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

    Performs: ephemeral-static X25519 ECDH → HKDF (domain separated) → AEAD wrap.
    A fresh ephemeral X25519 keypair is generated per call so compromise of
    the sender's long-term key does not expose past wrapped bundles (forward
    secrecy). The sender's Ed25519 identity public key is bound into the KDF
    and AEAD AAD to tie the bundle cryptographically to the claimed sender.
    All crypto happens in Rust — keys never exist in Python.

    Args:
        keystore: Unlocked key store (sender's Ed25519 identity key is used
            only as a domain binding, not for ECDH)
        file_key: 32-byte file encryption key
        meta_key: 32-byte metadata encryption key
        file_id: File identifier for domain separation
        recipient_pubkey: Recipient's X25519 public key (32 bytes)

    Returns:
        Wrapped key bundle bytes: ephemeral_pubkey || nonce || AEAD ciphertext
    """
    return keystore.wrap_file_keys(file_key, meta_key, file_id, recipient_pubkey)


def unwrap_keys(
    keystore: KeyStore,
    wrapped_bundle: bytes,
    file_id: bytes,
    sender_pubkey: bytes,
) -> tuple[bytes, bytes]:
    """Unwrap file keys from a wrapped bundle.

    The recipient's X25519 private key performs ECDH with the ephemeral
    public key embedded in the bundle. The sender's Ed25519 identity key is
    used only as a domain binding (HKDF info / AEAD AAD) so the bundle is
    cryptographically tied to the claimed sender.

    Args:
        keystore: Unlocked key store with recipient's private key
        wrapped_bundle: Output from wrap_keys_for_recipient
        file_id: File identifier for domain separation
        sender_pubkey: Sender's Ed25519 identity public key (32 bytes)

    Returns:
        (file_key, meta_key) tuple
    """
    return keystore.unwrap_file_keys(wrapped_bundle, file_id, sender_pubkey)
