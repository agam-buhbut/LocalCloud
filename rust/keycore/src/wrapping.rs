// LocalCloud Key Management - Key Wrapping Module
//
// Per-file key wrapping for sharing.
//
// Security properties:
// - Ephemeral-static ECDH: the sender generates a fresh ephemeral
//   X25519 pair per wrap; its public half travels with the bundle,
//   and the private half is zeroized immediately after the HKDF step.
//   This gives sender-side forward secrecy: compromise of the sender's
//   long-term identity key does NOT let an attacker recover past
//   file keys from stored wrapped bundles.
// - Per-file domain separation via HKDF info field (WRAP_DOMAIN || file_id).
// - The sender's long-term Ed25519 verifying key is bound into the
//   HKDF info and the AEAD AAD, so a bundle is cryptographically
//   tied to the advertised sender identity and cannot be grafted
//   across senders.
// - All intermediate secrets are held in Zeroizing<> wrappers.
// - No group keys — each recipient gets a unique wrapped bundle.
//
// Wire format (v2):
//   ephemeral_pubkey (32 bytes)
//   nonce            (24 bytes)
//   ciphertext+tag   (64 + 16 bytes)

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroizing;

use crate::secure_memory;

// ──────────────────────────── Constants ────────────────────────────

/// Domain separation prefix for file key wrapping.
const WRAP_DOMAIN: &[u8] = b"localcloud-file-wrap-v2";

/// AAD domain tag — included in the AEAD AAD alongside file_id and
/// sender identity, so ciphertext is bound to its intended context.
const WRAP_AAD_DOMAIN: &[u8] = b"localcloud-file-wrap-aad-v2";

/// Nonce length for XChaCha20-Poly1305.
const NONCE_LEN: usize = 24;

/// X25519 public-key length.
const PUBKEY_LEN: usize = 32;

/// AEAD authentication tag length for XChaCha20-Poly1305.
const TAG_LEN: usize = 16;

/// Wrapped payload: file_key (32) + meta_key (32) = 64 bytes plaintext.
const PAYLOAD_LEN: usize = 64;

// ──────────────────────────── Key Wrapping ────────────────────────────

/// Wrap file_key and meta_key for a specific recipient using
/// ephemeral-static ECDH.
///
/// 1. Generate a fresh ephemeral X25519 pair.
/// 2. Compute ECDH(ephemeral_priv, recipient_pub).
/// 3. Derive wrapping key via HKDF-SHA256, domain-separated by
///    file_id and the sender's Ed25519 identity.
/// 4. AEAD-encrypt (file_key || meta_key) with sender-identity bound AAD.
/// 5. Drop ephemeral_priv — it is never persisted.
///
/// Returns: ephemeral_pubkey (32) || nonce (24) || ciphertext+tag (80).
pub fn wrap_file_keys(
    file_key: &[u8; 32],
    meta_key: &[u8; 32],
    file_id: &[u8],
    recipient_pubkey: &[u8; 32],
    sender_identity_pub: &[u8; 32],
) -> Result<Vec<u8>, String> {
    // Ephemeral sender key — consumed by diffie_hellman, then dropped.
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient_pub = X25519PublicKey::from(*recipient_pubkey);
    let shared_secret =
        Zeroizing::new(ephemeral_secret.diffie_hellman(&recipient_pub).to_bytes());

    // RFC 7748 §6.1: reject a contributory-to-zero ECDH output. A
    // low-order recipient public key on Curve25519 produces a shared
    // secret with an attacker-known value (all zero for the identity
    // point); refusing to derive a wrapping key under these conditions
    // closes the small-subgroup attack on key wrapping.
    if secure_memory::is_zero_32(&shared_secret) {
        return Err("Low-order recipient public key rejected".to_string());
    }

    let wrapping_key = derive_wrapping_key(&shared_secret, file_id, sender_identity_pub)?;

    let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
    payload[..32].copy_from_slice(file_key);
    payload[32..].copy_from_slice(meta_key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let aad = build_aad(file_id, sender_identity_pub, ephemeral_public.as_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: payload.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|e| format!("Key wrapping failed: {}", e))?;

    let mut output = Vec::with_capacity(PUBKEY_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(ephemeral_public.as_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Unwrap file_key and meta_key from a wrapped bundle.
///
/// The recipient uses its long-term X25519 private key against the
/// ephemeral public key carried in the bundle. `sender_identity_pub`
/// is the Ed25519 public key the caller believes issued this bundle;
/// the AAD binding ensures decryption fails if that binding is wrong.
pub fn unwrap_file_keys(
    wrapped_bundle: &[u8],
    file_id: &[u8],
    sender_identity_pub: &[u8; 32],
    recipient_privkey: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    if wrapped_bundle.len() < PUBKEY_LEN + NONCE_LEN + PAYLOAD_LEN + TAG_LEN {
        return Err("Wrapped bundle too short".to_string());
    }

    let (ephemeral_pub_bytes, rest) = wrapped_bundle.split_at(PUBKEY_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let mut ephemeral_pub_arr = [0u8; PUBKEY_LEN];
    ephemeral_pub_arr.copy_from_slice(ephemeral_pub_bytes);
    let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_arr);

    // Recipient side of ECDH. We build the StaticSecret inside a scope
    // so its owned array is dropped (and zeroize feature wipes it)
    // immediately after diffie_hellman.
    let shared_secret = {
        let recipient_tmp = Zeroizing::new(*recipient_privkey);
        let recipient_secret = x25519_dalek::StaticSecret::from(*recipient_tmp);
        Zeroizing::new(recipient_secret.diffie_hellman(&ephemeral_pub).to_bytes())
    };

    // RFC 7748 §6.1: reject a contributory-to-zero ECDH output (low-
    // order ephemeral public key in the bundle). Without this, an
    // attacker who can plant a wrapped bundle can force the recipient
    // to derive a wrapping key under attacker-known shared secret.
    if secure_memory::is_zero_32(&shared_secret) {
        return Err("Low-order ephemeral public key rejected".to_string());
    }

    let wrapping_key = derive_wrapping_key(&shared_secret, file_id, sender_identity_pub)?;

    let aad = build_aad(file_id, sender_identity_pub, ephemeral_pub_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "Key unwrapping failed — invalid bundle or wrong keys".to_string())?,
    );

    if plaintext.len() != PAYLOAD_LEN {
        return Err("Unexpected payload length after unwrapping".to_string());
    }

    let mut file_key = Zeroizing::new([0u8; 32]);
    let mut meta_key = Zeroizing::new([0u8; 32]);
    file_key.copy_from_slice(&plaintext[..32]);
    meta_key.copy_from_slice(&plaintext[32..]);

    Ok((file_key, meta_key))
}

// ──────────────────────────── Internal ────────────────────────────

/// Derive a wrapping key from the ECDH shared secret.
///
/// info = WRAP_DOMAIN || sender_identity_pub || file_id
/// The sender identity is bound into the KDF so that a bundle cannot
/// be reinterpreted under a different claimed sender.
fn derive_wrapping_key(
    shared_secret: &[u8; 32],
    file_id: &[u8],
    sender_identity_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut info = Vec::with_capacity(WRAP_DOMAIN.len() + 32 + file_id.len());
    info.extend_from_slice(WRAP_DOMAIN);
    info.extend_from_slice(sender_identity_pub);
    info.extend_from_slice(file_id);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut())
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    Ok(key)
}

/// Build the AEAD AAD: WRAP_AAD_DOMAIN || sender_identity_pub ||
/// ephemeral_pub || file_id. Binding the ephemeral public key into AAD
/// prevents an attacker from swapping the ephemeral key in the header
/// while keeping the ciphertext; binding the sender identity prevents
/// cross-sender grafting.
fn build_aad(
    file_id: &[u8],
    sender_identity_pub: &[u8; 32],
    ephemeral_pub: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        WRAP_AAD_DOMAIN.len() + 32 + ephemeral_pub.len() + file_id.len(),
    );
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(sender_identity_pub);
    aad.extend_from_slice(ephemeral_pub);
    aad.extend_from_slice(file_id);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let sender_identity = [0x11u8; 32];
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let file_key = [0xAA; 32];
        let meta_key = [0xBB; 32];
        let file_id = b"test-file-id-12345";

        let wrapped = wrap_file_keys(
            &file_key,
            &meta_key,
            file_id,
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        let (unwrapped_fk, unwrapped_mk) =
            unwrap_file_keys(&wrapped, file_id, &sender_identity, &recipient_priv).unwrap();

        assert_eq!(*unwrapped_fk, file_key);
        assert_eq!(*unwrapped_mk, meta_key);
    }

    #[test]
    fn test_wrong_recipient_fails() {
        let sender_identity = [0x22u8; 32];
        let (_recipient_priv, recipient_pub) = generate_x25519_keypair();
        let (wrong_priv, _wrong_pub) = generate_x25519_keypair();

        let wrapped = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            b"test-file-id",
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        assert!(unwrap_file_keys(&wrapped, b"test-file-id", &sender_identity, &wrong_priv).is_err());
    }

    #[test]
    fn test_different_file_id_fails() {
        let sender_identity = [0x33u8; 32];
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let wrapped = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            b"file-A",
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        assert!(unwrap_file_keys(&wrapped, b"file-B", &sender_identity, &recipient_priv).is_err());
    }

    #[test]
    fn test_wrong_sender_identity_fails() {
        let sender_identity = [0x44u8; 32];
        let other_identity = [0x55u8; 32];
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let wrapped = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            b"test-file",
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        // Unwrapping under a different sender identity must fail because
        // sender identity is bound into both HKDF info and AAD.
        assert!(unwrap_file_keys(&wrapped, b"test-file", &other_identity, &recipient_priv).is_err());
    }

    #[test]
    fn test_ephemeral_uniqueness() {
        let sender_identity = [0x66u8; 32];
        let (_, recipient_pub) = generate_x25519_keypair();

        let w1 = wrap_file_keys(&[0xAA; 32], &[0xBB; 32], b"f", &recipient_pub, &sender_identity).unwrap();
        let w2 = wrap_file_keys(&[0xAA; 32], &[0xBB; 32], b"f", &recipient_pub, &sender_identity).unwrap();

        // Ephemeral pair differs on every wrap, so bundles must differ.
        assert_ne!(w1, w2);
        // And specifically the ephemeral-pub prefix must differ.
        assert_ne!(&w1[..PUBKEY_LEN], &w2[..PUBKEY_LEN]);
    }

    #[test]
    fn test_corrupted_bundle_fails() {
        let sender_identity = [0x77u8; 32];
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let mut wrapped = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            b"test-file",
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        if let Some(last) = wrapped.last_mut() {
            *last ^= 0xFF;
        }

        assert!(unwrap_file_keys(&wrapped, b"test-file", &sender_identity, &recipient_priv).is_err());
    }

    #[test]
    fn test_truncated_bundle_fails() {
        let result = unwrap_file_keys(b"too-short", b"file", &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }
}
