// LocalCloud Key Management - Key Wrapping Module
//
// Per-file key wrapping for sharing: X25519 ECDH → HKDF → AEAD-wrap.
//
// Security properties:
// - Per-file domain separation via HKDF info field
// - No key reuse across files
// - All intermediate secrets in Zeroizing<> wrappers
// - No group keys — each recipient gets a unique wrapped bundle

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

// ──────────────────────────── Constants ────────────────────────────

/// Domain separation prefix for file key wrapping
const WRAP_DOMAIN: &[u8] = b"localcloud-file-wrap-v1";

/// Nonce length for XChaCha20-Poly1305
const NONCE_LEN: usize = 24;

/// Wrapped payload: file_key (32) + meta_key (32) = 64 bytes plaintext
const PAYLOAD_LEN: usize = 64;

// ──────────────────────────── Key Wrapping ────────────────────────────

/// Wrap file_key and meta_key for a specific recipient.
///
/// 1. Compute X25519 shared secret between sender private and recipient public
/// 2. Derive wrapping key via HKDF-SHA256 with domain separation on file_id
/// 3. AEAD-encrypt (file_key || meta_key) under derived wrapping key
///
/// Returns: nonce (24 bytes) || ciphertext+tag
///
/// All intermediate secrets are zeroized after use.
pub fn wrap_file_keys(
    file_key: &[u8; 32],
    meta_key: &[u8; 32],
    file_id: &[u8],
    recipient_pubkey: &[u8; 32],
    sender_privkey: &[u8; 32],
) -> Result<Vec<u8>, String> {
    // Compute X25519 shared secret
    let sender_secret = StaticSecret::from(*sender_privkey);
    let recipient_pub = X25519PublicKey::from(*recipient_pubkey);
    let shared_secret = Zeroizing::new(sender_secret.diffie_hellman(&recipient_pub).to_bytes());

    // Derive wrapping key via HKDF with domain separation
    let wrapping_key = derive_wrapping_key(&shared_secret, file_id)?;

    // Build plaintext payload: file_key || meta_key
    let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
    payload[..32].copy_from_slice(file_key);
    payload[32..].copy_from_slice(meta_key);

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    // AEAD encrypt
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, payload.as_slice())
        .map_err(|e| format!("Key wrapping failed: {}", e))?;

    // Output: nonce || ciphertext
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Unwrap file_key and meta_key from a wrapped bundle.
///
/// Reverse of wrap_file_keys: ECDH → HKDF → AEAD-decrypt → (file_key, meta_key)
pub fn unwrap_file_keys(
    wrapped_bundle: &[u8],
    file_id: &[u8],
    sender_pubkey: &[u8; 32],
    recipient_privkey: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    // Validate minimum bundle length: nonce + at least 1 byte ciphertext + 16 byte tag
    if wrapped_bundle.len() < NONCE_LEN + PAYLOAD_LEN + 16 {
        return Err("Wrapped bundle too short".to_string());
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = wrapped_bundle.split_at(NONCE_LEN);

    // Compute X25519 shared secret (recipient-side)
    let recipient_secret = StaticSecret::from(*recipient_privkey);
    let sender_pub = X25519PublicKey::from(*sender_pubkey);
    let shared_secret = Zeroizing::new(recipient_secret.diffie_hellman(&sender_pub).to_bytes());

    // Derive the same wrapping key
    let wrapping_key = derive_wrapping_key(&shared_secret, file_id)?;

    // AEAD decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Key unwrapping failed — invalid bundle or wrong keys".to_string())?,
    );

    if plaintext.len() != PAYLOAD_LEN {
        return Err("Unexpected payload length after unwrapping".to_string());
    }

    // Extract file_key and meta_key
    let mut file_key = Zeroizing::new([0u8; 32]);
    let mut meta_key = Zeroizing::new([0u8; 32]);
    file_key.copy_from_slice(&plaintext[..32]);
    meta_key.copy_from_slice(&plaintext[32..]);

    Ok((file_key, meta_key))
}

// ──────────────────────────── Internal ────────────────────────────

/// Derive a wrapping key from shared secret + file_id using HKDF-SHA256.
///
/// Info field provides domain separation: WRAP_DOMAIN || file_id
fn derive_wrapping_key(
    shared_secret: &[u8; 32],
    file_id: &[u8],
) -> Result<Zeroizing<[u8; 32]>, String> {
    // Build info: domain || file_id
    let mut info = Vec::with_capacity(WRAP_DOMAIN.len() + file_id.len());
    info.extend_from_slice(WRAP_DOMAIN);
    info.extend_from_slice(file_id);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut())
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    Ok(key)
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
        let (sender_priv, sender_pub) = generate_x25519_keypair();
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let file_key = [0xAA; 32];
        let meta_key = [0xBB; 32];
        let file_id = b"test-file-id-12345";

        let wrapped = wrap_file_keys(
            &file_key,
            &meta_key,
            file_id,
            &recipient_pub,
            &sender_priv,
        )
        .unwrap();

        let (unwrapped_fk, unwrapped_mk) =
            unwrap_file_keys(&wrapped, file_id, &sender_pub, &recipient_priv).unwrap();

        assert_eq!(*unwrapped_fk, file_key);
        assert_eq!(*unwrapped_mk, meta_key);
    }

    #[test]
    fn test_wrong_recipient_fails() {
        let (sender_priv, sender_pub) = generate_x25519_keypair();
        let (_recipient_priv, recipient_pub) = generate_x25519_keypair();
        let (wrong_priv, _wrong_pub) = generate_x25519_keypair();

        let file_key = [0xAA; 32];
        let meta_key = [0xBB; 32];
        let file_id = b"test-file-id";

        let wrapped = wrap_file_keys(
            &file_key,
            &meta_key,
            file_id,
            &recipient_pub,
            &sender_priv,
        )
        .unwrap();

        // Try to unwrap with wrong private key
        let result = unwrap_file_keys(&wrapped, file_id, &sender_pub, &wrong_priv);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_file_id_fails() {
        let (sender_priv, sender_pub) = generate_x25519_keypair();
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let file_key = [0xAA; 32];
        let meta_key = [0xBB; 32];

        let wrapped = wrap_file_keys(
            &file_key,
            &meta_key,
            b"file-A",
            &recipient_pub,
            &sender_priv,
        )
        .unwrap();

        // Try to unwrap with different file_id (domain separation should prevent this)
        let result = unwrap_file_keys(&wrapped, b"file-B", &sender_pub, &recipient_priv);
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_separation() {
        let (sender_priv, _sender_pub) = generate_x25519_keypair();
        let (_recipient_priv, recipient_pub) = generate_x25519_keypair();

        let file_key = [0xAA; 32];
        let meta_key = [0xBB; 32];

        let wrapped_a = wrap_file_keys(
            &file_key,
            &meta_key,
            b"file-A",
            &recipient_pub,
            &sender_priv,
        )
        .unwrap();

        let wrapped_b = wrap_file_keys(
            &file_key,
            &meta_key,
            b"file-B",
            &recipient_pub,
            &sender_priv,
        )
        .unwrap();

        // Different file_ids should produce different wrapped bundles
        // (different nonces alone guarantee this, but also different HKDF-derived keys)
        assert_ne!(wrapped_a, wrapped_b);
    }

    #[test]
    fn test_corrupted_bundle_fails() {
        let (sender_priv, sender_pub) = generate_x25519_keypair();
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let file_key = [0xAA; 32];
        let meta_key = [0xBB; 32];
        let file_id = b"test-file";

        let mut wrapped = wrap_file_keys(
            &file_key,
            &meta_key,
            file_id,
            &recipient_pub,
            &sender_priv,
        )
        .unwrap();

        // Corrupt the ciphertext (last byte, part of AEAD tag)
        if let Some(last) = wrapped.last_mut() {
            *last ^= 0xFF;
        }

        let result = unwrap_file_keys(&wrapped, file_id, &sender_pub, &recipient_priv);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_bundle_fails() {
        let result = unwrap_file_keys(b"too-short", b"file", &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }
}
