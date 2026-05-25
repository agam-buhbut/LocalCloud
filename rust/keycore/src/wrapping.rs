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

/// AAD domain tag — bumped to v3 when the recipient public key was
/// added to the AAD binding. v2 bundles cannot be unwrapped under v3
/// AAD (and vice-versa), so the tag bump is itself a hard rev.
const WRAP_AAD_DOMAIN: &[u8] = b"localcloud-file-wrap-aad-v3";

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
/// Required length of the file_id (16-byte UUID4 raw bytes). The
/// length is enforced at the wrap/unwrap boundary so an empty or
/// malformed file_id can never reach HKDF/AAD construction — earlier
/// the function accepted any length, which would have allowed two
/// distinct callers passing different but suffix-related file_ids to
/// produce ambiguous AAD encodings. (Round-2 H4)
pub const REQUIRED_FILE_ID_LEN: usize = 16;

pub fn wrap_file_keys(
    file_key: &[u8; 32],
    meta_key: &[u8; 32],
    file_id: &[u8],
    recipient_pubkey: &[u8; 32],
    sender_identity_pub: &[u8; 32],
) -> Result<Vec<u8>, String> {
    if file_id.len() != REQUIRED_FILE_ID_LEN {
        return Err("file_id must be 16 bytes".to_string());
    }
    // Ephemeral sender key — consumed by diffie_hellman, then dropped.
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient_pub = X25519PublicKey::from(*recipient_pubkey);
    let shared_secret = Zeroizing::new(ephemeral_secret.diffie_hellman(&recipient_pub).to_bytes());

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

    let aad = build_aad(
        file_id,
        sender_identity_pub,
        ephemeral_public.as_bytes(),
        recipient_pubkey,
    );

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
    if file_id.len() != REQUIRED_FILE_ID_LEN {
        return Err("file_id must be 16 bytes".to_string());
    }
    // Exact-length check: AEAD ciphertext is fixed-size (PAYLOAD_LEN +
    // TAG_LEN). Accepting longer bundles previously allowed trailing
    // bytes to ride along unauthenticated. (Finding #66 / #F13.6)
    let expected_len = PUBKEY_LEN + NONCE_LEN + PAYLOAD_LEN + TAG_LEN;
    if wrapped_bundle.len() != expected_len {
        return Err("Wrapped bundle has unexpected length".to_string());
    }

    let (ephemeral_pub_bytes, rest) = wrapped_bundle.split_at(PUBKEY_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let mut ephemeral_pub_arr = [0u8; PUBKEY_LEN];
    ephemeral_pub_arr.copy_from_slice(ephemeral_pub_bytes);
    let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_arr);

    // Recipient side of ECDH. Build the StaticSecret ONCE from the
    // heap-pinned private-key copy, reuse for both diffie_hellman AND
    // for re-deriving the recipient public key bound into the AAD.
    //
    // The intermediate stack-frame copy of the private key bytes is
    // also wrapped in `Zeroizing` so the stack slot is wiped on scope
    // exit — without this the StaticSecret consumes the array, and the
    // resulting unzeroized stack frame may persist briefly. (Round-9 I1)
    let (shared_secret, recipient_pub_for_aad) = {
        let mut recipient_arr: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        recipient_arr.copy_from_slice(recipient_privkey);
        // Wrap the dereferenced array in Zeroizing so the consumed
        // copy fed into StaticSecret::from is wiped on drop. The
        // StaticSecret itself also zero-on-drop, but the intermediate
        // by-value stack copy did not before.
        let secret_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(*recipient_arr);
        let recipient_secret = x25519_dalek::StaticSecret::from(*secret_bytes);
        let recipient_pub_bytes = *X25519PublicKey::from(&recipient_secret).as_bytes();
        let ss = Zeroizing::new(
            recipient_secret.diffie_hellman(&ephemeral_pub).to_bytes(),
        );
        (ss, recipient_pub_bytes)
    };

    // RFC 7748 §6.1: reject a contributory-to-zero ECDH output (low-
    // order ephemeral public key in the bundle). Without this, an
    // attacker who can plant a wrapped bundle can force the recipient
    // to derive a wrapping key under attacker-known shared secret.
    if secure_memory::is_zero_32(&shared_secret) {
        return Err("Low-order ephemeral public key rejected".to_string());
    }

    let wrapping_key = derive_wrapping_key(&shared_secret, file_id, sender_identity_pub)?;
    let aad = build_aad(
        file_id,
        sender_identity_pub,
        ephemeral_pub_bytes,
        &recipient_pub_for_aad,
    );

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

/// Build the AEAD AAD::
///
///     WRAP_AAD_DOMAIN
///         || sender_identity_pub (32 bytes)
///         || recipient_pubkey    (32 bytes)
///         || ephemeral_pub       (32 bytes)
///         || file_id             (16 bytes)
///
/// Binding the ephemeral pubkey defeats ephemeral-swap attacks;
/// binding the sender identity defeats cross-sender grafting;
/// binding the recipient pubkey ensures a bundle wrapped for one
/// recipient cannot decrypt under another's private key even if the
/// outer policy enforcement is bypassed. All fields are fixed-length
/// so the concatenation is unambiguous.
fn build_aad(
    file_id: &[u8],
    sender_identity_pub: &[u8; 32],
    ephemeral_pub: &[u8],
    recipient_pub: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        WRAP_AAD_DOMAIN.len()
            + 32 // sender
            + 32 // recipient
            + ephemeral_pub.len()
            + file_id.len(),
    );
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(sender_identity_pub);
    aad.extend_from_slice(recipient_pub);
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
        let file_id = &[0u8; 16];

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
            &[0u8; 16],
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        assert!(unwrap_file_keys(&wrapped, &[0u8; 16], &sender_identity, &wrong_priv).is_err());
    }

    #[test]
    fn test_different_file_id_fails() {
        let sender_identity = [0x33u8; 32];
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let wrapped = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            &[2u8; 16],
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        assert!(unwrap_file_keys(&wrapped, &[3u8; 16], &sender_identity, &recipient_priv).is_err());
    }

    #[test]
    fn test_wrong_sender_identity_fails() {
        let sender_identity = [0x44u8; 32];
        let other_identity = [0x55u8; 32];
        let (recipient_priv, recipient_pub) = generate_x25519_keypair();

        let wrapped = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            &[1u8; 16],
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        // Unwrapping under a different sender identity must fail because
        // sender identity is bound into both HKDF info and AAD.
        assert!(unwrap_file_keys(&wrapped, &[1u8; 16], &other_identity, &recipient_priv).is_err());
    }

    #[test]
    fn test_ephemeral_uniqueness() {
        let sender_identity = [0x66u8; 32];
        let (_, recipient_pub) = generate_x25519_keypair();

        let w1 = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            &[4u8; 16],
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();
        let w2 = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            &[4u8; 16],
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

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
            &[1u8; 16],
            &recipient_pub,
            &sender_identity,
        )
        .unwrap();

        if let Some(last) = wrapped.last_mut() {
            *last ^= 0xFF;
        }

        assert!(unwrap_file_keys(&wrapped, &[1u8; 16], &sender_identity, &recipient_priv).is_err());
    }

    #[test]
    fn test_truncated_bundle_fails() {
        let result = unwrap_file_keys(b"too-short", &[0u8; 16], &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_length_file_id_rejected() {
        let recipient_pub = [0xCC; 32];
        let result_wrap = wrap_file_keys(
            &[0xAA; 32],
            &[0xBB; 32],
            b"short", // not 16 bytes
            &recipient_pub,
            &[0x99; 32],
        );
        assert!(result_wrap.is_err());

        let result_unwrap = unwrap_file_keys(&[0u8; 136], b"short", &[0u8; 32], &[0u8; 32]);
        assert!(result_unwrap.is_err());
    }
}
