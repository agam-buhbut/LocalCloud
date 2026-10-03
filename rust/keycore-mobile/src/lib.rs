// LocalCloud Key Management - UniFFI Mobile Skin
//
// Mirrors the desktop PyO3 surface (`keycore`) for the Android client,
// generated via UniFFI proc-macro mode (no .udl, no build.rs).
//
// Like the PyO3 skin, this is a thin wrapper over `keycore-core`: `KeyPair`
// wraps a `keycore_core::IdentityKeyPair` and drives it through that type's
// high-level METHODS. Raw private-key bytes are never pulled out of the core
// type — the core does not expose them.
//
// SECURITY: every fallible operation returns one opaque error
// (`KeycoreError::Crypto`); inner error strings from the core are discarded
// at this boundary so the foreign side can never observe cipher/errno/oracle
// internals (see `KeycoreError`).

use std::sync::Arc;

use keycore_core::IdentityKeyPair;

uniffi::setup_scaffolding!("keycore_mobile");

/// Opaque error returned by every fallible mobile operation.
///
/// SECURITY (error oracle): exactly ONE fieldless variant. Every inner
/// `Result<_, String>` from `keycore-core` is mapped to this, DISCARDING the
/// inner string. UniFFI's default error surfacing would otherwise carry the
/// inner `Display` text across the FFI — leaking whether a failure was a
/// wrong password vs. corrupted ciphertext vs. an errno, i.e. an error-oracle
/// regression. Do not add fields or per-cause variants, and do not interpolate
/// inner detail into the `Display` impl below.
#[derive(Debug, uniffi::Error)]
pub enum KeycoreError {
    /// A cryptographic operation failed. The specific cause is intentionally
    /// withheld.
    Crypto,
}

impl std::fmt::Display for KeycoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fixed, cause-free message. Never interpolate inner error detail.
        write!(f, "cryptographic operation failed")
    }
}

impl std::error::Error for KeycoreError {}

/// The two 32-byte content keys recovered by [`KeyPair::unwrap_file_keys`].
///
/// UniFFI has no tuple type, so the PyO3 `(bytes, bytes)` return is modelled
/// as this record. These are per-file CONTENT keys, NOT identity private keys.
#[derive(uniffi::Record)]
pub struct UnwrappedKeys {
    pub file_key: Vec<u8>,
    pub meta_key: Vec<u8>,
}

/// Mobile identity keypair.
///
/// Private keys live exclusively inside the wrapped
/// `keycore_core::IdentityKeyPair` (mlock'd, zeroize-on-drop) and never cross
/// the FFI boundary; the foreign side can only reach public keys and the
/// operation methods.
#[derive(uniffi::Object)]
pub struct KeyPair {
    inner: IdentityKeyPair,
}

#[uniffi::export]
impl KeyPair {
    /// Generate a new identity keypair (mlock'd, zeroize-on-drop; core dumps
    /// disabled for the process).
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, KeycoreError> {
        let inner = IdentityKeyPair::generate().map_err(|_| KeycoreError::Crypto)?;
        Ok(Arc::new(KeyPair { inner }))
    }

    /// Decrypt a keypair from an encrypted store (CBOR bytes).
    ///
    /// # Security — timing side channel
    /// Cheap structural checks run BEFORE the expensive Argon2id KDF, so a
    /// structural error is distinguishable by timing from a wrong-password
    /// error. Use this for LOCAL provisioning / unlock only (an on-disk file
    /// under the user's control). NEVER wire it to a remote oracle: an
    /// adversary submitting blobs could distinguish error classes via timing.
    #[uniffi::constructor]
    pub fn decrypt_from_store(data: Vec<u8>, password: Vec<u8>) -> Result<Arc<Self>, KeycoreError> {
        let inner = IdentityKeyPair::decrypt_from_store(&data, &password)
            .map_err(|_| KeycoreError::Crypto)?;
        Ok(Arc::new(KeyPair { inner }))
    }

    /// Encrypt this keypair to a portable store (CBOR bytes): Argon2id
    /// (512 MiB, t=3) + XChaCha20-Poly1305.
    pub fn encrypt_to_store(&self, password: Vec<u8>) -> Result<Vec<u8>, KeycoreError> {
        self.inner
            .encrypt_to_store(&password)
            .map_err(|_| KeycoreError::Crypto)
    }

    /// X25519 public key (32 bytes).
    pub fn x25519_public_key(&self) -> Vec<u8> {
        self.inner.x25519_public_key().to_vec()
    }

    /// Ed25519 public / verifying key (32 bytes).
    pub fn ed25519_public_key(&self) -> Vec<u8> {
        self.inner.ed25519_public_key().to_vec()
    }

    /// Sign a message with the Ed25519 private key; returns the 64-byte
    /// signature. The private key never leaves the core type.
    pub fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, KeycoreError> {
        self.inner.sign(&message).map_err(|_| KeycoreError::Crypto)
    }

    /// Wrap `file_key` + `meta_key` (each 32 bytes) for `recipient_pubkey`
    /// (32 bytes) using ephemeral-static ECDH, binding this identity as the
    /// sender. `file_id` must be 16 bytes.
    ///
    /// Returns: ephemeral_pubkey || nonce || ciphertext+tag.
    pub fn wrap_file_keys(
        &self,
        file_key: Vec<u8>,
        meta_key: Vec<u8>,
        file_id: Vec<u8>,
        recipient_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, KeycoreError> {
        let fk = to_array32(&file_key)?;
        let mk = to_array32(&meta_key)?;
        let rpk = to_array32(&recipient_pubkey)?;
        self.inner
            .wrap_file_keys(&fk, &mk, &file_id, &rpk)
            .map_err(|_| KeycoreError::Crypto)
    }

    /// Unwrap `file_key` + `meta_key` from a wrapped bundle using this
    /// identity's X25519 private key. `sender_pubkey` (32 bytes) is the
    /// sender's Ed25519 identity key (domain binding, not an ECDH input);
    /// `file_id` must be 16 bytes.
    pub fn unwrap_file_keys(
        &self,
        wrapped_bundle: Vec<u8>,
        file_id: Vec<u8>,
        sender_pubkey: Vec<u8>,
    ) -> Result<UnwrappedKeys, KeycoreError> {
        let spk = to_array32(&sender_pubkey)?;
        let (file_key, meta_key) = self
            .inner
            .unwrap_file_keys(&wrapped_bundle, &file_id, &spk)
            .map_err(|_| KeycoreError::Crypto)?;
        // FFI boundary, same tradeoff as the PyO3 skin: the copies handed to
        // Kotlin cannot be wiped from Rust. The `Zeroizing` originals are
        // wiped when they drop at the end of this call.
        Ok(UnwrappedKeys {
            file_key: file_key.to_vec(),
            meta_key: meta_key.to_vec(),
        })
    }
}

/// Verify an Ed25519 signature.
///
/// Returns `false` for any malformed input or invalid signature — "this does
/// not verify" is the only observable outcome, so callers cannot distinguish
/// "malformed" from "invalid".
#[uniffi::export]
pub fn verify_signature(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let pk: [u8; 32] = match public_key.as_slice().try_into() {
        Ok(p) => p,
        Err(_) => return false,
    };
    keycore_core::verify(&pk, &message, &signature).unwrap_or(false)
}

/// Convert a byte slice to a 32-byte array, mapping any length mismatch to the
/// opaque error (no length detail leaked).
fn to_array32(bytes: &[u8]) -> Result<[u8; 32], KeycoreError> {
    bytes.try_into().map_err(|_| KeycoreError::Crypto)
}

// These tests call the same exported API that Kotlin sees. UniFFI exposes
// `KeycoreError` to Kotlin as `KeycoreException`.
#[cfg(test)]
mod tests {
    use super::*;

    const FILE_ID: [u8; 16] = [7u8; 16];

    fn keypair() -> Arc<KeyPair> {
        KeyPair::generate().expect("key generation should succeed")
    }

    /// The error from a call that must fail. (`unwrap_err` needs the success
    /// type to be `Debug`; `KeyPair` and `UnwrappedKeys` are not.)
    fn err_of<T>(result: Result<T, KeycoreError>) -> KeycoreError {
        match result {
            Ok(_) => panic!("expected the call to fail"),
            Err(err) => err,
        }
    }

    /// Every failure must be the one fieldless variant with the fixed,
    /// cause-free message. The `match` has no catch-all arm, so this stops
    /// compiling if a second variant is ever added.
    fn assert_opaque(err: &KeycoreError) {
        match err {
            KeycoreError::Crypto => {}
        }
        assert_eq!(err.to_string(), "cryptographic operation failed");
    }

    #[test]
    fn generate_gives_32_byte_public_keys_and_unique_keypairs() {
        let a = keypair();
        let b = keypair();
        assert_eq!(a.x25519_public_key().len(), 32);
        assert_eq!(a.ed25519_public_key().len(), 32);
        assert_ne!(a.x25519_public_key(), [0u8; 32]);
        assert_ne!(a.ed25519_public_key(), [0u8; 32]);
        assert_ne!(a.x25519_public_key(), b.x25519_public_key());
        assert_ne!(a.ed25519_public_key(), b.ed25519_public_key());
    }

    #[test]
    fn sign_then_verify_signature() {
        let kp = keypair();
        let msg = b"hello from android".to_vec();
        let sig = kp.sign(msg.clone()).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify_signature(
            kp.ed25519_public_key(),
            msg.clone(),
            sig.clone()
        ));

        // A changed message, another signer's key, or a changed signature
        // must not verify.
        assert!(!verify_signature(
            kp.ed25519_public_key(),
            b"hello from elsewhere".to_vec(),
            sig.clone()
        ));
        assert!(!verify_signature(
            keypair().ed25519_public_key(),
            msg.clone(),
            sig.clone()
        ));
        let mut changed_sig = sig;
        changed_sig[0] ^= 0x01;
        assert!(!verify_signature(kp.ed25519_public_key(), msg, changed_sig));
    }

    #[test]
    fn verify_signature_is_false_for_malformed_input() {
        let kp = keypair();
        let msg = b"m".to_vec();
        let sig = kp.sign(msg.clone()).unwrap();
        assert!(!verify_signature(vec![0u8; 31], msg.clone(), sig.clone()));
        assert!(!verify_signature(Vec::new(), msg.clone(), sig.clone()));
        assert!(!verify_signature(
            kp.ed25519_public_key(),
            msg.clone(),
            sig[..63].to_vec()
        ));
        assert!(!verify_signature(kp.ed25519_public_key(), msg, Vec::new()));
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let sender = keypair();
        let recipient = keypair();
        let file_key = vec![0xAA; 32];
        let meta_key = vec![0xBB; 32];
        let bundle = sender
            .wrap_file_keys(
                file_key.clone(),
                meta_key.clone(),
                FILE_ID.to_vec(),
                recipient.x25519_public_key(),
            )
            .unwrap();
        // Wire format: ephemeral pubkey (32) || nonce (24) || ciphertext (64) + tag (16).
        assert_eq!(bundle.len(), 32 + 24 + 64 + 16);

        let keys = recipient
            .unwrap_file_keys(bundle, FILE_ID.to_vec(), sender.ed25519_public_key())
            .unwrap();
        assert_eq!(keys.file_key, file_key);
        assert_eq!(keys.meta_key, meta_key);
    }

    #[test]
    fn unwrap_fails_opaquely_for_wrong_keys_file_id_or_tampering() {
        let sender = keypair();
        let recipient = keypair();
        let bundle = sender
            .wrap_file_keys(
                vec![1; 32],
                vec![2; 32],
                FILE_ID.to_vec(),
                recipient.x25519_public_key(),
            )
            .unwrap();
        let mut tampered = bundle.clone();
        *tampered.last_mut().unwrap() ^= 0xFF;

        let failures = [
            // Someone other than the recipient.
            err_of(keypair().unwrap_file_keys(
                bundle.clone(),
                FILE_ID.to_vec(),
                sender.ed25519_public_key(),
            )),
            // The right recipient, but a different claimed sender.
            err_of(recipient.unwrap_file_keys(
                bundle.clone(),
                FILE_ID.to_vec(),
                keypair().ed25519_public_key(),
            )),
            // A different file id.
            err_of(recipient.unwrap_file_keys(bundle, vec![8u8; 16], sender.ed25519_public_key())),
            // One flipped byte.
            err_of(recipient.unwrap_file_keys(
                tampered,
                FILE_ID.to_vec(),
                sender.ed25519_public_key(),
            )),
        ];
        for err in &failures {
            assert_opaque(err);
        }
    }

    #[test]
    fn every_failure_is_the_single_opaque_error() {
        let kp = keypair();
        let peer = keypair();
        let key = vec![0x11; 32];

        let failures = [
            // wrap_file_keys: wrong-length inputs.
            err_of(kp.wrap_file_keys(
                vec![0; 31],
                key.clone(),
                FILE_ID.to_vec(),
                peer.x25519_public_key(),
            )),
            err_of(kp.wrap_file_keys(
                key.clone(),
                vec![0; 33],
                FILE_ID.to_vec(),
                peer.x25519_public_key(),
            )),
            err_of(kp.wrap_file_keys(
                key.clone(),
                key.clone(),
                vec![0; 15],
                peer.x25519_public_key(),
            )),
            err_of(kp.wrap_file_keys(key.clone(), key.clone(), FILE_ID.to_vec(), vec![0; 31])),
            // wrap_file_keys: an all-zero (low-order) recipient key is refused.
            err_of(kp.wrap_file_keys(key.clone(), key, FILE_ID.to_vec(), vec![0; 32])),
            // unwrap_file_keys: not a bundle, too short, wrong-length sender key.
            err_of(kp.unwrap_file_keys(vec![0; 136], FILE_ID.to_vec(), peer.ed25519_public_key())),
            err_of(kp.unwrap_file_keys(vec![0; 10], FILE_ID.to_vec(), peer.ed25519_public_key())),
            err_of(kp.unwrap_file_keys(vec![0; 136], FILE_ID.to_vec(), vec![0; 31])),
            // decrypt_from_store: input that is not a key store. These are
            // refused before the slow Argon2id step, so the test stays fast.
            err_of(KeyPair::decrypt_from_store(
                b"not a key store".to_vec(),
                b"pw".to_vec(),
            )),
            err_of(KeyPair::decrypt_from_store(Vec::new(), b"pw".to_vec())),
            err_of(KeyPair::decrypt_from_store(
                vec![0; 16 * 1024 + 1],
                b"pw".to_vec(),
            )),
        ];
        for err in &failures {
            assert_opaque(err);
        }
    }
}
