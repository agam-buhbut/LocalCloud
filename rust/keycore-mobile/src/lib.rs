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
