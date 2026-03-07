// LocalCloud Key Management - Identity Module
//
// Handles identity keypair lifecycle: generation, mlock, zeroize-on-drop,
// encrypted storage via Argon2id + XChaCha20-Poly1305.
//
// Security guarantees:
// - All private keys stored in Zeroizing<> wrappers (drop = guaranteed zeroize)
// - mlock() called on key memory to prevent swap
// - prctl(PR_SET_DUMPABLE, 0) prevents core dumps
// - Keys encrypted at rest with Argon2id-derived master key

use argon2::{self, Argon2, Algorithm, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::secure_memory;

// ──────────────────────────── Constants ────────────────────────────

/// Protocol version for the encrypted key store format
const KEY_STORE_VERSION: u8 = 1;

/// Argon2id parameters for client-side key derivation
/// Memory: 512 MiB, Time: 3 iterations, Parallelism: 1
const ARGON2_M_COST_KIB: u32 = 512 * 1024; // 512 MiB in KiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;

/// Salt length for Argon2id
const SALT_LEN: usize = 32;

/// Nonce length for XChaCha20-Poly1305
const NONCE_LEN: usize = 24;

// ──────────────────────────── Types ────────────────────────────

/// Serializable format for the encrypted key store on disk
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyStore {
    /// Format version for migration support
    pub version: u8,
    /// Random salt for Argon2id
    pub salt: Vec<u8>,
    /// Argon2id memory cost in KiB
    pub m_cost: u32,
    /// Argon2id time cost (iterations)
    pub t_cost: u32,
    /// Argon2id parallelism
    pub p_cost: u32,
    /// Nonce used for AEAD encryption of the key bundle
    pub nonce: Vec<u8>,
    /// AEAD-encrypted key bundle (X25519 private + Ed25519 private + both pubkeys)
    pub ciphertext: Vec<u8>,
}

/// Plaintext key bundle for serialization before encryption
#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct KeyBundle {
    /// X25519 private key (32 bytes)
    x25519_private: Vec<u8>,
    /// X25519 public key (32 bytes)
    x25519_public: Vec<u8>,
    /// Ed25519 private key (32 bytes, seed)
    ed25519_private: Vec<u8>,
    /// Ed25519 public key (32 bytes)
    ed25519_public: Vec<u8>,
}

/// In-memory identity keypair with all key material in locked, zeroizing memory.
///
/// When dropped, private keys are guaranteed to be zeroized and memory unlocked.
pub struct IdentityKeyPair {
    // Private keys — zeroized on drop
    x25519_private: Zeroizing<[u8; 32]>,
    ed25519_private: Zeroizing<[u8; 32]>,
    // Public keys — not secret but kept alongside for convenience
    x25519_public: [u8; 32],
    ed25519_public: [u8; 32],
    // Track whether mlock succeeded so we can munlock on drop
    is_locked: bool,
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        // Zeroizing<> handles zeroization automatically via its own Drop
        // We just need to munlock the memory if it was locked
        if self.is_locked {
            secure_memory::munlock_slice(self.x25519_private.as_ref());
            secure_memory::munlock_slice(self.ed25519_private.as_ref());
            self.is_locked = false;
        }
    }
}

impl IdentityKeyPair {
    /// Generate a new identity keypair from OS CSPRNG.
    ///
    /// Private keys are immediately mlock'd to prevent swapping.
    /// Core dumps are disabled via prctl.
    pub fn generate() -> Result<Self, String> {
        // Prevent core dumps
        secure_memory::disable_core_dumps()
            .map_err(|e| format!("Failed to disable core dumps: {}", e))?;

        // Generate X25519 keypair
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_pub = X25519PublicKey::from(&x25519_secret);

        let mut x25519_priv_bytes = Zeroizing::new([0u8; 32]);
        x25519_priv_bytes.copy_from_slice(&x25519_secret.to_bytes());

        // Generate Ed25519 keypair
        let ed25519_signing = Ed25519SigningKey::generate(&mut OsRng);
        let ed25519_verifying = ed25519_signing.verifying_key();

        let mut ed25519_priv_bytes = Zeroizing::new([0u8; 32]);
        ed25519_priv_bytes.copy_from_slice(&ed25519_signing.to_bytes());

        // mlock private key memory — warn loudly on failure (#15)
        let x25519_locked = secure_memory::mlock_slice(x25519_priv_bytes.as_ref());
        let ed25519_locked = secure_memory::mlock_slice(ed25519_priv_bytes.as_ref());
        let lock_ok = x25519_locked && ed25519_locked;
        if !lock_ok {
            eprintln!(
                "WARNING: mlock() failed for private key memory. \
                 Keys may be swappable to disk. Run with sufficient \
                 RLIMIT_MEMLOCK or as root for production use."
            );
        }

        Ok(IdentityKeyPair {
            x25519_private: x25519_priv_bytes,
            ed25519_private: ed25519_priv_bytes,
            x25519_public: x25519_pub.to_bytes(),
            ed25519_public: ed25519_verifying.to_bytes(),
            is_locked: lock_ok,
        })
    }

    /// Encrypt the keypair into a portable store format.
    ///
    /// Uses Argon2id to derive an encryption key from the password,
    /// then encrypts the serialized key bundle with XChaCha20-Poly1305.
    pub fn encrypt_to_store(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        // Generate random salt and nonce
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive encryption key from password via Argon2id
        let master_key = Self::derive_master_key(password, &salt)?;

        // Serialize the key bundle
        let bundle = KeyBundle {
            x25519_private: self.x25519_private.to_vec(),
            x25519_public: self.x25519_public.to_vec(),
            ed25519_private: self.ed25519_private.to_vec(),
            ed25519_public: self.ed25519_public.to_vec(),
        };

        let mut plaintext = Zeroizing::new(Vec::new());
        ciborium::into_writer(&bundle, &mut *plaintext)
            .map_err(|e| format!("CBOR serialization failed: {}", e))?;

        // Encrypt with XChaCha20-Poly1305
        let cipher = XChaCha20Poly1305::new_from_slice(master_key.as_ref())
            .map_err(|e| format!("Cipher init failed: {}", e))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // Build the encrypted key store
        let store = EncryptedKeyStore {
            version: KEY_STORE_VERSION,
            salt: salt.to_vec(),
            m_cost: ARGON2_M_COST_KIB,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };

        // Serialize the store to CBOR
        let mut output = Vec::new();
        ciborium::into_writer(&store, &mut output)
            .map_err(|e| format!("Store serialization failed: {}", e))?;

        Ok(output)
    }

    /// Decrypt a keypair from an encrypted store.
    ///
    /// Uses the stored Argon2id params to derive the encryption key,
    /// then decrypts and reconstructs the identity keypair with mlock.
    pub fn decrypt_from_store(data: &[u8], password: &[u8]) -> Result<Self, String> {
        // Prevent core dumps
        secure_memory::disable_core_dumps()
            .map_err(|e| format!("Failed to disable core dumps: {}", e))?;

        // Deserialize the store
        let store: EncryptedKeyStore = ciborium::from_reader(data)
            .map_err(|e| format!("Store deserialization failed: {}", e))?;

        if store.version != KEY_STORE_VERSION {
            return Err(format!(
                "Unsupported key store version: {} (expected {})",
                store.version, KEY_STORE_VERSION
            ));
        }

        // Derive the master key using stored Argon2id parameters
        let master_key = Self::derive_master_key_with_params(
            password,
            &store.salt,
            store.m_cost,
            store.t_cost,
            store.p_cost,
        )?;

        // Decrypt the key bundle
        let cipher = XChaCha20Poly1305::new_from_slice(master_key.as_ref())
            .map_err(|e| format!("Cipher init failed: {}", e))?;

        if store.nonce.len() != NONCE_LEN {
            return Err("Invalid nonce length".to_string());
        }
        let nonce = XNonce::from_slice(&store.nonce);

        let plaintext_bytes = Zeroizing::new(
            cipher
                .decrypt(nonce, store.ciphertext.as_slice())
                .map_err(|_| "Decryption failed — wrong password or corrupted data".to_string())?,
        );

        // Deserialize the key bundle
        let bundle: KeyBundle = ciborium::from_reader(plaintext_bytes.as_slice())
            .map_err(|e| format!("Key bundle deserialization failed: {}", e))?;

        // Validate key lengths
        if bundle.x25519_private.len() != 32
            || bundle.x25519_public.len() != 32
            || bundle.ed25519_private.len() != 32
            || bundle.ed25519_public.len() != 32
        {
            return Err("Invalid key lengths in key bundle".to_string());
        }

        // Reconstruct the keypair with mlock
        let mut x25519_priv = Zeroizing::new([0u8; 32]);
        x25519_priv.copy_from_slice(&bundle.x25519_private);

        let mut ed25519_priv = Zeroizing::new([0u8; 32]);
        ed25519_priv.copy_from_slice(&bundle.ed25519_private);

        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&bundle.x25519_public);

        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&bundle.ed25519_public);

        // Verify that public keys match private keys
        let derived_x25519_pub =
            X25519PublicKey::from(&StaticSecret::from(*x25519_priv));
        if derived_x25519_pub.as_bytes() != &x25519_pub {
            return Err("X25519 public key does not match private key".to_string());
        }

        let derived_ed25519_pub = Ed25519SigningKey::from_bytes(&ed25519_priv)
            .verifying_key();
        if derived_ed25519_pub.to_bytes() != ed25519_pub {
            return Err("Ed25519 public key does not match private key".to_string());
        }

        // mlock private key memory — warn loudly on failure (#15)
        let x25519_locked = secure_memory::mlock_slice(x25519_priv.as_ref());
        let ed25519_locked = secure_memory::mlock_slice(ed25519_priv.as_ref());
        let lock_ok = x25519_locked && ed25519_locked;
        if !lock_ok {
            eprintln!(
                "WARNING: mlock() failed for decrypted key memory. \
                 Keys may be swappable to disk."
            );
        }

        Ok(IdentityKeyPair {
            x25519_private: x25519_priv,
            ed25519_private: ed25519_priv,
            x25519_public: x25519_pub,
            ed25519_public: ed25519_pub,
            is_locked: lock_ok,
        })
    }

    // ──────────── Accessors (public keys are not secret) ────────────

    /// Get the X25519 public key bytes
    pub fn x25519_public_key(&self) -> &[u8; 32] {
        &self.x25519_public
    }

    /// Get the Ed25519 public key bytes (verifying key)
    pub fn ed25519_public_key(&self) -> &[u8; 32] {
        &self.ed25519_public
    }

    /// Get a reference to the X25519 private key (for internal crypto ops only)
    pub(crate) fn x25519_private_key(&self) -> &[u8; 32] {
        &self.x25519_private
    }

    /// Get a reference to the Ed25519 private key (for internal crypto ops only)
    pub(crate) fn ed25519_private_key(&self) -> &[u8; 32] {
        &self.ed25519_private
    }

    // ──────────── Internal key derivation ────────────

    /// Derive master encryption key from password using default Argon2id params
    fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        Self::derive_master_key_with_params(
            password,
            salt,
            ARGON2_M_COST_KIB,
            ARGON2_T_COST,
            ARGON2_P_COST,
        )
    }

    /// Derive master encryption key from password using explicit Argon2id params
    fn derive_master_key_with_params(
        password: &[u8],
        salt: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        let params = Params::new(m_cost, t_cost, p_cost, Some(ARGON2_OUTPUT_LEN))
            .map_err(|e| format!("Invalid Argon2 params: {}", e))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, salt, key.as_mut())
            .map_err(|e| format!("Argon2id key derivation failed: {}", e))?;

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = IdentityKeyPair::generate().unwrap();
        // Public keys should not be all zeros
        assert_ne!(kp.x25519_public_key(), &[0u8; 32]);
        assert_ne!(kp.ed25519_public_key(), &[0u8; 32]);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let kp = IdentityKeyPair::generate().unwrap();
        let password = b"test-password-for-unit-testing";

        // Encrypt to store
        let store_data = kp.encrypt_to_store(password).unwrap();
        assert!(!store_data.is_empty());

        // Decrypt from store
        let kp2 = IdentityKeyPair::decrypt_from_store(&store_data, password).unwrap();

        // Verify keys match
        assert_eq!(kp.x25519_public_key(), kp2.x25519_public_key());
        assert_eq!(kp.ed25519_public_key(), kp2.ed25519_public_key());
        assert_eq!(kp.x25519_private_key(), kp2.x25519_private_key());
        assert_eq!(kp.ed25519_private_key(), kp2.ed25519_private_key());
    }

    #[test]
    fn test_wrong_password_fails() {
        let kp = IdentityKeyPair::generate().unwrap();
        let store_data = kp.encrypt_to_store(b"correct-password").unwrap();

        let result = IdentityKeyPair::decrypt_from_store(&store_data, b"wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_store_fails() {
        let kp = IdentityKeyPair::generate().unwrap();
        let mut store_data = kp.encrypt_to_store(b"password").unwrap();

        // Corrupt the last byte (part of ciphertext/tag)
        if let Some(last) = store_data.last_mut() {
            *last ^= 0xFF;
        }

        let result = IdentityKeyPair::decrypt_from_store(&store_data, b"password");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keypairs_are_unique() {
        let kp1 = IdentityKeyPair::generate().unwrap();
        let kp2 = IdentityKeyPair::generate().unwrap();

        assert_ne!(kp1.x25519_public_key(), kp2.x25519_public_key());
        assert_ne!(kp1.ed25519_public_key(), kp2.ed25519_public_key());
    }
}
