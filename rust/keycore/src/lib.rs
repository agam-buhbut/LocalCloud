// LocalCloud Key Management - PyO3 Module Entry Point
//
// Exposes the Rust key management functionality to Python via PyO3.
// Python code interacts with `keycore.KeyPair`, `keycore.wrap_file_keys()`, etc.
// Private key material NEVER crosses the FFI boundary in plaintext —
// only encrypted blobs, public keys, and operation results are returned.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

mod identity;
mod secure_memory;
mod signing;
mod wrapping;

// ──────────────────────────── PyO3 Wrapper: KeyPair ────────────────────────────

/// Python-visible identity keypair.
///
/// Private keys live exclusively in Rust memory (mlock'd, zeroize-on-drop).
/// Python can only access public keys and perform operations through methods.
#[pyclass]
struct KeyPair {
    inner: identity::IdentityKeyPair,
}

#[pymethods]
impl KeyPair {
    /// Generate a new identity keypair.
    ///
    /// Private keys are immediately mlock'd and will be zeroized on drop.
    /// Core dumps are disabled for this process.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let inner = identity::IdentityKeyPair::generate()
            .map_err(|e| PyValueError::new_err(e))?;
        Ok(KeyPair { inner })
    }

    /// Encrypt the keypair to a portable store format (CBOR bytes).
    ///
    /// Uses Argon2id (512 MiB, t=3) to derive an encryption key from the password,
    /// then XChaCha20-Poly1305 to encrypt the key bundle.
    fn encrypt_to_store<'py>(&self, py: Python<'py>, password: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.inner.encrypt_to_store(password)
            .map_err(|e| PyValueError::new_err(e))?;
        Ok(PyBytes::new_bound(py, &data))
    }

    /// Decrypt a keypair from an encrypted store (CBOR bytes).
    ///
    /// Returns a new KeyPair with keys in mlock'd memory.
    /// Error message is deliberately generic to avoid leaking whether
    /// the failure was due to wrong password vs corrupted data.
    #[staticmethod]
    fn decrypt_from_store(data: &[u8], password: &[u8]) -> PyResult<Self> {
        let inner = identity::IdentityKeyPair::decrypt_from_store(data, password)
            .map_err(|_| PyValueError::new_err("Failed to decrypt key store"))?;
        Ok(KeyPair { inner })
    }

    /// Get the X25519 public key (32 bytes).
    fn x25519_public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.x25519_public_key())
    }

    /// Get the Ed25519 public key / verifying key (32 bytes).
    fn ed25519_public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.ed25519_public_key())
    }

    /// Sign a message using the Ed25519 private key.
    ///
    /// Returns the 64-byte signature. The private key never leaves Rust memory.
    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sig = signing::sign(self.inner.ed25519_private_key(), message)
            .map_err(|e| PyValueError::new_err(e))?;
        Ok(PyBytes::new_bound(py, &sig))
    }

    /// Wrap file_key + meta_key for a specific recipient.
    ///
    /// Performs X25519 ECDH → HKDF (domain separated by file_id) →
    /// XChaCha20-Poly1305 AEAD encryption of the key payload.
    ///
    /// Returns the wrapped bundle bytes (nonce || ciphertext).
    fn wrap_file_keys<'py>(
        &self,
        py: Python<'py>,
        file_key: &[u8],
        meta_key: &[u8],
        file_id: &[u8],
        recipient_pubkey: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        if file_key.len() != 32 || meta_key.len() != 32 || recipient_pubkey.len() != 32 {
            return Err(PyValueError::new_err(
                "file_key, meta_key, and recipient_pubkey must each be 32 bytes",
            ));
        }

        let fk: &[u8; 32] = file_key.try_into().unwrap();
        let mk: &[u8; 32] = meta_key.try_into().unwrap();
        let rpk: &[u8; 32] = recipient_pubkey.try_into().unwrap();

        let wrapped = wrapping::wrap_file_keys(
            fk,
            mk,
            file_id,
            rpk,
            self.inner.x25519_private_key(),
        )
        .map_err(|e| PyValueError::new_err(e))?;

        Ok(PyBytes::new_bound(py, &wrapped))
    }

    /// Unwrap file_key + meta_key from a wrapped bundle.
    ///
    /// Returns (file_key: bytes, meta_key: bytes).
    fn unwrap_file_keys<'py>(
        &self,
        py: Python<'py>,
        wrapped_bundle: &[u8],
        file_id: &[u8],
        sender_pubkey: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        if sender_pubkey.len() != 32 {
            return Err(PyValueError::new_err(
                "sender_pubkey must be 32 bytes",
            ));
        }

        let spk: &[u8; 32] = sender_pubkey.try_into().unwrap();

        let (file_key, meta_key) = wrapping::unwrap_file_keys(
            wrapped_bundle,
            file_id,
            spk,
            self.inner.x25519_private_key(),
        )
        .map_err(|e| PyValueError::new_err(e))?;

        Ok((
            PyBytes::new_bound(py, file_key.as_ref()),
            PyBytes::new_bound(py, meta_key.as_ref()),
        ))
    }
}

// ──────────────────────────── Standalone Functions ────────────────────────────

/// Verify an Ed25519 signature.
///
/// Can be called without a KeyPair (only needs the public key).
#[pyfunction]
fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    if public_key.len() != 32 {
        return Err(PyValueError::new_err("public_key must be 32 bytes"));
    }
    let pk: &[u8; 32] = public_key.try_into().unwrap();

    signing::verify(pk, message, signature)
        .map_err(|e| PyValueError::new_err(e))
}

// ──────────────────────────── Module Registration ────────────────────────────

/// LocalCloud secure key management module.
///
/// Provides identity keypair management (generate, encrypt, decrypt),
/// per-file key wrapping (X25519 + HKDF + AEAD), and Ed25519 signing.
///
/// All private key material is kept in Rust memory:
/// - mlock'd to prevent swapping
/// - Zeroize-on-drop for guaranteed cleanup
/// - Core dumps disabled via prctl
#[pymodule]
fn keycore(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<KeyPair>()?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    Ok(())
}
