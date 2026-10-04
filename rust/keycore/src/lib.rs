// LocalCloud Key Management - PyO3 Module Entry Point
//
// Exposes the Rust key management functionality to Python via PyO3.
// Python code interacts with `keycore.KeyPair`, `keycore.verify_signature()`, etc.
// Private key material NEVER crosses the FFI boundary in plaintext —
// only encrypted blobs, public keys, and operation results are returned.
//
// This is a thin skin over the `keycore-core` crate. The PyO3 `KeyPair`
// wraps a `keycore_core::IdentityKeyPair` and drives it exclusively through
// that type's high-level METHODS (sign / wrap_file_keys / unwrap_file_keys /
// encrypt_to_store / decrypt_from_store). Raw private-key bytes are never
// pulled out of the core type here — the core does not expose them.

use keycore_core::IdentityKeyPair;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// ──────────────────────────── PyO3 Wrapper: KeyPair ────────────────────────────

/// Python-visible identity keypair.
///
/// Private keys live exclusively in Rust memory (mlock'd, zeroize-on-drop).
/// Python can only access public keys and perform operations through methods.
#[pyclass]
struct KeyPair {
    inner: IdentityKeyPair,
}

#[pymethods]
impl KeyPair {
    /// Generate a new identity keypair.
    ///
    /// Private keys are immediately mlock'd and will be zeroized on drop.
    /// Core dumps are disabled for this process.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        // Inner error strings are not propagated across the FFI boundary
        // — they could echo serializer/cipher internals. Return a
        // deliberately generic Python exception instead.
        let inner = IdentityKeyPair::generate()
            .map_err(|_| PyValueError::new_err("Key generation failed"))?;
        Ok(KeyPair { inner })
    }

    /// Encrypt the keypair to a portable store format (CBOR bytes).
    ///
    /// Uses Argon2id (512 MiB, t=3) to derive an encryption key from the password,
    /// then XChaCha20-Poly1305 to encrypt the key bundle.
    fn encrypt_to_store<'py>(
        &self,
        py: Python<'py>,
        password: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = self
            .inner
            .encrypt_to_store(password)
            .map_err(|_| PyValueError::new_err("Key store encryption failed"))?;
        Ok(PyBytes::new(py, &data))
    }

    /// Decrypt a keypair from an encrypted store (CBOR bytes).
    ///
    /// Returns a new KeyPair with keys in mlock'd memory.
    /// Error message is deliberately generic to avoid leaking whether
    /// the failure was due to wrong password vs corrupted data.
    #[staticmethod]
    fn decrypt_from_store(data: &[u8], password: &[u8]) -> PyResult<Self> {
        let inner = IdentityKeyPair::decrypt_from_store(data, password)
            .map_err(|_| PyValueError::new_err("Failed to decrypt key store"))?;
        Ok(KeyPair { inner })
    }

    /// Get the X25519 public key (32 bytes).
    fn x25519_public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.x25519_public_key())
    }

    /// Get the Ed25519 public key / verifying key (32 bytes).
    fn ed25519_public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.ed25519_public_key())
    }

    /// Sign a message using the Ed25519 private key.
    ///
    /// Returns the 64-byte signature. The private key never leaves Rust memory:
    /// signing is performed by the core `IdentityKeyPair::sign` method, which
    /// uses the private key internally without exposing it.
    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self
            .inner
            .sign(message)
            .map_err(|_| PyValueError::new_err("Signing failed"))?;
        Ok(PyBytes::new(py, &sig))
    }

    /// Wrap file_key + meta_key for a specific recipient using
    /// ephemeral-static ECDH for forward secrecy.
    ///
    /// The sender's long-term X25519 key is NOT used; instead the core
    /// generates a fresh ephemeral pair per call. The core method also
    /// mixes this keypair's Ed25519 public key into the KDF and AEAD AAD
    /// as a sender label. The label does not prove who made the bundle;
    /// see keycore-core/src/wrapping.rs.
    ///
    /// Returns: ephemeral_pubkey || nonce || ciphertext+tag.
    fn wrap_file_keys<'py>(
        &self,
        py: Python<'py>,
        file_key: &[u8],
        meta_key: &[u8],
        file_id: &[u8],
        recipient_pubkey: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let fk: &[u8; 32] = file_key
            .try_into()
            .map_err(|_| PyValueError::new_err("file_key must be 32 bytes"))?;
        let mk: &[u8; 32] = meta_key
            .try_into()
            .map_err(|_| PyValueError::new_err("meta_key must be 32 bytes"))?;
        let rpk: &[u8; 32] = recipient_pubkey
            .try_into()
            .map_err(|_| PyValueError::new_err("recipient_pubkey must be 32 bytes"))?;

        let wrapped = self
            .inner
            .wrap_file_keys(fk, mk, file_id, rpk)
            .map_err(|_| PyValueError::new_err("Key wrapping failed"))?;

        Ok(PyBytes::new(py, &wrapped))
    }

    /// Unwrap file_key + meta_key from a wrapped bundle.
    ///
    /// `sender_pubkey` is the sender's long-term Ed25519 identity
    /// public key (used as a domain binding, not for ECDH). The
    /// ephemeral X25519 public key is read from the bundle itself.
    ///
    /// Returns (file_key: bytes, meta_key: bytes).
    ///
    /// FFI boundary note: the recovered file_key/meta_key necessarily
    /// cross into Python `bytes`, which are NOT zeroizable — Python owns
    /// their lifetime and CPython will not wipe the buffer on free. This
    /// is an accepted architectural boundary: these per-file content keys
    /// must be usable by the Python layer to decrypt data. Long-term
    /// identity private keys never cross this boundary; they stay in
    /// Rust mlock'd, zeroize-on-drop memory.
    fn unwrap_file_keys<'py>(
        &self,
        py: Python<'py>,
        wrapped_bundle: &[u8],
        file_id: &[u8],
        sender_pubkey: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let spk: &[u8; 32] = sender_pubkey
            .try_into()
            .map_err(|_| PyValueError::new_err("sender_pubkey must be 32 bytes"))?;

        let (file_key, meta_key) = self
            .inner
            .unwrap_file_keys(wrapped_bundle, file_id, spk)
            .map_err(|_| PyValueError::new_err("Key unwrapping failed"))?;

        // Architectural boundary: the recovered file/meta keys necessarily
        // cross into Python `bytes` here (non-zeroizable, Python-owned
        // lifetime). Accepted tradeoff — see this method's doc. Only
        // per-file content keys cross; identity private keys never do.
        Ok((
            PyBytes::new(py, file_key.as_ref()),
            PyBytes::new(py, meta_key.as_ref()),
        ))
    }
}

// ──────────────────────────── Standalone Functions ────────────────────────────

/// Verify an Ed25519 signature.
///
/// Can be called without a KeyPair (only needs the public key).
#[pyfunction]
fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    // Any structural problem (wrong-length pubkey or signature, invalid
    // curve point) is mapped to `Ok(false)` rather than `Err`. From the
    // caller's perspective, "this signature does not verify" is the same
    // outcome regardless of whether the bytes were the wrong length or
    // were the right length and merely invalid. (Finding #73)
    let pk: &[u8; 32] = match public_key.try_into() {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    Ok(keycore_core::verify(pk, message, signature).unwrap_or(false))
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
