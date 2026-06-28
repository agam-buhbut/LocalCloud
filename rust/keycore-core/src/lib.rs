// LocalCloud Key Management - Pure-Rust Cryptographic Core
//
// This crate holds the pure crypto logic with NO FFI bindings (no PyO3,
// no UniFFI). The desktop PyO3 extension (`keycore`) and the mobile
// UniFFI skin (`keycore-mobile`) are thin wrappers over this crate.
//
// SECURITY INVARIANT: raw private key material never crosses this crate's
// public boundary. `IdentityKeyPair` keeps its X25519/Ed25519 private-key
// accessors `pub(crate)` and exposes only high-level operations (sign,
// wrap_file_keys, unwrap_file_keys, encrypt_to_store, decrypt_from_store)
// that use the raw keys internally. Only public keys, encrypted blobs,
// signatures, and recovered per-file content keys are returned.

pub mod identity;
pub mod secure_memory;
pub mod signing;
pub mod wrapping;

// On-disk/wire format pinning vectors — proves the crate split preserves
// the keystore and wrap-bundle byte formats so existing keystores still
// decrypt and desktop<->Android stay interoperable.
#[cfg(test)]
mod format_pin;

// Public API re-exports. The crypto-operation free functions
// (`sign`, `verify`, `wrap_file_keys`, `unwrap_file_keys`) accept key
// material as INPUT but never return identity private keys, so they do
// not constitute private-key egress.
pub use identity::{EncryptedKeyStore, IdentityKeyPair};
pub use signing::{sign, verify};
pub use wrapping::{unwrap_file_keys, wrap_file_keys, REQUIRED_FILE_ID_LEN};
