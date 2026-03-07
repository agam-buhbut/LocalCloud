// LocalCloud Key Management - Signing Module
//
// Ed25519 signing and verification operations.
// The signing key never leaves Rust memory and is protected by
// Zeroizing<> and mlock from the identity module.

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};

// ──────────────────────────── Signing ────────────────────────────

/// Sign a message using an Ed25519 private key (32-byte seed).
///
/// Returns the 64-byte Ed25519 signature.
pub fn sign(private_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed25519 signature against a public key and message.
///
/// Returns Ok(true) if valid, Ok(false) if invalid signature,
/// or Err on malformed key/signature.
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| format!("Invalid public key: {}", e))?;

    if signature_bytes.len() != 64 {
        return Err("Signature must be exactly 64 bytes".to_string());
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_array);

    match verifying_key.verify(message, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn generate_ed25519_keypair() -> ([u8; 32], [u8; 32]) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing.to_bytes(), verifying.to_bytes())
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let message = b"Hello, LocalCloud!";

        let signature = sign(&priv_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        let valid = verify(&pub_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_tampered_message_fails() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let message = b"Original message";

        let signature = sign(&priv_key, message).unwrap();

        let valid = verify(&pub_key, b"Tampered message", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (priv_key, _pub_key) = generate_ed25519_keypair();
        let (_other_priv, other_pub) = generate_ed25519_keypair();
        let message = b"Test message";

        let signature = sign(&priv_key, message).unwrap();

        let valid = verify(&other_pub, message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_invalid_signature_length() {
        let (_priv_key, pub_key) = generate_ed25519_keypair();
        let result = verify(&pub_key, b"msg", &[0u8; 63]); // Wrong length
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let message = b"";

        let signature = sign(&priv_key, message).unwrap();
        let valid = verify(&pub_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_large_message() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let message = vec![0xAB; 1024 * 1024]; // 1 MiB

        let signature = sign(&priv_key, &message).unwrap();
        let valid = verify(&pub_key, &message, &signature).unwrap();
        assert!(valid);
    }
}
