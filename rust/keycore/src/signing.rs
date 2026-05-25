// LocalCloud Key Management - Signing Module
//
// Ed25519 signing and verification operations.
// The signing key never leaves Rust memory and is protected by
// Zeroizing<> and mlock from the identity module.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

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
/// Returns Ok(true) if valid, Ok(false) for any other reason — wrong
/// signature, wrong-length signature, or invalid public key. Callers
/// distinguishing "malformed" from "invalid" got the same observable
/// outcome anyway, and surfacing those as Err leaked which gate
/// rejected attacker-controlled bytes. (Finding #5, #73)
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    let verifying_key = match VerifyingKey::from_bytes(public_key) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };

    if signature_bytes.len() != 64 {
        return Ok(false);
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(message, &signature).is_ok())
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
        // Wrong-length signature should NOT be returned as Err — it
        // should be a normal "this does not verify" Ok(false), so
        // callers can't distinguish "malformed" from "invalid". (#73)
        let result = verify(&pub_key, b"msg", &[0u8; 63]).unwrap();
        assert!(!result);
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
