// LocalCloud Key Management - Signing Module
//
// Ed25519 signing and verification operations.
// The signing key never leaves Rust memory and is protected by
// Zeroizing<> and mlock from the identity module.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

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
///
/// Uses `verify_strict` (CRY-H1). This crate builds ed25519-dalek without
/// the `legacy_compatibility` feature, so non-strict verification already
/// rejects non-canonical / unreduced S (S >= L). `verify_strict`
/// additionally rejects signatures whose public key A or commitment R is a
/// small-order point — inputs that satisfy the cofactorless verification
/// equation but were never produced by an honest signer. Legitimate
/// signatures are unaffected: dalek never emits small-order R, and honest
/// keys are never small-order.
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

    Ok(verifying_key.verify_strict(message, &signature).is_ok())
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

    /// CRY-H1 regression: reject signatures over low-order public keys.
    ///
    /// ed25519-dalek 2.2.0 is built WITHOUT `legacy_compatibility`, so
    /// non-strict `verify()` already rejects non-canonical / unreduced S
    /// (S >= L). The remaining gap is that non-strict `verify()` accepts
    /// signatures whose public key A (or commitment R) is a small-order
    /// point — the cofactorless verification equation `[s]B - [k]A == R`
    /// holds for such crafted inputs even though no honest signer produced
    /// them. `verify_strict()` closes this by rejecting small-order A/R.
    ///
    /// This is the published "`low_order_A`" CCTV vector ("Taming the many
    /// `EdDSAs`"), validated against `ed25519-dalek` 2.2.0 directly:
    ///   A   = identity point         (small order, `is_weak()` == true)
    ///   R   = compressed basepoint B (= [1]B)
    ///   s   = 1
    ///   msg = b""
    /// Because A is the identity, the `[k]A` term vanishes and the
    /// equation reduces to `[s]B == R`, which the bytes satisfy exactly.
    /// Current `verify()` ACCEPTS this; `verify_strict()` REJECTS it.
    #[test]
    fn test_low_order_public_key_rejected() {
        // A = Ed25519 identity point: y = 1, x = 0 (little-endian).
        let pub_key: [u8; 32] = {
            let mut a = [0u8; 32];
            a[0] = 1;
            a
        };

        // signature = R (32 bytes) || s (32 bytes)
        //   R = compressed basepoint, s = 1
        let mut signature = [0u8; 64];
        let r = hex_to_32("5866666666666666666666666666666666666666666666666666666666666666");
        signature[..32].copy_from_slice(&r);
        signature[32] = 1; // s = 1 (little-endian, canonical, < L)

        let accepted = verify(&pub_key, b"", &signature).unwrap();
        assert!(
            !accepted,
            "small-order public key signature must be rejected (verify_strict)"
        );
    }

    /// A legitimately produced signature must still verify under the
    /// strict path — dalek never emits small-order R, and honest keys are
    /// never small-order, so `verify_strict()` is a no-op for valid sigs.
    #[test]
    fn test_strict_change_preserves_valid_signatures() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let message = b"legitimate signature must still verify";

        let signature = sign(&priv_key, message).unwrap();
        assert!(verify(&pub_key, message, &signature).unwrap());
    }

    /// Decode a fixed-length 64-char hex string into a [u8; 32]. Test-only
    /// helper to keep the crafted vector readable; panics on bad input,
    /// which is acceptable inside #[cfg(test)].
    fn hex_to_32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars");
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .expect("invalid hex digit in test vector");
        }
        out
    }
}
