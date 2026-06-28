//! On-disk / wire-format pinning vectors (architect #4 — irreversible invariant).
//!
//! These vectors were produced by the CURRENT code and are now frozen. They
//! prove the keycore crate split did not perturb either byte format:
//!
//!  * `decrypt_from_store` must still recover the exact keypair from a keystore
//!    blob captured before the split — so existing on-disk keystores keep
//!    decrypting.
//!  * `unwrap_file_keys` must still recover the exact `(file_key, meta_key)`
//!    from a wrap bundle captured before the split — so desktop-wrapped
//!    bundles stay interoperable with the Android client (and vice-versa).
//!
//! If either format ever changes (struct field order, CBOR encoding, AAD/HKDF
//! info layout, version byte, …) these tests fail loudly. They are golden
//! vectors: do NOT regenerate them to make a failing test pass — a failure
//! here means the format moved, which is a compatibility break.

use crate::IdentityKeyPair;

// ─────────────── Keystore blob (encrypt_to_store) golden vector ───────────────

/// Password used when the pinned keystore blob below was sealed.
const KEYSTORE_PASSWORD: &[u8] = b"format-pin-password-keystore-v2";

/// CBOR `EncryptedKeyStore` blob for a (random) keypair, captured pre-split.
const KEYSTORE_BLOB_HEX: &str = "a76776657273696f6e026473616c74982018ff18ab182b184504189d188a187b18dc188018c4182b18aa18e21875186518ae185e18ba18821833184912184818c4189c18e6182705187718f418af666d5f636f73741a0008000066745f636f73740366705f636f737401656e6f6e6365981818bb18321829187d0a18ac184318e3189a189318ef1218f218f81819187d187c1818183e18e418c2187318a018bd6a636970686572746578749901461890189818c01874182918f918c4189a18c118b918371825183f1820181d18da1882188a18621878187618c713188d183418ec18e8186918b2183d189818791876187e18eb18a41831182f18da189118d818c31848181e18a2182b189e18e0186e18ae18d81894188318d618a118ed1879189e18c3189518ec1849185b18f518e41829185c0218ba187018aa18c918851857189a1718b3186818f218f018841824183818f31832184a184718fd181c1618f618d7183518a31860182d18d218d018a918c4186c11188418d5182f18da18d51880185318a218ca18e918b11618f118b218f5186718d918d9182518be187e18b61833189d187e184109182818ed181c1888151880181818b01864184c185618f6187618f01861188f186b189a186918dc0d18e6186b187f18371875188418f518db18ec18ea11188918f218e1185118af18d718fc18b8186718791877182218e018ce1861182318e118671842181e188418fc183c185f189918d7188f18a518f4183d182b185805187b18661834183218920d184f185818691857184f1518721418d60f18c418b00e0518d0186718b518561837181c187518b31888183918ea18841832182c0a183602186c18e6186818371862188518af182118de1844181a1835182a18ee182218d7182918730018ee10185b18641820187b18f4181b18ca186718c618ea189218fa188118fa187f184618fd18f7186b1829184618601843186f18b81849187718a018ec18a418ea187d18f018ac184b1118a6182218aa1818184e18511882182d1877184018e418f018ce1873187018e6186b18a918cf1895183618dd186a18a61829187a18c5189a187018f2184a18ac188b18a918b818c118a71873";

/// Public/private keys the pinned keystore blob must decrypt to.
const KEYSTORE_X25519_PUB_HEX: &str =
    "e56468e03e010d0625bc366de470c969ad531e35ac01e71f7a548116cb95425f";
const KEYSTORE_ED25519_PUB_HEX: &str =
    "063decd2d6bbb0bc5aafa188a7cfa15a31a8adc053098e33f082e11126d7a201";
const KEYSTORE_X25519_PRIV_HEX: &str =
    "260c74c811cb6e77c47c7acdb099ebaacdb8f2602760109d8513fce31c7ca815";
const KEYSTORE_ED25519_PRIV_HEX: &str =
    "f024b4a9fda5478871f6949ba2476c3768fa7b9d4367fe338b8a0376357ef3dd";

// ─────────────── Wrap bundle (wrap_file_keys) golden vector ───────────────

/// `ephemeral_pub || nonce || ct+tag` bundle captured pre-split.
const WRAP_BUNDLE_HEX: &str = "d0943f3dddd63e8b8341c15b5c7267a4daf3c0f19cb73f8c19477aeda4f1536539f2c4231c07944b7a6eacfd85a934b9f4026474ad2c4a5079694e83e1cf81c458a388d5e2c0d3377b6dcaa4ce40fe4be1d32cf00b94f0293f33c61418bef249e8a1ca7169cc8f8eccb426e6cc95412ddec2359a4a97a9fcfe21ca10a79ca8536c62d51745fc6b7e";

/// Recipient long-term X25519 private key for the pinned bundle.
const WRAP_RECIPIENT_PRIV_HEX: &str =
    "720e553e881a1d04850c4ad16a32caccb211c4c123e8effd693dc03cf8217157";

/// Fixed inputs used when the bundle was produced.
const WRAP_FILE_ID: &[u8] = b"pinned-file-id16"; // exactly 16 bytes
const WRAP_SENDER_ID_PUB: [u8; 32] = [0x5A; 32];
const WRAP_EXPECTED_FILE_KEY: [u8; 32] = [0xA1; 32];
const WRAP_EXPECTED_META_KEY: [u8; 32] = [0xB2; 32];

// ─────────────────────────── helpers ───────────────────────────

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex string must have even length"
    );
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("invalid hex digit"))
        .collect()
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let v = hex_decode(s);
    let mut out = [0u8; 32];
    assert_eq!(v.len(), 32, "expected 32 bytes");
    out.copy_from_slice(&v);
    out
}

// ─────────────────────────── tests ───────────────────────────

/// The pinned keystore blob must decrypt, under its captured password, to the
/// exact public AND private keys captured pre-split. This pins the full
/// `EncryptedKeyStore` + `KeyBundle` on-disk format and the Argon2id/AEAD
/// parameters baked into the blob.
#[test]
fn pinned_keystore_blob_decrypts_to_expected_keys() {
    let blob = hex_decode(KEYSTORE_BLOB_HEX);
    let kp = IdentityKeyPair::decrypt_from_store(&blob, KEYSTORE_PASSWORD)
        .expect("pinned keystore blob must still decrypt — on-disk format changed?");

    assert_eq!(
        kp.x25519_public_key(),
        &hex_to_32(KEYSTORE_X25519_PUB_HEX),
        "X25519 public key drifted from pinned keystore format"
    );
    assert_eq!(
        kp.ed25519_public_key(),
        &hex_to_32(KEYSTORE_ED25519_PUB_HEX),
        "Ed25519 public key drifted from pinned keystore format"
    );
    // pub(crate) accessors are reachable from in-crate tests; pinning the
    // private keys proves the secret bytes round-trip through the format too.
    assert_eq!(
        kp.x25519_private_key(),
        &hex_to_32(KEYSTORE_X25519_PRIV_HEX),
        "X25519 private key drifted from pinned keystore format"
    );
    assert_eq!(
        kp.ed25519_private_key(),
        &hex_to_32(KEYSTORE_ED25519_PRIV_HEX),
        "Ed25519 private key drifted from pinned keystore format"
    );
}

/// The pinned wrap bundle must unwrap, with the captured recipient private key
/// and the fixed sender-id / file-id, to the exact file_key + meta_key. This
/// pins the wrap wire format (ephemeral_pub || nonce || ct+tag), the HKDF info
/// layout, and the AEAD AAD construction.
#[test]
fn pinned_wrap_bundle_unwraps_to_expected_keys() {
    let bundle = hex_decode(WRAP_BUNDLE_HEX);
    let recipient_priv = hex_to_32(WRAP_RECIPIENT_PRIV_HEX);

    let (file_key, meta_key) = crate::wrapping::unwrap_file_keys(
        &bundle,
        WRAP_FILE_ID,
        &WRAP_SENDER_ID_PUB,
        &recipient_priv,
    )
    .expect("pinned wrap bundle must still unwrap — wire format changed?");

    assert_eq!(
        *file_key, WRAP_EXPECTED_FILE_KEY,
        "file_key drifted from pinned wrap format"
    );
    assert_eq!(
        *meta_key, WRAP_EXPECTED_META_KEY,
        "meta_key drifted from pinned wrap format"
    );
}
