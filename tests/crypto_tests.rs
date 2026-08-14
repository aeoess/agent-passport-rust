//! Ed25519 verification parity: the reference TypeScript signatures recorded
//! in the bilateral fixture must verify, and every malformed-input and
//! boundary case must reject exactly as Node and Go reject it.

use agent_passport::crypto::verify_ed25519;
use agent_passport::jcs;
use serde_json::Value;

#[derive(serde::Deserialize)]
struct BilateralDoc {
    keypair: Keypair,
    vectors: Vec<BilateralVector>,
}

#[derive(serde::Deserialize)]
struct Keypair {
    #[serde(rename = "publicKeyHex")]
    public_key_hex: String,
}

#[derive(serde::Deserialize)]
struct BilateralVector {
    name: String,
    input: Value,
    ed25519_signature_over_canonical_hex: String,
    ed25519_pubkey_hex: String,
    expected_verification: bool,
}

fn fixture() -> BilateralDoc {
    serde_json::from_str(include_str!("vectors/canonicalize-fixture-v1.json")).unwrap()
}

#[test]
fn reference_signatures_verify_over_canonical_bytes() {
    let doc = fixture();
    assert_eq!(doc.vectors.len(), 10);
    for v in &doc.vectors {
        assert_eq!(
            v.ed25519_pubkey_hex, doc.keypair.public_key_hex,
            "{}",
            v.name
        );
        let canonical = jcs::canonicalize(&v.input).unwrap();
        let verified = verify_ed25519(
            canonical.as_bytes(),
            &v.ed25519_signature_over_canonical_hex,
            &v.ed25519_pubkey_hex,
        );
        assert_eq!(verified, v.expected_verification, "{}", v.name);
        assert!(verified, "{}: fixture signatures are all valid", v.name);
    }
}

fn sample() -> (Vec<u8>, String, String) {
    let doc = fixture();
    let v = &doc.vectors[0];
    let canonical = jcs::canonicalize(&v.input).unwrap();
    (
        canonical.into_bytes(),
        v.ed25519_signature_over_canonical_hex.clone(),
        v.ed25519_pubkey_hex.clone(),
    )
}

#[test]
fn uppercase_hex_is_accepted() {
    // Node's regex admits A-F and Go's hex.DecodeString admits uppercase; the
    // Rust port must too.
    let (message, signature, public_key) = sample();
    assert!(verify_ed25519(
        &message,
        &signature.to_uppercase(),
        &public_key.to_uppercase()
    ));
}

#[test]
fn tampered_message_rejects() {
    let (mut message, signature, public_key) = sample();
    message[0] ^= 0x01;
    assert!(!verify_ed25519(&message, &signature, &public_key));
}

#[test]
fn tampered_signature_rejects() {
    let (message, signature, public_key) = sample();
    let mut bytes = hex::decode(&signature).unwrap();
    bytes[10] ^= 0x01;
    assert!(!verify_ed25519(&message, &hex::encode(bytes), &public_key));
}

#[test]
fn wrong_key_rejects() {
    let (message, signature, _) = sample();
    let other_key = "16bd0f3e8181e93d58c23268ee0d5f4d5b70b3ce66fc246c0f5d7ec3dda9ab81";
    assert!(!verify_ed25519(&message, &signature, other_key));
}

#[test]
fn wrong_lengths_reject_before_parsing() {
    let (message, signature, public_key) = sample();
    // Key equivocation: a longer key whose leading 32 bytes are valid.
    let long_key = format!("{public_key}00");
    assert!(!verify_ed25519(&message, &signature, &long_key));
    let short_key = &public_key[..62];
    assert!(!verify_ed25519(&message, &signature, short_key));
    let long_sig = format!("{signature}00");
    assert!(!verify_ed25519(&message, &long_sig, &public_key));
    let short_sig = &signature[..126];
    assert!(!verify_ed25519(&message, short_sig, &public_key));
    assert!(!verify_ed25519(&message, "", &public_key));
    assert!(!verify_ed25519(&message, &signature, ""));
}

#[test]
fn malformed_hex_rejects() {
    let (message, signature, public_key) = sample();
    let bad_key = format!("zz{}", &public_key[2..]);
    assert!(!verify_ed25519(&message, &signature, &bad_key));
    let bad_sig = format!("zz{}", &signature[2..]);
    assert!(!verify_ed25519(&message, &bad_sig, &public_key));
}

#[test]
fn non_canonical_scalar_rejects() {
    // Add the Ed25519 group order L to S. RFC 8032 requires rejecting a
    // non-canonical scalar; Node (OpenSSL), Go (crypto/ed25519), and
    // ed25519-dalek verify all reject it, which is the pinned parity.
    const GROUP_ORDER_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let (message, signature, public_key) = sample();
    assert!(verify_ed25519(&message, &signature, &public_key));
    let mut bytes = hex::decode(&signature).unwrap();
    let mut carry = 0u16;
    for (i, order_byte) in GROUP_ORDER_LE.iter().enumerate() {
        let sum = u16::from(bytes[32 + i]) + u16::from(*order_byte) + carry;
        bytes[32 + i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 32 bytes");
    assert!(
        !verify_ed25519(&message, &hex::encode(bytes), &public_key),
        "signature with S + L must be rejected"
    );
}

#[test]
fn invalid_point_encoding_rejects() {
    let (message, signature, _) = sample();
    // 32 bytes that do not decode to a curve point.
    let not_a_point = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    assert!(!verify_ed25519(&message, &signature, not_a_point));
}

#[test]
fn small_order_boundary_pins_verify_over_verify_strict() {
    // Wave 1.1 item 5. Deterministic small order vector: the public key is
    // the canonical encoding of the Edwards identity point (order 1), the
    // signature is R = the same encoding with S = 0, so the RFC 8032
    // equation [S]B = R + [k]A degenerates to identity = identity for
    // every message. Observed through the complete pinned reference paths
    // (probes/phase0/MATRIX.md): the TypeScript SDK verify() and full
    // verifyDelegation (Node v24.11.1) ACCEPT, the Go VerifyEd25519 and
    // full VerifyCanonicalSignature (go1.26.3) ACCEPT. This test pins the
    // Rust halves of that four-way matrix: the crate's plain-verify path
    // agrees with both references, and dalek's verify_strict alone
    // differs, which is exactly the wave 1 ground for choosing verify.
    use ed25519_dalek::{Signature, VerifyingKey};

    let small_order_public = format!("01{}", "00".repeat(31));
    let small_order_signature = format!("01{}{}", "00".repeat(31), "00".repeat(32));
    let message = b"APS wave1.1 small order probe";

    assert!(
        verify_ed25519(message, &small_order_signature, &small_order_public),
        "plain verify accepts the small order vector, as Node and Go do"
    );
    assert!(
        verify_ed25519(
            b"a completely different message",
            &small_order_signature,
            &small_order_public
        ),
        "the degenerate vector is message independent"
    );

    let key_bytes: [u8; 32] = hex::decode(&small_order_public)
        .unwrap()
        .try_into()
        .unwrap();
    let signature_bytes: [u8; 64] = hex::decode(&small_order_signature)
        .unwrap()
        .try_into()
        .unwrap();
    let key = VerifyingKey::from_bytes(&key_bytes).unwrap();
    let signature = Signature::from_bytes(&signature_bytes);
    assert!(
        key.verify_strict(message, &signature).is_err(),
        "verify_strict rejects the same vector: the one path that differs"
    );
}
