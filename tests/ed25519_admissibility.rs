//! Ed25519 admissibility. A public key or an R that decodes to a small order
//! point, a non canonically encoded public key or R, and a scalar s that is not
//! reduced modulo the group order are all inadmissible, so the artifact that
//! carries them is refused before it is believed.
//!
//! `tests/vectors/ed25519-admissibility-v1.json` records the behaviour on which
//! the two strict reference implementations agree: libsodium through PyNaCl and
//! ed25519-dalek `verify_strict`. The same file is used by the TypeScript, Go
//! and Python suites, so the four implementations answer every vector the same
//! way by construction.

use agent_passport::crypto::verify_ed25519;

#[derive(serde::Deserialize)]
struct Doc {
    version: String,
    count: usize,
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    id: String,
    group: String,
    note: String,
    message_utf8: String,
    public_key_hex: String,
    signature_hex: String,
    expected_verification: bool,
}

fn doc() -> Doc {
    serde_json::from_str(include_str!("vectors/ed25519-admissibility-v1.json")).unwrap()
}

#[test]
fn admissibility_vectors_match_the_strict_reference() {
    let d = doc();
    assert_eq!(d.version, "ed25519-admissibility-v1");
    assert_eq!(d.vectors.len(), d.count);
    let mut wrong = Vec::new();
    for v in &d.vectors {
        let got = verify_ed25519(
            v.message_utf8.as_bytes(),
            &v.signature_hex,
            &v.public_key_hex,
        );
        if got != v.expected_verification {
            wrong.push(format!(
                "{} [{}] expected {} got {} :: {}",
                v.id, v.group, v.expected_verification, got, v.note
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} vectors disagree with the strict reference:\n{}",
        wrong.len(),
        d.vectors.len(),
        wrong
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn small_order_public_key_is_rejected() {
    // The Edwards identity point as a public key with R = the identity and
    // s = 0. The RFC 8032 equation degenerates to identity = identity, so a
    // verifier that does not test admissibility accepts this signature for
    // every message.
    let public = format!("01{}", "00".repeat(31));
    let signature = format!("01{}{}", "00".repeat(31), "00".repeat(32));
    assert!(!verify_ed25519(
        b"APS admissibility probe",
        &signature,
        &public
    ));
    assert!(!verify_ed25519(
        b"a completely different message",
        &signature,
        &public
    ));
}

#[test]
fn every_small_order_encoding_is_rejected() {
    let d = doc();
    let groups = ["small_order_pk", "small_order_pk_message_independence"];
    let mut n = 0;
    for v in d.vectors.iter().filter(|v| groups.contains(&v.group.as_str())) {
        assert!(
            !verify_ed25519(v.message_utf8.as_bytes(), &v.signature_hex, &v.public_key_hex),
            "{} accepted a small order public key: {}",
            v.id,
            v.note
        );
        n += 1;
    }
    assert_eq!(n, 28, "all eight small order points in every encoding");
}

#[test]
fn small_order_r_under_an_honest_key_is_rejected() {
    // R is the identity and s = k*a mod L, so the cofactorless equation holds
    // exactly under a genuine prime order public key. Only an admissibility
    // test on R refuses it.
    let d = doc();
    let mut n = 0;
    for v in d
        .vectors
        .iter()
        .filter(|v| v.group == "small_order_R_honest_key" && v.id.starts_with("smallR-honest-"))
    {
        assert!(
            !verify_ed25519(v.message_utf8.as_bytes(), &v.signature_hex, &v.public_key_hex),
            "{} accepted a small order R: {}",
            v.id,
            v.note
        );
        n += 1;
    }
    assert!(n >= 8, "expected the honest key small order R vectors, got {n}");
}

#[test]
fn ordinary_keys_and_signatures_are_unaffected() {
    let d = doc();
    let mut n = 0;
    for v in d.vectors.iter().filter(|v| v.group == "normal") {
        assert!(
            verify_ed25519(v.message_utf8.as_bytes(), &v.signature_hex, &v.public_key_hex),
            "{} is an ordinary valid signature and must still verify",
            v.id
        );
        n += 1;
    }
    assert_eq!(n, 128);
}

// ---------------------------------------------------------------------------
// High level paths. The primitive is not the surface an attacker meets; the
// artifact verifiers are. Each of these hands a verifier the degenerate
// identity-key signature, which satisfies the RFC 8032 equation for every
// message, so a permissive primitive would accept the artifact whatever its
// contents. Inadmissible key material must stop the artifact.
// ---------------------------------------------------------------------------

/// The Edwards identity point as a public key.
const IDENTITY_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
/// R = the identity encoding, s = 0.
const DEGENERATE_SIG: &str = concat!(
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000"
);

#[test]
fn delegation_with_a_small_order_signer_is_refused() {
    use agent_passport::delegation::{
        verify_delegation, verify_delegation_signature, DelegationError,
    };
    use serde_json::json;

    let delegation = json!({
        "delegationId": "del_smallorder",
        "delegatedBy": IDENTITY_KEY,
        "delegatedTo": "agent-b",
        "scope": ["*"],
        "expiresAt": "2099-01-01T00:00:00Z",
        "signature": DEGENERATE_SIG,
    });
    assert!(
        !verify_delegation_signature(&delegation),
        "a delegation signed with an inadmissible key must not verify"
    );
    let status = verify_delegation(&delegation, "2026-06-01T00:00:00Z").unwrap();
    assert!(
        !status.valid,
        "and the full delegation check must refuse it too"
    );
    assert!(
        status.errors.contains(&DelegationError::InvalidSignature),
        "the refusal reason must be the signature, not an unrelated field: {:?}",
        status.errors
    );
}

#[test]
fn passport_issuer_countersignature_with_a_small_order_key_is_refused() {
    use agent_passport::passport::verify_issuer_signature;
    use serde_json::json;

    let signed = json!({
        "passport": {"agentId": "agent-a", "version": "1.0"},
        "signature": "00",
        "issuerSignature": {
            "issuerPublicKey": IDENTITY_KEY,
            "signature": DEGENERATE_SIG,
            "issuedAt": "2026-01-01T00:00:00Z",
        },
    });
    assert!(
        !verify_issuer_signature(&signed, IDENTITY_KEY),
        "an issuer countersignature under an inadmissible key must not verify"
    );
}

#[test]
fn receipt_signature_under_a_small_order_key_is_refused() {
    use agent_passport::crypto::verify_ed25519;

    // receipt_core resolves the signer key through the caller and then calls
    // the same primitive over the descriptor bound preimage. Whatever preimage
    // the receipt produces, the degenerate signature satisfies the equation, so
    // only admissibility stops it.
    for preimage in [
        r#"{"receipt_id":"r1"}"#,
        r#"{"receipt_id":"r2","kind":"attribution"}"#,
        "",
    ] {
        assert!(
            !verify_ed25519(preimage.as_bytes(), DEGENERATE_SIG, IDENTITY_KEY),
            "receipt preimage {preimage:?} must not accept the degenerate signature"
        );
    }
}

#[test]
fn the_degenerate_signature_is_message_independent_and_still_refused() {
    use agent_passport::crypto::verify_ed25519;
    // 256 unrelated messages, one signature. Under a permissive primitive every
    // one of them verifies. None may.
    for i in 0..256u32 {
        let message = format!("unrelated APS artifact body {i}");
        assert!(
            !verify_ed25519(message.as_bytes(), DEGENERATE_SIG, IDENTITY_KEY),
            "message {i} accepted the message independent signature"
        );
    }
}
