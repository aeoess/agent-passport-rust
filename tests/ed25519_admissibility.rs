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
    artifact_vectors: ArtifactVector,
}

/// A real delegation whose canonical bytes satisfy the RFC 8032 equation under
/// a small-order public key, with a full-order canonical R and s < L. It was
/// minted with no private key.
#[derive(serde::Deserialize)]
struct ArtifactVector {
    #[allow(dead_code)]
    note: String,
    public_key_hex: String,
    canonical_preimage: String,
    delegation: serde_json::Value,
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
    for v in d
        .vectors
        .iter()
        .filter(|v| groups.contains(&v.group.as_str()))
    {
        assert!(
            !verify_ed25519(
                v.message_utf8.as_bytes(),
                &v.signature_hex,
                &v.public_key_hex
            ),
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
            !verify_ed25519(
                v.message_utf8.as_bytes(),
                &v.signature_hex,
                &v.public_key_hex
            ),
            "{} accepted a small order R: {}",
            v.id,
            v.note
        );
        n += 1;
    }
    assert!(
        n >= 8,
        "expected the honest key small order R vectors, got {n}"
    );
}

#[test]
fn ordinary_keys_and_signatures_are_unaffected() {
    let d = doc();
    let mut n = 0;
    for v in d.vectors.iter().filter(|v| v.group == "normal") {
        assert!(
            verify_ed25519(
                v.message_utf8.as_bytes(),
                &v.signature_hex,
                &v.public_key_hex
            ),
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

// ---------------------------------------------------------------------------
// The public-key half of admissibility, isolated.
//
// Every vector above that carries a small-order public key also carries
// R = the identity, so a test on R alone refuses it and the test on A is never
// exercised. These vectors close that: a canonical order-8 public key, a full
// order canonical R = [r]B, and a message ground until k = H(R||A||M) mod L is
// divisible by 8, so [k]A is the identity and [s]B = R + [k]A holds with
// s = r < L. Only the test on A refuses them.
// ---------------------------------------------------------------------------

#[test]
fn small_order_public_key_with_full_order_r_is_rejected() {
    let d = doc();
    let mut n = 0;
    for v in d
        .vectors
        .iter()
        .filter(|v| v.group == "small_order_A_full_order_R")
    {
        assert!(
            !verify_ed25519(
                v.message_utf8.as_bytes(),
                &v.signature_hex,
                &v.public_key_hex
            ),
            "{} accepted a small order public key carrying an ordinary R: {}",
            v.id,
            v.note
        );
        n += 1;
    }
    assert_eq!(n, 28, "the isolating vectors must be present");
}

#[test]
fn both_halves_of_the_check_are_independently_forced() {
    let d = doc();
    let a_only = d
        .vectors
        .iter()
        .filter(|v| v.group == "small_order_A_full_order_R")
        .count();
    let r_only = d
        .vectors
        .iter()
        .filter(|v| v.group == "small_order_R_honest_key" && v.id.starts_with("smallR-honest-"))
        .count();
    assert!(a_only > 0, "no vector isolates the public key half");
    assert!(r_only > 0, "no vector isolates the R half");
}

/// Artifact path for the same class. This delegation grants payments:transfer
/// and admin:*, and it was minted with no private key at all.
#[test]
fn delegation_with_small_order_signer_and_ordinary_r_is_refused() {
    use agent_passport::delegation::{
        delegation_signature_preimage, verify_delegation, verify_delegation_signature,
        DelegationError,
    };

    let d = doc();
    let av = &d.artifact_vectors;

    // The canonical bytes this crate computes must be the ones the signature
    // was ground against, otherwise the test would pass for the wrong reason.
    let preimage = delegation_signature_preimage(&av.delegation).unwrap();
    assert_eq!(
        preimage, av.canonical_preimage,
        "canonical bytes differ from the fixture preimage"
    );
    assert_eq!(
        av.delegation["delegatedBy"].as_str().unwrap(),
        av.public_key_hex
    );

    assert!(
        !verify_delegation_signature(&av.delegation),
        "a delegation granting payments:transfer and admin:*, minted with no \
         private key, was accepted under a small order signer"
    );
    let status = verify_delegation(&av.delegation, "2026-06-01T00:00:00Z").unwrap();
    assert!(!status.valid);
    assert!(
        status.errors.contains(&DelegationError::InvalidSignature),
        "the refusal reason must be the signature: {:?}",
        status.errors
    );
}

// ── RETRO-AUDIT C2 / R1 ─────────────────────────────────────────────────────
//
// In this crate "the guard" is a third-party dependency. `verify_ed25519` is a
// thin wrapper over `VerifyingKey::from_bytes` + `verify_strict`; small-order
// rejection, canonicality and s < L are all properties of ed25519-dalek. Go is
// insulated by its own `admissiblePoint`, this crate is not. Combine that with
// the R conjunct having been pinned only at R = the identity encoding, and a
// dalek release that relaxed verify_strict's handling of R would have passed
// this suite unchanged.
//
// The vectors below are the ones a bump has to fail on: an ADMISSIBLE public
// key A = A0 + T (A0 prime order, T of order 8, so A is not small order) with
// an R of order 2, 4 and 8. `verify_strict` must refuse all three. Cargo.toml
// pins the dalek MINOR version so that arriving at a version which does not is
// a deliberate edit rather than a `cargo update`.
//
// LIVENESS IS ASSERTED, NOT ASSUMED. The permissive oracle here is dalek's own
// non-strict `Verifier::verify`, which uses the cofactored equation and
// therefore accepts a small-order R. A negative vector that the permissive
// verifier also rejects pins nothing about verify_strict — 24 of the 32
// existing small_order_R_honest_key vectors are vacuous in exactly that way,
// and counting them instead of measuring them was RETRO-AUDIT C9.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// The permissive oracle: dalek's non-strict verify. Accepts what verify_strict
/// refuses on admissibility grounds, so `permissive && !strict` is exactly
/// "this vector discriminates".
fn permissive_verify(v: &Vector) -> bool {
    let Ok(pk) = hex::decode(&v.public_key_hex) else {
        return false;
    };
    let Ok(sig) = hex::decode(&v.signature_hex) else {
        return false;
    };
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else {
        return false;
    };
    let Ok(sig): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    key.verify(v.message_utf8.as_bytes(), &Signature::from_bytes(&sig))
        .is_ok()
}

#[test]
fn small_order_r_under_an_admissible_torsion_aliased_key_is_refused_and_live() {
    let d = doc();
    let group: Vec<&Vector> = d
        .vectors
        .iter()
        .filter(|v| v.group == "small_order_R_torsion_alias_A")
        .collect();
    assert_eq!(
        group.len(),
        3,
        "small_order_R_torsion_alias_A must carry R of order 2, 4 and 8"
    );

    const IDENTITY_R: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    let mut seen: Vec<&str> = Vec::new();
    let mut live = 0;
    for v in &group {
        let r_half = &v.signature_hex[..64];
        assert_ne!(
            r_half, IDENTITY_R,
            "{}: R is the identity encoding, the one class already pinned",
            v.id
        );
        assert!(!seen.contains(&r_half), "{}: duplicate R half", v.id);
        seen.push(r_half);

        assert!(!v.expected_verification, "{}: must be a negative", v.id);
        assert!(
            !verify_ed25519(
                v.message_utf8.as_bytes(),
                &v.signature_hex,
                &v.public_key_hex
            ),
            "{} accepted a small order R under an admissible key: {}",
            v.id,
            v.note
        );
        assert!(
            permissive_verify(v),
            "{}: VACUOUS. The permissive verifier rejects this vector too, so it pins nothing \
             about verify_strict and would survive a dependency bump that dropped the R check.",
            v.id
        );
        live += 1;
    }
    assert_eq!(live, 3, "all three R classes must be LIVE");
}

#[test]
fn the_torsion_aliased_key_itself_is_admissible() {
    // The positive control. Without it, a verifier that refused EVERY signature
    // under a torsion-aliased key would pass the test above and the three
    // negatives would isolate nothing.
    let d = doc();
    let control: Vec<&Vector> = d
        .vectors
        .iter()
        .filter(|v| v.group == "torsion_alias_A_valid_R")
        .collect();
    assert_eq!(control.len(), 1);
    let v = control[0];
    assert!(v.expected_verification);
    assert!(
        permissive_verify(v),
        "{}: the control does not verify permissively, so it controls nothing",
        v.id
    );
    assert!(
        verify_ed25519(
            v.message_utf8.as_bytes(),
            &v.signature_hex,
            &v.public_key_hex
        ),
        "{}: verify_strict refused the control, so the refusals above are not attributable to R",
        v.id
    );

    for n in d
        .vectors
        .iter()
        .filter(|n| n.group == "small_order_R_torsion_alias_A")
    {
        assert_eq!(
            n.public_key_hex, v.public_key_hex,
            "{} uses a different key from the control; the R half is not isolated",
            n.id
        );
    }
}
