//! A signature over a passport says who signed it, not who vouches for it.
//!
//! The verifying key is the one the passport carries, so a good signature is
//! available to anyone who can generate a key pair. With an empty
//! `trusted_issuers` list this crate reported success and attached
//! `PassportWarning::NoTrustedIssuers`, so a passport minted by anyone at all
//! came back valid and a caller had to know to read a warning to find out why.
//!
//! The contract, identical in all four SDKs: a bare verification is integrity
//! and not authority, so it is not valid; a trusted issuer's countersignature
//! is valid with the issuer-trust flag set; an explicit self-signed opt-in is
//! valid with the self-signed flag set; and the opt-in never rescues a failed
//! issuer check.

mod common;

use agent_passport::passport::{
    verify_passport, PassportError, PassportVerification, PassportVerifyOptions, PassportWarning,
};
use common::{public_key_hex, seed_from, sign_hex};
use serde_json::{json, Value};

const AGENT_SEED: &str = "aps-rg2-agent";
const ISSUER_SEED: &str = "aps-rg2-issuer";
const OTHER_SEED: &str = "aps-rg2-other";
const NOW: &str = "2026-06-03T13:00:00Z";

fn minted(expires_at: &str) -> Value {
    let seed = seed_from(AGENT_SEED);
    let passport = json!({
        "version": "1.0.0",
        "agentId": "ag_attacker_claims_treasury",
        "publicKey": public_key_hex(&seed),
        "capabilities": ["commerce:checkout"],
        "createdAt": "2026-06-03T12:00:00Z",
        "expiresAt": expires_at,
    });
    let canonical = agent_passport::passport::agent_signature_preimage(&passport).unwrap();
    json!({
        "passport": passport,
        "signature": sign_hex(&canonical, &seed),
        "signedAt": "2026-06-03T12:00:00Z",
    })
}

/// The countersignature the other three SDKs already verify: over the legacy
/// canonical of {passport, signature, signedAt}.
fn countersign(envelope: &Value, issuer_seed: &str, named_key: &str) -> Value {
    let payload = agent_passport::passport::issuer_signature_preimage(envelope).unwrap();
    let mut signed = envelope.clone();
    signed["issuerSignature"] = json!({
        "issuerId": "aeoess",
        "issuerPublicKey": named_key,
        "signature": sign_hex(&payload, &seed_from(issuer_seed)),
        "signedAt": envelope.get("signedAt").cloned().unwrap_or(Value::Null),
    });
    signed
}

fn verify(envelope: &Value, trusted: &[String], allow_self_signed: bool) -> PassportVerification {
    verify_passport(
        envelope,
        &PassportVerifyOptions {
            trusted_issuers: trusted,
            evaluation_time: NOW,
            allowed_clock_skew_ms: 0,
            allow_self_signed,
        },
    )
    .expect("fixtures are structurally valid")
}

const LIVE: &str = "2030-01-01T00:00:00Z";

#[test]
fn a_bare_verification_is_integrity_not_authority() {
    let none: Vec<String> = Vec::new();
    let result = verify(&minted(LIVE), &none, false);
    assert!(!result.valid, "{:?}", result.errors);
    assert!(result
        .errors
        .contains(&PassportError::AuthorityNotEstablished));
    assert!(!result.issuer_trust_checked);
    assert!(!result.self_signed_accepted);
}

#[test]
fn the_signature_is_still_checked_and_reported_on_a_bare_call() {
    // Integrity is established and reported even though authority is not: the
    // bare call must not collapse into one undifferentiated refusal.
    let none: Vec<String> = Vec::new();
    let mut tampered = minted(LIVE);
    tampered["passport"]["agentId"] = json!("ag_promoted");
    let result = verify(&tampered, &none, false);
    assert!(result.errors.contains(&PassportError::InvalidSignature));
    assert!(result
        .errors
        .contains(&PassportError::AuthorityNotEstablished));
}

#[test]
fn a_trusted_issuer_countersignature_is_valid() {
    let issuers = vec![public_key_hex(&seed_from(ISSUER_SEED))];
    let signed = countersign(&minted(LIVE), ISSUER_SEED, &issuers[0]);
    let result = verify(&signed, &issuers, false);
    assert!(result.valid, "{:?}", result.errors);
    assert!(result.issuer_trust_checked);
    assert!(!result.self_signed_accepted);
}

#[test]
fn the_self_signed_opt_in_is_explicit() {
    let none: Vec<String> = Vec::new();
    let result = verify(&minted(LIVE), &none, true);
    assert!(result.valid, "{:?}", result.errors);
    assert!(result.self_signed_accepted);
    assert!(!result.issuer_trust_checked);
    assert!(result.warnings.contains(&PassportWarning::NoTrustedIssuers));
}

#[test]
fn the_opt_in_still_requires_a_good_signature() {
    let none: Vec<String> = Vec::new();
    let mut tampered = minted(LIVE);
    tampered["passport"]["agentId"] = json!("ag_promoted");
    assert!(!verify(&tampered, &none, true).valid);
}

#[test]
fn a_trusted_list_with_no_countersignature_is_refused() {
    let issuers = vec![public_key_hex(&seed_from(ISSUER_SEED))];
    let result = verify(&minted(LIVE), &issuers, false);
    assert!(!result.valid);
    assert!(result.issuer_trust_checked);
}

#[test]
fn a_countersignature_by_a_key_not_in_the_list_is_refused() {
    let issuers = vec![public_key_hex(&seed_from(ISSUER_SEED))];
    let other = public_key_hex(&seed_from(OTHER_SEED));
    let signed = countersign(&minted(LIVE), OTHER_SEED, &other);
    assert!(!verify(&signed, &issuers, false).valid);
}

#[test]
fn a_countersignature_naming_a_trusted_key_but_made_by_another_is_refused() {
    let issuers = vec![public_key_hex(&seed_from(ISSUER_SEED))];
    // Names the trusted issuer, signed by somebody else.
    let signed = countersign(&minted(LIVE), OTHER_SEED, &issuers[0]);
    let result = verify(&signed, &issuers, false);
    assert!(!result.valid);
    assert!(result
        .errors
        .contains(&PassportError::InvalidIssuerCountersignature));
}

#[test]
fn a_countersigned_passport_re_signed_by_another_key_is_refused() {
    let issuers = vec![public_key_hex(&seed_from(ISSUER_SEED))];
    let signed = countersign(&minted(LIVE), ISSUER_SEED, &issuers[0]);
    let mut tampered = signed.clone();
    tampered["passport"]["agentId"] = json!("ag_promoted");
    assert!(!verify(&tampered, &issuers, false).valid);
}

#[test]
fn an_expired_passport_under_a_trusted_issuer_is_still_refused() {
    let issuers = vec![public_key_hex(&seed_from(ISSUER_SEED))];
    let signed = countersign(&minted("2020-01-01T00:00:00Z"), ISSUER_SEED, &issuers[0]);
    let result = verify(&signed, &issuers, false);
    assert!(!result.valid);
    assert!(result.errors.contains(&PassportError::Expired));
}

#[test]
fn the_opt_in_does_not_rescue_a_failed_issuer_check() {
    // A caller that named issuers asked for that check. The flag is not a way
    // to ignore the answer.
    let issuers = vec![public_key_hex(&seed_from(ISSUER_SEED))];
    let other = public_key_hex(&seed_from(OTHER_SEED));
    let signed = countersign(&minted(LIVE), OTHER_SEED, &other);
    let result = verify(&signed, &issuers, true);
    assert!(!result.valid);
    assert!(!result.self_signed_accepted);
}

#[test]
fn an_empty_list_with_the_opt_in_is_the_only_way_to_pass_unvouched() {
    // Re-attack, not in the brief: the two inputs are independent, so pin the
    // whole truth table rather than the two rows the brief names.
    let none: Vec<String> = Vec::new();
    let issuers = vec![public_key_hex(&seed_from(ISSUER_SEED))];
    let bare = minted(LIVE);
    assert!(!verify(&bare, &none, false).valid, "no list, no opt-in");
    assert!(verify(&bare, &none, true).valid, "no list, opt-in");
    assert!(
        !verify(&bare, &issuers, false).valid,
        "list, no opt-in, no countersignature"
    );
    assert!(
        !verify(&bare, &issuers, true).valid,
        "list, opt-in, no countersignature"
    );
}
