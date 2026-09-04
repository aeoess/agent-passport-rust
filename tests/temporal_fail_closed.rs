//! A timestamp a verifier cannot read is not a timestamp it can honour.
//!
//! `verify_passport` used to wrap each temporal comparison in
//! `if let Some(ms) = ...and_then(parse_ms)`, so an `expiresAt` that was
//! absent, not a string, or not an RFC 3339 instant skipped the comparison
//! entirely and produced nothing. An honest expired passport was invalid and a
//! passport whose expiry was the word "never" was valid, which made writing
//! garbage into the field strictly better for the holder than writing a date.
//!
//! The repair reuses the shape `verify_delegation` already had at
//! `delegation.rs`: match on the parse, with an explicit arm for the failure.
//! The failure has its own variant rather than reusing `Expired`, because "the
//! limit had passed" and "there was no readable limit" are different findings.
//! An operator acts on the first by reissuing and on the second by fixing a
//! producer.
//!
//! Absence is deliberately NOT an error and is pinned below, so the line
//! between "no stated limit" and "a limit I could not read" stays a decision
//! rather than an accident.

mod common;

use agent_passport::passport::{
    verify_passport, PassportError, PassportVerifyOptions, PassportWarning,
};
use common::{public_key_hex, seed_from, sign_hex};
use serde_json::{json, Value};

const SEED: &str = "aps-temporal-fail-closed";
const NOW: &str = "2026-06-03T13:00:00Z";

/// Present, and not readable as an RFC 3339 instant by this crate's parser.
/// Each is a value a producer can put on the wire today.
fn unreadable_cases() -> Vec<(&'static str, Value)> {
    vec![
        ("not a date at all", json!("not-a-date")),
        ("empty string", json!("")),
        ("no zone designator", json!("2020-01-01T00:00:00")),
        ("date only", json!("2020-01-01")),
        ("impossible day of month", json!("2020-02-30T00:00:00Z")),
        ("hour 24", json!("2020-01-01T24:00:00Z")),
        ("whitespace padded", json!("  2020-01-01T00:00:00Z  ")),
        ("not a string: number", json!(1_767_225_600_000_i64)),
        ("not a string: bool", json!(true)),
        ("not a string: array", json!(["2020-01-01T00:00:00Z"])),
        (
            "not a string: object",
            json!({"at": "2020-01-01T00:00:00Z"}),
        ),
        ("not a string: null", json!(null)),
    ]
}

fn signed(members: Vec<(&str, Value)>) -> Value {
    let seed = seed_from(SEED);
    let mut passport = json!({
        "version": "1.0.0",
        "agentId": "ag_temporal",
        "publicKey": public_key_hex(&seed),
        "capabilities": ["code_execution"],
        "createdAt": "2026-06-03T12:00:00Z",
    });
    for (key, value) in members {
        passport[key] = value;
    }
    let canonical = agent_passport::passport::agent_signature_preimage(&passport).unwrap();
    json!({
        "passport": passport,
        "signature": sign_hex(&canonical, &seed),
        "signedAt": "2026-06-03T12:00:00Z",
    })
}

fn verify(signed: &Value) -> agent_passport::passport::PassportVerification {
    let none: Vec<String> = Vec::new();
    verify_passport(
        signed,
        &PassportVerifyOptions {
            trusted_issuers: &none,
            evaluation_time: NOW,
            allowed_clock_skew_ms: 0,
        },
    )
    .expect("probe envelopes are structurally valid")
}

// ── expiresAt ──────────────────────────────────────────────────────────────

#[test]
fn an_honest_expired_passport_is_expired() {
    // The baseline every unreadable case below is measured against.
    let result = verify(&signed(vec![("expiresAt", json!("2020-01-01T00:00:00Z"))]));
    assert!(!result.valid);
    assert!(result.errors.contains(&PassportError::Expired));
}

#[test]
fn an_unreadable_expiry_is_invalid_not_ignored() {
    for (label, value) in unreadable_cases() {
        let result = verify(&signed(vec![("expiresAt", value.clone())]));
        assert!(
            !result.valid,
            "expiresAt {label} ({value}) left the passport valid"
        );
        assert!(
            result.errors.contains(&PassportError::InvalidExpiry),
            "expiresAt {label} ({value}) produced {:?}, not InvalidExpiry",
            result.errors
        );
        // And it is not reported as an expiry that was read and had passed.
        assert!(
            !result.errors.contains(&PassportError::Expired),
            "expiresAt {label} was reported as Expired, which claims a limit was read"
        );
    }
}

#[test]
fn an_absent_expiry_is_invalid_because_the_profile_requires_one() {
    // `expiresAt: string` in the reference type, with no `?`. A passport that
    // omits it has not stated a limit at all, so reporting nothing would make
    // deleting the field the cheapest way to mint an eternal passport. Contrast
    // `notBefore`, which the profile marks optional and which is still skipped
    // when absent.
    let result = verify(&signed(vec![]));
    assert!(!result.valid);
    assert!(result.errors.contains(&PassportError::InvalidExpiry));
    assert!(!result.errors.contains(&PassportError::Expired));
}

#[test]
fn a_readable_future_expiry_still_verifies() {
    let result = verify(&signed(vec![("expiresAt", json!("2030-01-01T00:00:00Z"))]));
    assert!(result.valid, "{:?}", result.errors);
}

#[test]
fn an_explicit_offset_is_readable_and_still_compared() {
    // The repair narrows nothing that already parsed. This instant is in the
    // past once converted to UTC, so it must still be Expired, not Invalid.
    let result = verify(&signed(vec![(
        "expiresAt",
        json!("2020-01-01T05:30:00+05:30"),
    )]));
    assert!(result.errors.contains(&PassportError::Expired));
    assert!(!result.errors.contains(&PassportError::InvalidExpiry));
}

// ── notBefore ──────────────────────────────────────────────────────────────

#[test]
fn an_honest_future_not_before_is_not_yet_valid() {
    let result = verify(&signed(vec![
        ("expiresAt", json!("2030-01-01T00:00:00Z")),
        ("notBefore", json!("2029-01-01T00:00:00Z")),
    ]));
    assert!(!result.valid);
    assert!(result.errors.contains(&PassportError::NotYetValid));
}

#[test]
fn an_unreadable_not_before_is_invalid_not_ignored() {
    for (label, value) in unreadable_cases() {
        let result = verify(&signed(vec![
            ("expiresAt", json!("2030-01-01T00:00:00Z")),
            ("notBefore", value.clone()),
        ]));
        assert!(
            !result.valid,
            "notBefore {label} ({value}) left the passport valid"
        );
        assert!(
            result.errors.contains(&PassportError::InvalidNotBefore),
            "notBefore {label} ({value}) produced {:?}, not InvalidNotBefore",
            result.errors
        );
        assert!(
            !result.errors.contains(&PassportError::NotYetValid),
            "notBefore {label} was reported as NotYetValid, which claims a start date was read"
        );
    }
}

#[test]
fn an_absent_not_before_leaves_the_lower_edge_open() {
    let result = verify(&signed(vec![("expiresAt", json!("2030-01-01T00:00:00Z"))]));
    assert!(result.valid, "{:?}", result.errors);
    assert!(!result.errors.contains(&PassportError::InvalidNotBefore));
}

// ── embedded delegation, advisory only ─────────────────────────────────────

fn with_delegation(expires_at: Option<Value>) -> Value {
    let mut delegation = json!({ "delegationId": "del_1", "scope": ["code_execution"] });
    if let Some(value) = expires_at {
        delegation["expiresAt"] = value;
    }
    signed(vec![
        ("expiresAt", json!("2030-01-01T00:00:00Z")),
        ("delegations", json!([delegation])),
    ])
}

#[test]
fn an_honest_expired_delegation_warns_that_it_expired() {
    let result = verify(&with_delegation(Some(json!("2020-01-01T00:00:00Z"))));
    assert!(result
        .warnings
        .contains(&PassportWarning::DelegationExpired));
}

#[test]
fn an_unreadable_delegation_expiry_warns_under_its_own_name() {
    // Warnings never reach `valid` (pinned by passport_tests.rs), so this leg
    // loses a signal rather than opening a gate. It is still wrong to report
    // nothing: the result is the only thing a caller sees, and silence there
    // reads as "the delegation is fine".
    for (label, value) in unreadable_cases() {
        let result = verify(&with_delegation(Some(value.clone())));
        assert!(
            result
                .warnings
                .contains(&PassportWarning::DelegationInvalidExpiry),
            "delegation expiresAt {label} ({value}) produced {:?}",
            result.warnings
        );
        assert!(
            !result
                .warnings
                .contains(&PassportWarning::DelegationExpired),
            "delegation expiresAt {label} claimed the grant had expired, which was never read"
        );
    }
}

#[test]
fn an_absent_delegation_expiry_warns_about_neither() {
    let result = verify(&with_delegation(None));
    assert!(!result
        .warnings
        .contains(&PassportWarning::DelegationExpired));
    assert!(!result
        .warnings
        .contains(&PassportWarning::DelegationInvalidExpiry));
}

#[test]
fn the_delegation_warning_still_does_not_affect_validity() {
    // The repair adds a warning variant; it must not have quietly promoted the
    // delegation leg into a gate.
    let result = verify(&with_delegation(Some(json!("not-a-date"))));
    assert!(result.valid, "{:?}", result.errors);
}
