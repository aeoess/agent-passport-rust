//! Passport verification: the pinned reference TypeScript values from the Go
//! passport suite, tampering of every signed field, issuer trust paths,
//! temporal boundaries with equality, null-versus-omission under the legacy
//! profile, and structural-only status.

mod common;

use agent_passport::passport::{
    agent_signature_preimage, issuer_signature_preimage, verify_issuer_signature, verify_passport,
    PassportError, PassportVerifyOptions, PassportWarning,
};
use common::{public_key_hex, seed_from, sign_hex};
use serde_json::{json, Value};

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

// Deterministic inputs shared with the Go suite and the TS oracle.
const AGENT_KEY_SEED: &str = "aps-go-passport-agent-key";
const ISSUER_KEY_SEED: &str = "aps-go-passport-issuer-key";
const FIXED_CREATED_AT: &str = "2026-06-03T12:00:00Z";
const FIXED_EXPIRES_AT: &str = "2027-06-03T12:00:00Z";
const FIXED_SIGNED_AT: &str = "2026-06-03T12:00:00Z";
const FIXED_VERIFY_NOW: &str = "2026-06-03T13:00:00Z";

// Pinned values produced by the reference TypeScript SDK on the inputs above,
// vendored from the Go suite (passport/passport_test.go). Not authored here.
const TS_PASSPORT_CANONICAL_SHA256: &str =
    "0870b81e3d922da164321e92e1310d983b1ba419d7cf637ac057edd3bbd039fe";
const TS_AGENT_SIGNATURE: &str =
    "587cac21033db22d8e6744ddf3d75219228d7384f4868bb9b5e7a025c7f856dacfc343e6fa3ed1c0141cc0fc4460fa21ae2bb879ec3051e78531c4b8b146700a";
const TS_ISSUER_PAYLOAD_SHA256: &str =
    "a884026138ac415a483f2d4322a167e9d919915939ad1d8afc5d5934af8d99e1";
const TS_ISSUER_SIGNATURE: &str =
    "3f4bebf4250638b44f27b0e8649833025e0f3f9e9cad0cb26efcf3b741da12a04a739a2cdaf15e15ae9b51cc8d607af2e835f7e196d228ce8a18a7d5ad65180f";

/// The deterministic passport from the Go fixture, as a raw JSON value.
/// voteWeight 2 = round(1 + 0.5 + 0.2) for the two capabilities.
fn fixture_passport() -> Value {
    let agent_public = public_key_hex(&seed_from(AGENT_KEY_SEED));
    json!({
        "version": "1.0.0",
        "agentId": "ag_passport_001",
        "agentName": "Oracle Agent",
        "ownerAlias": "owner-alpha",
        "publicKey": agent_public,
        "mission": "cross-impl byte parity",
        "capabilities": ["code_execution", "web_search"],
        "runtime": {
            "platform": "node",
            "models": ["claude-opus-4"],
            "toolsCount": 3,
            "memoryType": "ephemeral"
        },
        "createdAt": FIXED_CREATED_AT,
        "expiresAt": FIXED_EXPIRES_AT,
        "voteWeight": 2,
        "reputation": {
            "overall": 1,
            "collaborationsCompleted": 0,
            "proposalsSubmitted": 0,
            "proposalsApproved": 0,
            "tokensContributed": 0,
            "tasksCompleted": 0,
            "lastUpdated": FIXED_CREATED_AT
        },
        "delegations": [],
        "metadata": {}
    })
}

fn signed_fixture() -> Value {
    json!({
        "passport": fixture_passport(),
        "signature": TS_AGENT_SIGNATURE,
        "signedAt": FIXED_SIGNED_AT,
        "issuerSignature": {
            "issuerId": "aeoess",
            "issuerPublicKey": public_key_hex(&seed_from(ISSUER_KEY_SEED)),
            "signature": TS_ISSUER_SIGNATURE,
            "signedAt": FIXED_SIGNED_AT
        }
    })
}

fn options<'a>(trusted: &'a [String]) -> PassportVerifyOptions<'a> {
    PassportVerifyOptions {
        trusted_issuers: trusted,
        evaluation_time: FIXED_VERIFY_NOW,
        allowed_clock_skew_ms: 0,
    }
}

#[test]
fn pinned_reference_preimages_and_signatures() {
    let signed = signed_fixture();
    let canonical = agent_signature_preimage(&signed["passport"]).unwrap();
    assert_eq!(sha256_hex(&canonical), TS_PASSPORT_CANONICAL_SHA256);
    let issuer_payload = issuer_signature_preimage(&signed).unwrap();
    assert_eq!(sha256_hex(&issuer_payload), TS_ISSUER_PAYLOAD_SHA256);

    let issuers = vec![public_key_hex(&seed_from(ISSUER_KEY_SEED))];
    let result = verify_passport(&signed, &options(&issuers)).unwrap();
    assert!(
        result.valid,
        "pinned reference passport verifies: {result:?}"
    );
    assert!(result.errors.is_empty());
    assert!(verify_issuer_signature(&signed, &issuers[0]));
    assert!(!verify_issuer_signature(
        &signed,
        &public_key_hex(&seed_from("other"))
    ));
}

#[test]
fn tampering_any_signed_field_invalidates() {
    let issuers = vec![public_key_hex(&seed_from(ISSUER_KEY_SEED))];
    let baseline = verify_passport(&signed_fixture(), &options(&issuers)).unwrap();
    assert!(baseline.valid);
    for (field, tampered_value) in [
        ("version", json!("2.0.0")),
        ("agentId", json!("ag_other")),
        ("agentName", json!("Mallory")),
        ("ownerAlias", json!("owner-beta")),
        ("mission", json!("something else")),
        ("capabilities", json!(["code_execution"])),
        ("createdAt", json!("2026-06-04T12:00:00Z")),
        ("expiresAt", json!("2028-06-03T12:00:00Z")),
        ("voteWeight", json!(9)),
        ("delegations", json!([{"delegatedTo": "x"}])),
        ("metadata", json!({"injected": true})),
    ] {
        let mut signed = signed_fixture();
        signed["passport"][field] = tampered_value;
        let result = verify_passport(&signed, &options(&issuers)).unwrap();
        assert!(
            result.errors.contains(&PassportError::InvalidSignature),
            "tampered {field} must fail the agent signature"
        );
    }
    // Tampering the envelope invalidates the issuer countersignature even
    // though the agent signature still holds.
    let mut signed = signed_fixture();
    signed["signedAt"] = json!("2026-06-04T12:00:00Z");
    let result = verify_passport(&signed, &options(&issuers)).unwrap();
    assert!(result
        .errors
        .contains(&PassportError::InvalidIssuerCountersignature));
    assert!(!result.errors.contains(&PassportError::InvalidSignature));
}

#[test]
fn issuer_trust_paths() {
    let issuers = vec![public_key_hex(&seed_from(ISSUER_KEY_SEED))];

    // Missing issuer signature under a trust set.
    let mut self_signed = signed_fixture();
    self_signed
        .as_object_mut()
        .unwrap()
        .remove("issuerSignature");
    let result = verify_passport(&self_signed, &options(&issuers)).unwrap();
    assert!(result
        .errors
        .contains(&PassportError::NoIssuerCountersignature));

    // Unknown issuer key.
    let strangers = vec![public_key_hex(&seed_from("some-other-authority"))];
    let result = verify_passport(&signed_fixture(), &options(&strangers)).unwrap();
    assert!(result.errors.contains(&PassportError::UntrustedIssuer));

    // Structural-only: no trusted issuers means a warning, not an error.
    let none: Vec<String> = Vec::new();
    let result = verify_passport(&self_signed, &options(&none)).unwrap();
    assert!(
        result.valid,
        "structural-only accepts a self-signed passport"
    );
    assert!(result.warnings.contains(&PassportWarning::NoTrustedIssuers));
}

#[test]
fn temporal_boundaries_pin_equality() {
    let none: Vec<String> = Vec::new();
    let signed = signed_fixture();
    let at = |when: &str| {
        verify_passport(
            &signed,
            &PassportVerifyOptions {
                trusted_issuers: &none,
                evaluation_time: when,
                allowed_clock_skew_ms: 0,
            },
        )
        .unwrap()
    };
    // Exactly at expiry: still live (expired only when strictly past).
    assert!(at(FIXED_EXPIRES_AT).valid);
    // One second past expiry: expired.
    assert!(at("2027-06-03T12:00:01Z")
        .errors
        .contains(&PassportError::Expired));
    // Skew tolerates it again.
    let skewed = verify_passport(
        &signed,
        &PassportVerifyOptions {
            trusted_issuers: &none,
            evaluation_time: "2027-06-03T12:00:01Z",
            allowed_clock_skew_ms: 2_000,
        },
    )
    .unwrap();
    assert!(skewed.valid);

    // notBefore: equality is valid; earlier is not.
    let mut gated = signed_fixture();
    gated["passport"]["notBefore"] = json!("2026-06-03T13:00:00Z");
    // The notBefore edit breaks the agent signature, which is fine here: only
    // the temporal verdicts are under test.
    let at_boundary = verify_passport(&gated, &options(&none)).unwrap();
    assert!(!at_boundary.errors.contains(&PassportError::NotYetValid));
    let early = verify_passport(
        &gated,
        &PassportVerifyOptions {
            trusted_issuers: &none,
            evaluation_time: "2026-06-03T12:59:59Z",
            allowed_clock_skew_ms: 0,
        },
    )
    .unwrap();
    assert!(early.errors.contains(&PassportError::NotYetValid));

    // A bad evaluation time is the verifier's own error, not a verdict.
    assert!(verify_passport(
        &signed,
        &PassportVerifyOptions {
            trusted_issuers: &none,
            evaluation_time: "not-a-time",
            allowed_clock_skew_ms: 0,
        },
    )
    .is_err());
}

#[test]
fn explicit_null_versus_omission_under_the_legacy_profile() {
    // The legacy profile strips null members, so a passport signed without a
    // member verifies identically when the member arrives as an explicit
    // null, and fails when it arrives with a value. This is the profile's
    // documented contract, pinned here so nobody reroutes passports through
    // strict JCS.
    let none: Vec<String> = Vec::new();
    let mut with_null = signed_fixture();
    with_null["passport"]["obligationBundleHash"] = Value::Null;
    let result = verify_passport(&with_null, &options(&none)).unwrap();
    assert!(
        result.valid,
        "explicit null must not change the legacy preimage: {result:?}"
    );

    let mut with_value = signed_fixture();
    with_value["passport"]["obligationBundleHash"] = json!("abc");
    let result = verify_passport(&with_value, &options(&none)).unwrap();
    assert!(result.errors.contains(&PassportError::InvalidSignature));
}

#[test]
fn malformed_inputs_and_missing_fields() {
    let none: Vec<String> = Vec::new();
    for broken in [
        Value::Null,
        json!("not-an-object"),
        json!({}),
        json!({"passport": fixture_passport()}),
        json!({"signature": TS_AGENT_SIGNATURE}),
        json!({"passport": null, "signature": TS_AGENT_SIGNATURE}),
        json!({"passport": fixture_passport(), "signature": ""}),
    ] {
        let result = verify_passport(&broken, &options(&none)).unwrap();
        assert_eq!(
            result.errors,
            vec![PassportError::MissingPassportOrSignature],
            "{broken}"
        );
    }

    // Malformed signature and malformed key reject via the signature check.
    let mut bad_sig = signed_fixture();
    bad_sig["signature"] = json!("zz".repeat(64));
    let result = verify_passport(&bad_sig, &options(&none)).unwrap();
    assert!(result.errors.contains(&PassportError::InvalidSignature));

    let mut bad_key = signed_fixture();
    bad_key["passport"]["publicKey"] = json!("deadbeef");
    let result = verify_passport(&bad_key, &options(&none)).unwrap();
    assert!(result.errors.contains(&PassportError::InvalidSignature));

    // Missing identity fields, still structurally reported. Rebuild a
    // consistently signed passport without agentId to isolate the check.
    let seed = seed_from(AGENT_KEY_SEED);
    let mut passport = fixture_passport();
    passport.as_object_mut().unwrap().remove("agentId");
    let canonical = agent_signature_preimage(&passport).unwrap();
    let signed = json!({
        "passport": passport,
        "signature": sign_hex(&canonical, &seed),
        "signedAt": FIXED_SIGNED_AT
    });
    let result = verify_passport(&signed, &options(&none)).unwrap();
    assert_eq!(result.errors, vec![PassportError::MissingAgentId]);
}

#[test]
fn warnings_do_not_affect_validity() {
    let none: Vec<String> = Vec::new();
    let seed = seed_from(AGENT_KEY_SEED);
    let mut passport = fixture_passport();
    passport.as_object_mut().unwrap().remove("version");
    passport["capabilities"] = json!([]);
    passport["voteWeight"] = json!(1);
    passport["delegations"] = json!([
        {"delegatedTo": "a", "expiresAt": "2020-01-01T00:00:00Z"},
        {"delegatedTo": "b", "spendLimit": 10, "spentAmount": 10}
    ]);
    let canonical = agent_signature_preimage(&passport).unwrap();
    let signed = json!({
        "passport": passport,
        "signature": sign_hex(&canonical, &seed),
        "signedAt": FIXED_SIGNED_AT
    });
    let result = verify_passport(&signed, &options(&none)).unwrap();
    assert!(result.valid, "{result:?}");
    for expected in [
        PassportWarning::NoTrustedIssuers,
        PassportWarning::NoVersion,
        PassportWarning::NoCapabilities,
        PassportWarning::DelegationExpired,
        PassportWarning::DelegationSpendExhausted,
    ] {
        assert!(result.warnings.contains(&expected), "{expected:?}");
    }
}
