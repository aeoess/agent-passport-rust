//! ReceiptV1 verification: the pinned reference KAT from
//! tests/receipt-core-v1.test.ts (receipt_id and issuer signature produced
//! by the TypeScript SDK with the all-zero seed), every rejection case, the
//! resolver outcome split, and the two-signer receipt_id regression.

mod common;

use agent_passport::receipt_core::{
    compute_receipt_id_v1, is_exact_utc_milliseconds, receipt_signature_payload_v1,
    validate_receipt_v1, verify_receipt_v1, KeyResolution, ReceiptError, ReceiptProblem,
    SignatureFailureReason,
};
use common::{public_key_hex, sign_hex};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

// Pinned by the reference TypeScript test with private key 00 * 32.
const KAT_RECEIPT_ID: &str = "89b0b77807e99845aab403f01bcdaa2f02949f6c9db84e1aca6c0a8449e4d023";
const KAT_RECEIPT_SIG: &str = "83deb713568bbdf0c85e1a6d46345530e84dbe86cdefe1cb608b0f14372c176a9e69e0033db11c4c44ff84be3de3bee5e212707eb84206f6c34455206d37f90b";

fn zero_seed_public() -> String {
    hex::encode(
        SigningKey::from_bytes(&[0u8; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn hex_of(c: char) -> String {
    c.to_string().repeat(64)
}

/// The exact receipt the reference created in its KAT: evidence sorted, one
/// issuer signature, recorded receipt_id and signature value.
fn kat_receipt() -> Value {
    json!({
        "profile": "aps-receipt-v1",
        "receipt_id": KAT_RECEIPT_ID,
        "receipt_type": "aps:action:v1",
        "issuer": "did:example:issuer",
        "subject_agent": "did:example:agent",
        "action_ref": hex_of('a'),
        "delegation_ref": hex_of('b'),
        "decision_ref": hex_of('c'),
        "issued_at": "2026-07-18T12:00:00.000Z",
        "evidence_refs": [
            {"artifact_type": "a", "sha256": hex_of('d')},
            {"artifact_type": "z", "sha256": hex_of('e')}
        ],
        "result": {"status": "success", "detail": null},
        "signatures": [
            {"signer": "did:example:issuer", "key_id": "key-1", "alg": "Ed25519", "value": KAT_RECEIPT_SIG}
        ]
    })
}

#[test]
fn pinned_reference_receipt_verifies() {
    let receipt = kat_receipt();
    assert_eq!(compute_receipt_id_v1(&receipt).unwrap(), KAT_RECEIPT_ID);
    let public = zero_seed_public();
    let result = verify_receipt_v1(&receipt, |_, _, _| KeyResolution::Key(public.clone()));
    assert!(result.valid, "{result:?}");
    assert!(result.receipt_id_valid);
    assert_eq!(result.signature_results.len(), 1);
    assert!(result.signature_results[0].valid);
}

#[test]
fn relabeled_key_id_invalidates_the_signature() {
    // The signer descriptor is inside the signed preimage: changing key_id
    // makes the same signature bytes verify against a different preimage.
    let mut receipt = kat_receipt();
    receipt["signatures"][0]["key_id"] = json!("key-2");
    let public = zero_seed_public();
    let result = verify_receipt_v1(&receipt, |_, _, _| KeyResolution::Key(public.clone()));
    assert!(!result.valid);
    assert!(result.receipt_id_valid, "receipt_id ignores signatures");
    assert!(!result.signature_results[0].valid);
    assert!(result.errors.contains(&ReceiptProblem::SignatureInvalid));
}

#[test]
fn tampered_result_invalidates_id_and_signature() {
    let mut receipt = kat_receipt();
    receipt["result"]["status"] = json!("failure");
    let public = zero_seed_public();
    let result = verify_receipt_v1(&receipt, |_, _, _| KeyResolution::Key(public.clone()));
    assert!(!result.valid);
    assert!(!result.receipt_id_valid);
    assert!(result.errors.contains(&ReceiptProblem::ReceiptIdMismatch));
}

#[test]
fn resolver_outcomes_are_distinct() {
    let receipt = kat_receipt();
    let unresolved = verify_receipt_v1(&receipt, |_, _, _| KeyResolution::Unresolved);
    assert!(!unresolved.valid);
    assert_eq!(
        unresolved.signature_results[0].reason,
        Some(SignatureFailureReason::KeyUnresolved)
    );
    let errored = verify_receipt_v1(&receipt, |_, _, _| KeyResolution::Error);
    assert!(!errored.valid);
    assert_eq!(
        errored.signature_results[0].reason,
        Some(SignatureFailureReason::KeyResolutionError)
    );
    // The resolver receives issued_at so it can resolve keys at issuance.
    let mut seen_issued_at = String::new();
    let _ = verify_receipt_v1(&receipt, |_, _, issued_at| {
        seen_issued_at = issued_at.to_string();
        KeyResolution::Unresolved
    });
    assert_eq!(seen_issued_at, "2026-07-18T12:00:00.000Z");
}

#[test]
fn validation_rejections() {
    type Case = (&'static str, Box<dyn Fn(&mut Value)>, ReceiptError);
    let cases: Vec<Case> = vec![
        (
            "unknown field",
            Box::new(|r| r["extra"] = json!(1)),
            ReceiptError::UnknownField,
        ),
        (
            "missing field",
            Box::new(|r| {
                r.as_object_mut().unwrap().remove("issuer");
            }),
            ReceiptError::MissingField,
        ),
        (
            "wrong profile",
            Box::new(|r| r["profile"] = json!("aps-receipt-v2")),
            ReceiptError::WrongProfile,
        ),
        (
            "empty identifier",
            Box::new(|r| r["receipt_type"] = json!("")),
            ReceiptError::EmptyIdentifier,
        ),
        (
            "bad receipt_id hex",
            Box::new(|r| r["receipt_id"] = json!("XYZ")),
            ReceiptError::InvalidHex64,
        ),
        (
            "uppercase action_ref",
            Box::new(|r| r["action_ref"] = json!("A".repeat(64))),
            ReceiptError::InvalidHex64,
        ),
        (
            "bad prev",
            Box::new(|r| r["prev"] = json!("00")),
            ReceiptError::InvalidHex64,
        ),
        (
            "issued_at second precision",
            Box::new(|r| r["issued_at"] = json!("2026-07-18T12:00:00Z")),
            ReceiptError::InvalidIssuedAt,
        ),
        (
            "issued_at offset",
            Box::new(|r| r["issued_at"] = json!("2026-07-18T12:00:00.000+00:00")),
            ReceiptError::InvalidIssuedAt,
        ),
        (
            "issued_at rollover date",
            Box::new(|r| r["issued_at"] = json!("2026-02-30T12:00:00.000Z")),
            ReceiptError::InvalidIssuedAt,
        ),
        (
            "result array",
            Box::new(|r| r["result"] = json!([1])),
            ReceiptError::InvalidResult,
        ),
        (
            "result null",
            Box::new(|r| r["result"] = json!(null)),
            ReceiptError::InvalidResult,
        ),
        (
            "evidence not array",
            Box::new(|r| r["evidence_refs"] = json!({})),
            ReceiptError::NotArrays,
        ),
        (
            "evidence unsorted",
            Box::new(|r| {
                r["evidence_refs"] = json!([
                    {"artifact_type": "z", "sha256": "e".repeat(64)},
                    {"artifact_type": "a", "sha256": "d".repeat(64)}
                ])
            }),
            ReceiptError::EvidenceRefsNotSorted,
        ),
        (
            "evidence duplicate",
            Box::new(|r| {
                r["evidence_refs"] = json!([
                    {"artifact_type": "a", "sha256": "d".repeat(64)},
                    {"artifact_type": "a", "sha256": "d".repeat(64)}
                ])
            }),
            ReceiptError::DuplicateEvidenceRef,
        ),
        (
            "evidence unknown key",
            Box::new(|r| {
                r["evidence_refs"] =
                    json!([{"artifact_type": "a", "sha256": "d".repeat(64), "note": 1}])
            }),
            ReceiptError::UnknownField,
        ),
        (
            "signature wrong alg",
            Box::new(|r| r["signatures"][0]["alg"] = json!("RSA")),
            ReceiptError::InvalidSignatureDescriptor,
        ),
        (
            "signature bad value hex",
            Box::new(|r| r["signatures"][0]["value"] = json!("zz")),
            ReceiptError::InvalidSignatureDescriptor,
        ),
        (
            "issuer signature missing",
            Box::new(|r| {
                r["signatures"] = json!([
                    {"signer": "did:example:other", "key_id": "k", "alg": "Ed25519", "value": "0".repeat(128)}
                ])
            }),
            ReceiptError::IssuerSignatureMissing,
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut receipt = kat_receipt();
        mutate(&mut receipt);
        assert_eq!(
            validate_receipt_v1(&receipt, true),
            Err(expected.clone()),
            "{name}"
        );
        let result = verify_receipt_v1(&receipt, |_, _, _| KeyResolution::Unresolved);
        assert!(!result.valid, "{name}: verify must also reject");
        assert!(
            result.signature_results.is_empty(),
            "{name}: no partial work"
        );
    }

    // Duplicate and unsorted signature descriptors.
    let mut dup = kat_receipt();
    dup["signatures"] = json!([
        {"signer": "did:example:issuer", "key_id": "key-1", "alg": "Ed25519", "value": "0".repeat(128)},
        {"signer": "did:example:issuer", "key_id": "key-1", "alg": "Ed25519", "value": "1".repeat(128)}
    ]);
    assert_eq!(
        validate_receipt_v1(&dup, true),
        Err(ReceiptError::DuplicateSignature)
    );
    let mut unsorted = kat_receipt();
    unsorted["signatures"] = json!([
        {"signer": "did:example:issuer", "key_id": "key-2", "alg": "Ed25519", "value": "0".repeat(128)},
        {"signer": "did:example:issuer", "key_id": "key-1", "alg": "Ed25519", "value": "1".repeat(128)}
    ]);
    assert_eq!(
        validate_receipt_v1(&unsorted, true),
        Err(ReceiptError::SignaturesNotSorted)
    );

    assert_eq!(
        validate_receipt_v1(&json!(null), true),
        Err(ReceiptError::NotAnObject)
    );
    // Unsafe integer inside result violates strict I-JSON.
    let mut unsafe_number = kat_receipt();
    unsafe_number["result"]["big"] = json!(9007199254740994i64);
    assert_eq!(
        validate_receipt_v1(&unsafe_number, true),
        Err(ReceiptError::NotStrictIJson)
    );
}

#[test]
fn issued_at_format_is_exact() {
    assert!(is_exact_utc_milliseconds("2026-07-18T12:00:00.000Z"));
    for bad in [
        "2026-07-18T12:00:00Z",
        "2026-07-18T12:00:00.0000Z",
        "2026-07-18T12:00:00.00Z",
        "2026-07-18 12:00:00.000Z",
        "2026-07-18T12:00:00.000+00:00",
        "2026-02-30T12:00:00.000Z",
        "2026-07-18T12:00:60.000Z",
        "",
    ] {
        assert!(!is_exact_utc_milliseconds(bad), "{bad}");
    }
}

#[test]
fn optional_members_stay_optional() {
    // decision_ref and prev may be omitted entirely; presence with a bad
    // value rejects (covered above), absence is fine.
    let mut receipt = kat_receipt();
    receipt.as_object_mut().unwrap().remove("decision_ref");
    // Removing decision_ref changes the identity preimage, so recompute.
    receipt["receipt_id"] = json!(compute_receipt_id_v1(&receipt).unwrap());
    assert_eq!(validate_receipt_v1(&receipt, true), Ok(()));
}

#[test]
fn two_signers_share_receipt_id_but_not_signatures() {
    // receipt_id is content-derived, not signer-bound: two signers over the
    // same unsigned body produce the same receipt_id and different
    // signatures. Callers must never treat receipt_id as a signer identity.
    let seed_one = [1u8; 32];
    let seed_two = [2u8; 32];
    let signer_one = "did:example:issuer";
    let signer_two = "did:example:witness";
    let mut receipt = json!({
        "profile": "aps-receipt-v1",
        "receipt_id": "0".repeat(64),
        "receipt_type": "aps:action:v1",
        "issuer": signer_one,
        "subject_agent": "did:example:agent",
        "action_ref": hex_of('a'),
        "delegation_ref": hex_of('b'),
        "issued_at": "2026-07-18T12:00:00.000Z",
        "evidence_refs": [],
        "result": {"status": "success"},
        "signatures": []
    });
    receipt["receipt_id"] = json!(compute_receipt_id_v1(&receipt).unwrap());
    let payload_one = receipt_signature_payload_v1(&receipt, signer_one, "key-1").unwrap();
    let payload_two = receipt_signature_payload_v1(&receipt, signer_two, "key-1").unwrap();
    let signature_one = sign_hex(&payload_one, &seed_one);
    let signature_two = sign_hex(&payload_two, &seed_two);
    assert_ne!(signature_one, signature_two);

    receipt["signatures"] = json!([
        {"signer": signer_one, "key_id": "key-1", "alg": "Ed25519", "value": signature_one},
        {"signer": signer_two, "key_id": "key-1", "alg": "Ed25519", "value": signature_two}
    ]);
    // Adding signatures does not change the content identity.
    assert_eq!(
        compute_receipt_id_v1(&receipt).unwrap(),
        receipt["receipt_id"].as_str().unwrap()
    );

    let key_one = public_key_hex(&seed_one);
    let key_two = public_key_hex(&seed_two);
    let result = verify_receipt_v1(&receipt, |signer, _, _| {
        if signer == signer_one {
            KeyResolution::Key(key_one.clone())
        } else {
            KeyResolution::Key(key_two.clone())
        }
    });
    assert!(result.valid, "{result:?}");
    assert!(result.signature_results.iter().all(|r| r.valid));
}

#[test]
fn strict_input_boundary_feeds_the_verifier() {
    // A receipt arriving as raw text passes through parse_strict_ijson, so a
    // duplicate member, an escape-alias duplicate, or oversized input never
    // reaches the schema.
    use agent_passport::jcs::{parse_strict_ijson_default, IJsonError};
    let serialized = serde_json::to_string(&kat_receipt()).unwrap();
    let reparsed = parse_strict_ijson_default(serialized.as_bytes()).unwrap();
    let public = zero_seed_public();
    let result = verify_receipt_v1(&reparsed, |_, _, _| KeyResolution::Key(public.clone()));
    assert!(result.valid, "{result:?}");

    assert_eq!(
        parse_strict_ijson_default(br#"{"profile":"x","profile":"y"}"#),
        Err(IJsonError::DuplicateMember)
    );
    assert_eq!(
        parse_strict_ijson_default(br#"{"a":1,"a":2}"#),
        Err(IJsonError::DuplicateMember)
    );
}
