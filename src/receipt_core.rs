//! ReceiptV1 verification, ported from the reference v2 receipt-core
//! (`src/v2/receipt-core/receipt.ts`). Verification only: receipt creation
//! and `ReceiptSignerV1` are deliberately not ported.
//!
//! Profile: strict JCS with domain separation. The receipt identity is
//! `sha256("APS-RECEIPT-ID-V1" NUL strictJCS(receipt minus receipt_id minus
//! signatures))`; each signature covers `"APS-RECEIPT-SIG-V1" NUL
//! strictJCS({receipt: receipt minus signatures, signer: descriptor})`, so a
//! signature is bound to its own signer descriptor and cannot be relabeled.
//! `receipt_id` validity and signature validity are reported separately:
//! `receipt_id` is content-derived and NOT signer-bound, so two signers over
//! the same unsigned body share a `receipt_id` while their signatures
//! differ.
//!
//! Receipts travel as raw [`serde_json::Value`] parsed through the strict
//! I-JSON boundary ([`crate::jcs::parse_strict_ijson`]) when they arrive as
//! text, so duplicate members, lone surrogates, oversized input, and unsafe
//! numbers are rejected before this module sees them. The schema here is
//! closed: unknown members reject, matching the reference `assertExactKeys`.
//!
//! Key lookup is caller-supplied through [`KeyResolution`] and receives
//! `(signer, key_id, issued_at)` so the caller can resolve the key that was
//! valid at issuance. The crate performs no network access; a resolver that
//! needs I/O must do it outside and hand results in.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::crypto::verify_ed25519;
use crate::jcs;

/// Domain-separation tag for the receipt identity preimage.
pub const RECEIPT_ID_TAG: &str = "APS-RECEIPT-ID-V1";
/// Domain-separation tag for the signature preimage.
pub const RECEIPT_SIG_TAG: &str = "APS-RECEIPT-SIG-V1";

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// True for an exact UTC-millisecond timestamp,
/// `YYYY-MM-DDTHH:MM:SS.mmmZ`, that round-trips through a real calendar
/// date. Wrong precision, offsets, and rollover dates all reject, matching
/// the reference `isExactUtcMilliseconds`.
pub fn is_exact_utc_milliseconds(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 {
        return false;
    }
    for (index, &b) in bytes.iter().enumerate() {
        let ok = match index {
            4 | 7 => b == b'-',
            10 => b == b'T',
            13 | 16 => b == b':',
            19 => b == b'.',
            23 => b == b'Z',
            _ => b.is_ascii_digit(),
        };
        if !ok {
            return false;
        }
    }
    let Ok(parsed) =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
    else {
        return false;
    };
    let utc = parsed.to_offset(time::UtcOffset::UTC);
    let formatted = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond()
    );
    formatted == value
}

/// A ReceiptV1 validation failure. Stable categories; no payload content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    /// The receipt is not a JSON object.
    #[error("ReceiptV1: not an object")]
    NotAnObject,
    /// The receipt carries a member outside the closed schema.
    #[error("ReceiptV1: unknown field")]
    UnknownField,
    /// A required member is missing.
    #[error("ReceiptV1: missing field")]
    MissingField,
    /// The receipt violates the strict I-JSON number rules.
    #[error("ReceiptV1: not strict I-JSON")]
    NotStrictIJson,
    /// `profile` is not `aps-receipt-v1`.
    #[error("ReceiptV1: profile")]
    WrongProfile,
    /// `receipt_type`, `issuer`, `subject_agent`, or `delegation_ref` is
    /// empty or not a string.
    #[error("ReceiptV1: empty identifier")]
    EmptyIdentifier,
    /// A hash-valued member is not lowercase 64-char hex.
    #[error("ReceiptV1: invalid hex64 value")]
    InvalidHex64,
    /// `issued_at` is not an exact UTC-millisecond timestamp.
    #[error("ReceiptV1: issued_at")]
    InvalidIssuedAt,
    /// `result` is not an object.
    #[error("ReceiptV1: result")]
    InvalidResult,
    /// `evidence_refs` or `signatures` is not an array.
    #[error("ReceiptV1: arrays")]
    NotArrays,
    /// An evidence reference is malformed.
    #[error("EvidenceRefV1: value")]
    InvalidEvidenceRef,
    /// Two evidence references collide.
    #[error("ReceiptV1: duplicate evidence_ref")]
    DuplicateEvidenceRef,
    /// `evidence_refs` is not sorted by (artifact_type, sha256) UTF-8 order.
    #[error("ReceiptV1: evidence_refs not sorted")]
    EvidenceRefsNotSorted,
    /// A signature descriptor is malformed (empty names, wrong alg, or an
    /// invalid signature value).
    #[error("ReceiptSignatureV1: value")]
    InvalidSignatureDescriptor,
    /// Two signature descriptors collide on (signer, key_id).
    #[error("ReceiptV1: duplicate signature")]
    DuplicateSignature,
    /// `signatures` is not sorted by (signer, key_id) UTF-8 order.
    #[error("ReceiptV1: signatures not sorted")]
    SignaturesNotSorted,
    /// No signature names the issuer.
    #[error("ReceiptV1: issuer signature missing")]
    IssuerSignatureMissing,
}

const ALLOWED_KEYS: [&str; 13] = [
    "profile",
    "receipt_id",
    "receipt_type",
    "issuer",
    "subject_agent",
    "action_ref",
    "delegation_ref",
    "decision_ref",
    "issued_at",
    "evidence_refs",
    "result",
    "prev",
    "signatures",
];
const REQUIRED_KEYS: [&str; 11] = [
    "profile",
    "receipt_id",
    "receipt_type",
    "issuer",
    "subject_agent",
    "action_ref",
    "delegation_ref",
    "issued_at",
    "evidence_refs",
    "result",
    "signatures",
];

fn require_str<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReceiptError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ReceiptError::EmptyIdentifier)
}

/// Validate a ReceiptV1 value against the closed reference schema. With
/// `require_values` false the `receipt_id` and signature values may be
/// placeholders (the reference uses that mode only while building; verifiers
/// pass true).
pub fn validate_receipt_v1(receipt: &Value, require_values: bool) -> Result<(), ReceiptError> {
    let object = receipt.as_object().ok_or(ReceiptError::NotAnObject)?;
    for key in object.keys() {
        if !ALLOWED_KEYS.contains(&key.as_str()) {
            return Err(ReceiptError::UnknownField);
        }
    }
    for key in REQUIRED_KEYS {
        if !object.contains_key(key) {
            return Err(ReceiptError::MissingField);
        }
    }
    jcs::assert_ijson(receipt).map_err(|_| ReceiptError::NotStrictIJson)?;
    if object.get("profile").and_then(Value::as_str) != Some("aps-receipt-v1") {
        return Err(ReceiptError::WrongProfile);
    }
    for key in ["receipt_type", "issuer", "subject_agent", "delegation_ref"] {
        if require_str(object, key)?.is_empty() {
            return Err(ReceiptError::EmptyIdentifier);
        }
    }
    let receipt_id = object
        .get("receipt_id")
        .and_then(Value::as_str)
        .ok_or(ReceiptError::InvalidHex64)?;
    if require_values && !is_lower_hex(receipt_id, 64) {
        return Err(ReceiptError::InvalidHex64);
    }
    let action_ref = object
        .get("action_ref")
        .and_then(Value::as_str)
        .ok_or(ReceiptError::InvalidHex64)?;
    if !is_lower_hex(action_ref, 64) {
        return Err(ReceiptError::InvalidHex64);
    }
    for optional in ["decision_ref", "prev"] {
        if let Some(member) = object.get(optional) {
            let text = member.as_str().ok_or(ReceiptError::InvalidHex64)?;
            if !is_lower_hex(text, 64) {
                return Err(ReceiptError::InvalidHex64);
            }
        }
    }
    let issued_at = object
        .get("issued_at")
        .and_then(Value::as_str)
        .ok_or(ReceiptError::InvalidIssuedAt)?;
    if !is_exact_utc_milliseconds(issued_at) {
        return Err(ReceiptError::InvalidIssuedAt);
    }
    if !object.get("result").is_some_and(Value::is_object) {
        return Err(ReceiptError::InvalidResult);
    }
    let evidence = object
        .get("evidence_refs")
        .and_then(Value::as_array)
        .ok_or(ReceiptError::NotArrays)?;
    let signatures = object
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or(ReceiptError::NotArrays)?;

    let mut previous_evidence: Option<(String, String)> = None;
    let mut seen_evidence = std::collections::HashSet::new();
    for member in evidence {
        let entry = member.as_object().ok_or(ReceiptError::InvalidEvidenceRef)?;
        for key in entry.keys() {
            if key != "artifact_type" && key != "sha256" {
                return Err(ReceiptError::UnknownField);
            }
        }
        let artifact_type = entry
            .get("artifact_type")
            .and_then(Value::as_str)
            .ok_or(ReceiptError::InvalidEvidenceRef)?;
        let sha256 = entry
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or(ReceiptError::InvalidEvidenceRef)?;
        if artifact_type.is_empty() || !is_lower_hex(sha256, 64) {
            return Err(ReceiptError::InvalidEvidenceRef);
        }
        let key = (artifact_type.to_string(), sha256.to_string());
        if !seen_evidence.insert(key.clone()) {
            return Err(ReceiptError::DuplicateEvidenceRef);
        }
        if let Some(previous) = &previous_evidence {
            if previous >= &key {
                return Err(ReceiptError::EvidenceRefsNotSorted);
            }
        }
        previous_evidence = Some(key);
    }

    let issuer = require_str(object, "issuer")?;
    let mut previous_signature: Option<(String, String)> = None;
    let mut seen_signatures = std::collections::HashSet::new();
    let mut issuer_signed = false;
    for member in signatures {
        let entry = member
            .as_object()
            .ok_or(ReceiptError::InvalidSignatureDescriptor)?;
        for key in entry.keys() {
            if !["signer", "key_id", "alg", "value"].contains(&key.as_str()) {
                return Err(ReceiptError::UnknownField);
            }
        }
        for key in ["signer", "key_id", "alg", "value"] {
            if !entry.contains_key(key) {
                return Err(ReceiptError::MissingField);
            }
        }
        let signer = entry
            .get("signer")
            .and_then(Value::as_str)
            .ok_or(ReceiptError::InvalidSignatureDescriptor)?;
        let key_id = entry
            .get("key_id")
            .and_then(Value::as_str)
            .ok_or(ReceiptError::InvalidSignatureDescriptor)?;
        let alg = entry
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(ReceiptError::InvalidSignatureDescriptor)?;
        let value = entry
            .get("value")
            .and_then(Value::as_str)
            .ok_or(ReceiptError::InvalidSignatureDescriptor)?;
        if signer.is_empty() || key_id.is_empty() || alg != "Ed25519" {
            return Err(ReceiptError::InvalidSignatureDescriptor);
        }
        if require_values && !is_lower_hex(value, 128) {
            return Err(ReceiptError::InvalidSignatureDescriptor);
        }
        let key = (signer.to_string(), key_id.to_string());
        if !seen_signatures.insert(key.clone()) {
            return Err(ReceiptError::DuplicateSignature);
        }
        if let Some(previous) = &previous_signature {
            if previous >= &key {
                return Err(ReceiptError::SignaturesNotSorted);
            }
        }
        previous_signature = Some(key);
        if signer == issuer {
            issuer_signed = true;
        }
    }
    if require_values && !issuer_signed {
        return Err(ReceiptError::IssuerSignatureMissing);
    }
    Ok(())
}

fn receipt_without(receipt: &Map<String, Value>, drop: &[&str]) -> Value {
    let mut copy = receipt.clone();
    for key in drop {
        copy.remove(*key);
    }
    Value::Object(copy)
}

/// The domain-separated receipt identity preimage:
/// `RECEIPT_ID_TAG NUL strictJCS(receipt minus receipt_id minus signatures)`.
pub fn receipt_id_payload_v1(receipt: &Value) -> Result<String, ReceiptError> {
    let object = receipt.as_object().ok_or(ReceiptError::NotAnObject)?;
    let body = receipt_without(object, &["receipt_id", "signatures"]);
    let canonical = jcs::strict_jcs(&body).map_err(|_| ReceiptError::NotStrictIJson)?;
    Ok(format!("{RECEIPT_ID_TAG}\0{canonical}"))
}

/// Recompute the content-derived `receipt_id`: lowercase-hex SHA-256 of
/// [`receipt_id_payload_v1`]. Not signer-bound; see the module docs.
pub fn compute_receipt_id_v1(receipt: &Value) -> Result<String, ReceiptError> {
    let payload = receipt_id_payload_v1(receipt)?;
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// The domain-separated signature preimage for one signer descriptor:
/// `RECEIPT_SIG_TAG NUL strictJCS({receipt: receipt minus signatures,
/// signer: {signer, key_id, alg: "Ed25519"}})`. Binding the descriptor into
/// the preimage is what makes a signature non-relabelable.
pub fn receipt_signature_payload_v1(
    receipt: &Value,
    signer: &str,
    key_id: &str,
) -> Result<String, ReceiptError> {
    let object = receipt.as_object().ok_or(ReceiptError::NotAnObject)?;
    let mut descriptor = Map::new();
    descriptor.insert("signer".to_string(), Value::String(signer.to_string()));
    descriptor.insert("key_id".to_string(), Value::String(key_id.to_string()));
    descriptor.insert("alg".to_string(), Value::String("Ed25519".to_string()));
    let mut form = Map::new();
    form.insert(
        "receipt".to_string(),
        receipt_without(object, &["signatures"]),
    );
    form.insert("signer".to_string(), Value::Object(descriptor));
    let canonical =
        jcs::strict_jcs(&Value::Object(form)).map_err(|_| ReceiptError::NotStrictIJson)?;
    Ok(format!("{RECEIPT_SIG_TAG}\0{canonical}"))
}

/// Outcome of resolving a signer's key at `issued_at`. The two failure
/// outcomes are deliberately distinct: a resolver that looked and found
/// nothing reports [`KeyResolution::Unresolved`], and a resolver whose
/// lookup itself failed reports [`KeyResolution::Error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyResolution {
    /// The signer's public key, lowercase or uppercase hex.
    Key(String),
    /// The resolver completed but knows no key for this signer and key id.
    Unresolved,
    /// The resolver failed (I/O, backend, or internal error).
    Error,
}

/// Why one signature failed, when it failed without a cryptographic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFailureReason {
    /// No key is known for the descriptor.
    KeyUnresolved,
    /// The resolver itself failed.
    KeyResolutionError,
}

/// Per-signature verification outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureResult {
    /// The descriptor's signer.
    pub signer: String,
    /// The descriptor's key id.
    pub key_id: String,
    /// Whether the signature verified.
    pub valid: bool,
    /// Set when the failure happened before a cryptographic check.
    pub reason: Option<SignatureFailureReason>,
}

/// A problem recorded by [`verify_receipt_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptProblem {
    /// Schema validation failed before anything else ran.
    Validation(ReceiptError),
    /// The recomputed receipt id does not match the stored one.
    ReceiptIdMismatch,
    /// At least one signature failed.
    SignatureInvalid,
}

/// Outcome of [`verify_receipt_v1`]. `receipt_id_valid` and the signature
/// results are reported separately: a valid `receipt_id` proves content
/// identity, never signer identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptVerification {
    /// True when no problem was recorded.
    pub valid: bool,
    /// Whether the stored `receipt_id` matches the recomputed one.
    pub receipt_id_valid: bool,
    /// One entry per signature descriptor, in receipt order.
    pub signature_results: Vec<SignatureResult>,
    /// Every problem found.
    pub errors: Vec<ReceiptProblem>,
}

/// Verify a ReceiptV1: closed-schema validation, `receipt_id` recomputation,
/// and every signature over its descriptor-bound preimage, with keys
/// resolved by the caller at `issued_at`. The resolver receives
/// `(signer, key_id, issued_at)` and must not be given network access inside
/// this crate.
pub fn verify_receipt_v1(
    receipt: &Value,
    mut resolve_key: impl FnMut(&str, &str, &str) -> KeyResolution,
) -> ReceiptVerification {
    if let Err(validation) = validate_receipt_v1(receipt, true) {
        return ReceiptVerification {
            valid: false,
            receipt_id_valid: false,
            signature_results: Vec::new(),
            errors: vec![ReceiptProblem::Validation(validation)],
        };
    }
    let object = receipt.as_object().expect("validated as object");
    let mut errors = Vec::new();
    let stored_id = object
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let receipt_id_valid = compute_receipt_id_v1(receipt)
        .map(|computed| computed == stored_id)
        .unwrap_or(false);
    if !receipt_id_valid {
        errors.push(ReceiptProblem::ReceiptIdMismatch);
    }
    let issued_at = object
        .get("issued_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut signature_results = Vec::new();
    for member in object
        .get("signatures")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let signer = member.get("signer").and_then(Value::as_str).unwrap_or("");
        let key_id = member.get("key_id").and_then(Value::as_str).unwrap_or("");
        let value = member.get("value").and_then(Value::as_str).unwrap_or("");
        let result = match resolve_key(signer, key_id, issued_at) {
            KeyResolution::Key(key) => {
                let valid = receipt_signature_payload_v1(receipt, signer, key_id)
                    .map(|payload| verify_ed25519(payload.as_bytes(), value, &key))
                    .unwrap_or(false);
                SignatureResult {
                    signer: signer.to_string(),
                    key_id: key_id.to_string(),
                    valid,
                    reason: None,
                }
            }
            KeyResolution::Unresolved => SignatureResult {
                signer: signer.to_string(),
                key_id: key_id.to_string(),
                valid: false,
                reason: Some(SignatureFailureReason::KeyUnresolved),
            },
            KeyResolution::Error => SignatureResult {
                signer: signer.to_string(),
                key_id: key_id.to_string(),
                valid: false,
                reason: Some(SignatureFailureReason::KeyResolutionError),
            },
        };
        signature_results.push(result);
    }
    if signature_results.iter().any(|r| !r.valid) {
        errors.push(ReceiptProblem::SignatureInvalid);
    }
    ReceiptVerification {
        valid: errors.is_empty(),
        receipt_id_valid,
        signature_results,
        errors,
    }
}
