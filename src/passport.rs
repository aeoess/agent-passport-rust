//! Passport verification, ported from the reference `verifyPassport`
//! (`src/verification/verify.ts`) and `verifyIssuerSignature`
//! (`src/core/passport.ts`).
//!
//! Profile: passports sign over the legacy canonical form
//! ([`crate::legacy_canonical`], null-stripping), never strict JCS. The agent
//! signature covers `canonicalize(passport)`; the issuer countersignature
//! covers `canonicalize({passport, signature, signedAt})`.
//!
//! The passport travels here as a raw [`serde_json::Value`] rather than a
//! fixed struct: the signature covers every member the signer included, so
//! collapsing to a known field set would silently change the preimage for
//! any passport carrying extra members.
//!
//! Trust: with an empty `trusted_issuers` list the result is structural-only
//! and carries [`PassportWarning::NoTrustedIssuers`], the same warning
//! contract as the reference. Verification success and issuer-trust success
//! are reported separately in the errors list, never merged into one bool.
//!
//! Time: no wall clock. [`verify_passport`] takes an explicit RFC 3339
//! evaluation time and applies the reference's explicit-clock boundary
//! semantics: expired only when `expires_at` is strictly earlier than the
//! evaluation time minus the allowed skew, and not yet valid only when
//! `not_before` is strictly later than the evaluation time plus the skew.
//! Equality on either boundary is live. An unparseable or absent
//! `expiresAt`/`notBefore` skips that check, which is the reference behavior
//! and is deliberately preserved rather than silently hardened.

use serde_json::{Map, Value};

use crate::crypto::verify_ed25519;
use crate::legacy_canonical;

/// A verification failure. Variants are stable categories; no variant carries
/// signed payload contents, keys, or signatures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PassportError {
    /// The envelope is not an object, or `passport`/`signature` is missing.
    #[error("missing passport or signature")]
    MissingPassportOrSignature,
    /// The agent signature does not verify over the canonical passport.
    #[error("invalid signature: passport may have been tampered with")]
    InvalidSignature,
    /// Trusted issuers were supplied but the passport carries no issuer
    /// countersignature.
    #[error("no issuer countersignature: passport is self-signed")]
    NoIssuerCountersignature,
    /// The issuer countersignature names a key outside the trusted set.
    #[error("issuer not in trusted issuers list")]
    UntrustedIssuer,
    /// The issuer countersignature does not verify over the issuer preimage.
    #[error("invalid issuer countersignature")]
    InvalidIssuerCountersignature,
    /// `expires_at` is earlier than the evaluation time (minus skew).
    #[error("passport expired")]
    Expired,
    /// `not_before` is later than the evaluation time (plus skew).
    #[error("passport not yet valid")]
    NotYetValid,
    /// `agentId` is missing or empty.
    #[error("missing agentId")]
    MissingAgentId,
    /// `publicKey` is missing or empty.
    #[error("missing publicKey")]
    MissingPublicKey,
}

/// A non-fatal observation. Matches the reference warning contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassportWarning {
    /// No trusted issuers were supplied: the result is structural-only and
    /// self-signed passports are accepted.
    NoTrustedIssuers,
    /// The passport has no `version` member.
    NoVersion,
    /// The passport declares no capabilities.
    NoCapabilities,
    /// An embedded delegation expired before the evaluation time.
    DelegationExpired,
    /// An embedded delegation has spent its full spend limit.
    DelegationSpendExhausted,
}

/// Outcome of [`verify_passport`]. `valid` is true exactly when `errors` is
/// empty; warnings never affect it. When no trusted issuers were supplied
/// the result is structural-only, marked by
/// [`PassportWarning::NoTrustedIssuers`].
#[derive(Debug, Clone, PartialEq)]
pub struct PassportVerification {
    /// True when no error was recorded.
    pub valid: bool,
    /// Every check that failed.
    pub errors: Vec<PassportError>,
    /// Non-fatal observations, including the structural-only marker.
    pub warnings: Vec<PassportWarning>,
}

/// Inputs for [`verify_passport`].
#[derive(Debug, Clone)]
pub struct PassportVerifyOptions<'a> {
    /// Issuer public keys (hex) whose countersignature makes a passport
    /// authority-issued. Empty means structural-only verification.
    pub trusted_issuers: &'a [String],
    /// RFC 3339 evaluation time. There is no wall-clock fallback.
    pub evaluation_time: &'a str,
    /// Uniform clock skew in milliseconds, applied exactly as the
    /// reference's `allowedClockSkewMs`: expiry tolerated within `now - skew`
    /// and `not_before` honored within `now + skew`. Zero reproduces the
    /// exact-boundary behavior.
    pub allowed_clock_skew_ms: i64,
}

fn parse_ms(ts: &str) -> Option<i64> {
    let parsed =
        time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339).ok()?;
    Some((parsed.unix_timestamp_nanos() / 1_000_000) as i64)
}

/// The exact agent signed-bytes preimage: legacy canonical of the passport
/// value. Exposed so oracles and callers can hash or compare it.
pub fn agent_signature_preimage(passport: &Value) -> Result<String, crate::jcs::JcsError> {
    legacy_canonical::canonicalize(passport)
}

/// The exact issuer countersignature preimage: legacy canonical of
/// `{passport, signature, signedAt}` taken from the signed envelope.
pub fn issuer_signature_preimage(signed: &Value) -> Result<String, crate::jcs::JcsError> {
    let mut payload = Map::new();
    payload.insert(
        "passport".to_string(),
        signed.get("passport").cloned().unwrap_or(Value::Null),
    );
    payload.insert(
        "signature".to_string(),
        signed.get("signature").cloned().unwrap_or(Value::Null),
    );
    payload.insert(
        "signedAt".to_string(),
        signed.get("signedAt").cloned().unwrap_or(Value::Null),
    );
    legacy_canonical::canonicalize(&Value::Object(payload))
}

/// Verify an issuer countersignature against one expected issuer key,
/// matching the reference `verifyIssuerSignature`: the stored
/// `issuerPublicKey` must equal `issuer_public_key` and the signature must
/// verify over the issuer preimage.
pub fn verify_issuer_signature(signed: &Value, issuer_public_key: &str) -> bool {
    let Some(issuer) = signed.get("issuerSignature").and_then(Value::as_object) else {
        return false;
    };
    if issuer.get("issuerPublicKey").and_then(Value::as_str) != Some(issuer_public_key) {
        return false;
    }
    let Some(signature) = issuer.get("signature").and_then(Value::as_str) else {
        return false;
    };
    let Ok(payload) = issuer_signature_preimage(signed) else {
        return false;
    };
    verify_ed25519(payload.as_bytes(), signature, issuer_public_key)
}

/// Verify a signed passport at an explicit evaluation time.
///
/// Checks, in the reference order: envelope shape, agent signature over the
/// legacy canonical passport, issuer countersignature against the trusted
/// set (or the structural-only warning when the set is empty), the expiry
/// and not-before boundaries, required identity fields, and embedded
/// delegation observations (warnings only).
///
/// Returns an error only when `evaluation_time` itself cannot be parsed;
/// every finding about the passport is reported in the result.
pub fn verify_passport(
    signed: &Value,
    options: &PassportVerifyOptions<'_>,
) -> Result<PassportVerification, legacy_canonical::TimestampError> {
    let now_ms = parse_ms(options.evaluation_time).ok_or(legacy_canonical::TimestampError)?;
    let skew = options.allowed_clock_skew_ms;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let Some(envelope) = signed.as_object() else {
        return Ok(PassportVerification {
            valid: false,
            errors: vec![PassportError::MissingPassportOrSignature],
            warnings,
        });
    };
    let passport = envelope.get("passport");
    let signature = envelope.get("signature").and_then(Value::as_str);
    let (Some(passport), Some(signature)) = (passport, signature) else {
        return Ok(PassportVerification {
            valid: false,
            errors: vec![PassportError::MissingPassportOrSignature],
            warnings,
        });
    };
    if passport.is_null() || signature.is_empty() {
        return Ok(PassportVerification {
            valid: false,
            errors: vec![PassportError::MissingPassportOrSignature],
            warnings,
        });
    }

    let public_key = passport
        .get("publicKey")
        .and_then(Value::as_str)
        .unwrap_or("");
    let signature_ok = match agent_signature_preimage(passport) {
        Ok(canonical) => verify_ed25519(canonical.as_bytes(), signature, public_key),
        Err(_) => false,
    };
    if !signature_ok {
        errors.push(PassportError::InvalidSignature);
    }

    if options.trusted_issuers.is_empty() {
        warnings.push(PassportWarning::NoTrustedIssuers);
    } else {
        let issuer = envelope.get("issuerSignature").and_then(Value::as_object);
        let issuer_signature = issuer.and_then(|i| i.get("signature").and_then(Value::as_str));
        let issuer_key = issuer.and_then(|i| i.get("issuerPublicKey").and_then(Value::as_str));
        match (issuer_signature, issuer_key) {
            (Some(issuer_signature), Some(issuer_key))
                if !issuer_signature.is_empty() && !issuer_key.is_empty() =>
            {
                if !options.trusted_issuers.iter().any(|k| k == issuer_key) {
                    errors.push(PassportError::UntrustedIssuer);
                } else {
                    let issuer_ok = match issuer_signature_preimage(signed) {
                        Ok(payload) => {
                            verify_ed25519(payload.as_bytes(), issuer_signature, issuer_key)
                        }
                        Err(_) => false,
                    };
                    if !issuer_ok {
                        errors.push(PassportError::InvalidIssuerCountersignature);
                    }
                }
            }
            _ => errors.push(PassportError::NoIssuerCountersignature),
        }
    }

    // Temporal boundaries, explicit-clock semantics. Unparseable or absent
    // timestamps skip the check, exactly as the reference skips a NaN parse.
    if let Some(expiry_ms) = passport
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(parse_ms)
    {
        if expiry_ms < now_ms - skew {
            errors.push(PassportError::Expired);
        }
    }
    if let Some(nbf_ms) = passport
        .get("notBefore")
        .and_then(Value::as_str)
        .and_then(parse_ms)
    {
        if nbf_ms > now_ms + skew {
            errors.push(PassportError::NotYetValid);
        }
    }

    if passport
        .get("version")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        warnings.push(PassportWarning::NoVersion);
    }
    if passport
        .get("agentId")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        errors.push(PassportError::MissingAgentId);
    }
    if public_key.is_empty() {
        errors.push(PassportError::MissingPublicKey);
    }
    let capabilities_empty = passport
        .get("capabilities")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty);
    if capabilities_empty {
        warnings.push(PassportWarning::NoCapabilities);
    }

    // Embedded delegations produce warnings only, at the same evaluation
    // time. The reference's truthiness gate on spend fields is preserved: a
    // zero spend limit or zero spent amount never triggers the warning.
    if let Some(delegations) = passport.get("delegations").and_then(Value::as_array) {
        for delegation in delegations {
            if let Some(expiry_ms) = delegation
                .get("expiresAt")
                .and_then(Value::as_str)
                .and_then(parse_ms)
            {
                if expiry_ms < now_ms {
                    warnings.push(PassportWarning::DelegationExpired);
                }
            }
            let limit = delegation.get("spendLimit").and_then(Value::as_f64);
            let spent = delegation.get("spentAmount").and_then(Value::as_f64);
            if let (Some(limit), Some(spent)) = (limit, spent) {
                if limit != 0.0 && spent != 0.0 && spent >= limit {
                    warnings.push(PassportWarning::DelegationSpendExhausted);
                }
            }
        }
    }

    Ok(PassportVerification {
        valid: errors.is_empty(),
        errors,
        warnings,
    })
}
