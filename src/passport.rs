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
//! Trust: a signature over a passport says who signed it, not who vouches for
//! it. The verifying key is the one the passport carries, so a good signature
//! is available to anyone who can generate a key pair. An empty
//! `trusted_issuers` list therefore establishes integrity and NOT authority,
//! and is an error unless the caller sets `allow_self_signed`, which is the
//! deliberate opt-in and carries [`PassportWarning::NoTrustedIssuers`] to say
//! no trust root was consulted. Verification success and issuer-trust success
//! are reported separately, never merged into one bool: the result carries
//! `issuer_trust_checked` and `self_signed_accepted` alongside `valid`.
//!
//! This is the contract the reference now applies too. The comment here used
//! to claim the same WARNING contract as the reference; the reference changed,
//! and an empty list is no longer an admission in any of the four SDKs.
//!
//! Time: no wall clock. [`verify_passport`] takes an explicit RFC 3339
//! evaluation time and applies the reference's explicit-clock boundary
//! semantics: expired only when `expires_at` is strictly earlier than the
//! evaluation time minus the allowed skew, and not yet valid only when
//! `not_before` is strictly later than the evaluation time plus the skew.
//! Equality on either boundary is live. A present but unreadable
//! `expiresAt`/`notBefore` is an error of its own
//! ([`PassportError::InvalidExpiry`], [`PassportError::InvalidNotBefore`]),
//! never a skipped check: a limit this verifier cannot read is not a limit it
//! can honour. `expiresAt` is required by the profile, so an absent one is
//! `InvalidExpiry` too; `notBefore` is optional, so an absent one leaves the
//! lower edge of the window open. The reference draws both lines the same way,
//! and reports the unreadable case separately from the case where a limit was
//! read and found to have passed.

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
    /// `expires_at` is present but is not a string, or is a string that is not
    /// an RFC 3339 instant. Distinct from [`PassportError::Expired`]: that one
    /// reports a limit this verifier read and found to have passed, this one
    /// reports that it never read a limit at all. An expiry a verifier cannot
    /// read is not an expiry it can honour.
    #[error("invalid expiresAt")]
    InvalidExpiry,
    /// `not_before` is later than the evaluation time (plus skew).
    #[error("passport not yet valid")]
    NotYetValid,
    /// `not_before` is present but is not a string, or is a string that is not
    /// an RFC 3339 instant. Distinct from [`PassportError::NotYetValid`]: the
    /// verifier has seen no evidence that the window has opened, which is a
    /// different claim from having seen a start date still in the future.
    #[error("invalid notBefore")]
    InvalidNotBefore,
    /// `agentId` is missing or empty.
    #[error("missing agentId")]
    MissingAgentId,
    /// `publicKey` is missing or empty.
    #[error("missing publicKey")]
    MissingPublicKey,
    /// No trusted issuers were supplied and the caller did not opt in to
    /// self-signed acceptance, so nothing established who vouches for this
    /// passport. Distinct from every error above: those report something the
    /// verifier read and found wrong, this reports a question nobody asked.
    #[error("authority not established: supply trusted_issuers, or set allow_self_signed")]
    AuthorityNotEstablished,
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
    /// An embedded delegation carries an `expiresAt` that is not a string, or
    /// is a string that is not an RFC 3339 instant. Reported separately from
    /// [`PassportWarning::DelegationExpired`] so an operator can tell a
    /// delegation whose limit has passed from one whose limit could not be
    /// read; the second usually means a broken producer, not a stale grant.
    DelegationInvalidExpiry,
    /// An embedded delegation has spent its full spend limit.
    DelegationSpendExhausted,
}

/// Outcome of [`verify_passport`]. `valid` is true exactly when `errors` is
/// empty; warnings never affect it. With no trusted issuers and no opt-in the
/// result is not valid and carries
/// [`PassportError::AuthorityNotEstablished`]; with the opt-in it is valid,
/// `self_signed_accepted` is set, and [`PassportWarning::NoTrustedIssuers`]
/// records that no trust root was consulted.
#[derive(Debug, Clone, PartialEq)]
pub struct PassportVerification {
    /// True when no error was recorded.
    pub valid: bool,
    /// Every check that failed.
    pub errors: Vec<PassportError>,
    /// Non-fatal observations, including the structural-only marker.
    pub warnings: Vec<PassportWarning>,
    /// Whether an issuer-trust check ran at all, that is, whether a non-empty
    /// `trusted_issuers` list was supplied.
    pub issuer_trust_checked: bool,
    /// Whether this verdict was reached with no trust root consulted, which
    /// happens only when the caller set `allow_self_signed`. A caller that
    /// must not act on a self-vouching passport branches on this rather than
    /// on the presence of a warning.
    pub self_signed_accepted: bool,
}

/// Inputs for [`verify_passport`].
#[derive(Debug, Clone)]
pub struct PassportVerifyOptions<'a> {
    /// Issuer public keys (hex) whose countersignature makes a passport
    /// authority-issued. An empty list holds no anchors; it does not mean
    /// "trust anyone", and on its own it is not an admission.
    pub trusted_issuers: &'a [String],
    /// Accept a passport carrying no trusted countersignature, on its own
    /// signature alone. False is the safe default and the one to keep unless
    /// the calling path is explicitly integrity-only. Consulted only when
    /// `trusted_issuers` is empty: a caller that named issuers asked for that
    /// check, and this flag does not rescue a failed one.
    pub allow_self_signed: bool,
    /// RFC 3339 evaluation time. There is no wall-clock fallback.
    pub evaluation_time: &'a str,
    /// Uniform clock skew in milliseconds, applied exactly as the
    /// reference's `allowedClockSkewMs`: expiry tolerated within `now - skew`
    /// and `not_before` honored within `now + skew`. Zero reproduces the
    /// exact-boundary behavior. Unsigned by construction, so a negative
    /// allowance cannot exist; a skew whose application would leave the i64
    /// millisecond domain is the typed
    /// [`PassportInputError::SkewArithmetic`], never a wrap or a panic.
    /// This unsigned domain is a deliberate Rust-side restriction of the
    /// verifier OPTIONS API only; it does not change how any signed
    /// artifact is interpreted.
    pub allowed_clock_skew_ms: u64,
}

/// Input-domain failure of [`verify_passport`]: the verifier options could
/// not be applied. Distinct from findings about the passport itself, which
/// are always reported inside [`PassportVerification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PassportInputError {
    /// `evaluation_time` is not a valid RFC 3339 timestamp.
    #[error("evaluation time is not a valid RFC 3339 timestamp")]
    InvalidEvaluationTime,
    /// `allowed_clock_skew_ms` cannot be applied to the evaluation time
    /// without leaving the i64 millisecond domain.
    #[error("allowed clock skew cannot be applied to the evaluation time")]
    SkewArithmetic,
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
/// Returns an error only when the verifier inputs are unusable: an
/// unparseable `evaluation_time`, or a skew that cannot be applied within
/// the i64 millisecond domain. Every finding about the passport itself is
/// reported in the result.
pub fn verify_passport(
    signed: &Value,
    options: &PassportVerifyOptions<'_>,
) -> Result<PassportVerification, PassportInputError> {
    let now_ms =
        parse_ms(options.evaluation_time).ok_or(PassportInputError::InvalidEvaluationTime)?;
    // Checked conversion and checked boundary arithmetic: the skew is
    // unsigned, so only overflow past the i64 domain can fail, and it fails
    // as a typed error before any verdict is formed.
    let skew = i64::try_from(options.allowed_clock_skew_ms)
        .map_err(|_| PassportInputError::SkewArithmetic)?;
    let expiry_floor = now_ms
        .checked_sub(skew)
        .ok_or(PassportInputError::SkewArithmetic)?;
    let not_before_ceiling = now_ms
        .checked_add(skew)
        .ok_or(PassportInputError::SkewArithmetic)?;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let Some(envelope) = signed.as_object() else {
        return Ok(PassportVerification {
            valid: false,
            errors: vec![PassportError::MissingPassportOrSignature],
            warnings,
            issuer_trust_checked: false,
            self_signed_accepted: false,
        });
    };
    let passport = envelope.get("passport");
    let signature = envelope.get("signature").and_then(Value::as_str);
    let (Some(passport), Some(signature)) = (passport, signature) else {
        return Ok(PassportVerification {
            valid: false,
            errors: vec![PassportError::MissingPassportOrSignature],
            warnings,
            issuer_trust_checked: false,
            self_signed_accepted: false,
        });
    };
    if passport.is_null() || signature.is_empty() {
        return Ok(PassportVerification {
            valid: false,
            errors: vec![PassportError::MissingPassportOrSignature],
            warnings,
            issuer_trust_checked: false,
            self_signed_accepted: false,
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

    let issuer_trust_checked = !options.trusted_issuers.is_empty();
    let mut self_signed_accepted = false;
    if !issuer_trust_checked {
        if options.allow_self_signed {
            self_signed_accepted = true;
            warnings.push(PassportWarning::NoTrustedIssuers);
        } else {
            // Integrity is established above and reported above. Authority is
            // the caller's to supply, and without it there is nothing here to
            // be valid about.
            errors.push(PassportError::AuthorityNotEstablished);
        }
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

    // Temporal boundaries, explicit-clock semantics. A timestamp that is
    // present but unreadable fails closed, in the same shape `verify_delegation`
    // already uses: an expiry this verifier cannot read is not an expiry it can
    // honour, and skipping the comparison would make writing garbage into the
    // field strictly better for the holder than writing an honest date. The
    // failure is reported under its own variant rather than as Expired, because
    // "the limit had passed" and "there was no readable limit" are different
    // findings and an operator acts on them differently.
    // `expiresAt` is a required member of the profile (`expiresAt: string` in
    // the reference type, no `?`), so an absent one is not an open-ended window,
    // it is a passport that never stated a limit. Reporting nothing would make
    // omitting the field the cheapest way to mint an eternal passport, which is
    // the same defect as writing garbage into it by a shorter route.
    match passport
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(parse_ms)
    {
        None => errors.push(PassportError::InvalidExpiry),
        Some(expiry_ms) => {
            if expiry_ms < expiry_floor {
                errors.push(PassportError::Expired);
            }
        }
    }
    // notBefore is optional: absent leaves the lower edge of the window open.
    // Present but unreadable is an error, for the same reason as above.
    match passport.get("notBefore") {
        None => {}
        Some(value) => match value.as_str().and_then(parse_ms) {
            None => errors.push(PassportError::InvalidNotBefore),
            Some(nbf_ms) => {
                if nbf_ms > not_before_ceiling {
                    errors.push(PassportError::NotYetValid);
                }
            }
        },
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
            match delegation.get("expiresAt") {
                None => {}
                Some(value) => match value.as_str().and_then(parse_ms) {
                    None => warnings.push(PassportWarning::DelegationInvalidExpiry),
                    Some(expiry_ms) => {
                        if expiry_ms < now_ms {
                            warnings.push(PassportWarning::DelegationExpired);
                        }
                    }
                },
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

    let valid = errors.is_empty();
    Ok(PassportVerification {
        valid,
        errors,
        warnings,
        issuer_trust_checked,
        // True only when the caller opted in AND the verdict held.
        self_signed_accepted: self_signed_accepted && valid,
    })
}
