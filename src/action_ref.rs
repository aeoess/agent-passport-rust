//! `action_ref`: the content-addressed request identity, per
//! draft-pidlisnyi-aps-03 section 4.1.
//!
//! Parity target: `computeActionRef` and `canonicalizeScopeRequired` in the
//! reference TypeScript SDK (`src/core/action-ref.ts`) and the frozen
//! `actionref-canonical-fixture-v1.json` vectors. Two receipts with the same
//! `action_ref` describe the same request.

use unicode_normalization::UnicodeNormalization;

/// `scope_required` violates section 4.1: the array holds two elements that
/// are equal after NFC normalization. A duplicated array has no canonical
/// form and is rejected rather than deduplicated: an equality key must not
/// map distinct inputs onto one value silently. The duplicate value is never
/// included in the message.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActionRefError {
    /// Duplicate `scope_required` elements after NFC normalization.
    /// Category `invalid_scope_required`, reason `duplicate_scope_required`,
    /// shared across the APS SDKs.
    #[error("action_ref: scope_required contains duplicate elements after NFC normalization (duplicate_scope_required)")]
    DuplicateScopeRequired,
    /// `created_at` is not a parseable RFC 3339 timestamp.
    #[error("action_ref: invalid timestamp")]
    InvalidTimestamp,
}

/// Canonicalize a `scope_required` array per section 4.1: NFC-normalize each
/// scope string, reject duplicates detected after normalization (so two
/// spellings that collide only under NFC reject as well), then sort by
/// Unicode code point. The input slice is never mutated; the result is a
/// fresh vector. No case folding: scopes differing only in case stay
/// distinct.
///
/// The code-point sort intentionally differs from the UTF-16 code-unit order
/// used for JCS object keys: this sort is a pre-canonicalization step defined
/// by the spec, not part of RFC 8785. For valid UTF-8, Rust's default string
/// ordering is byte order, which equals code-point order.
pub fn canonicalize_scopes(scope_required: &[String]) -> Result<Vec<String>, ActionRefError> {
    let mut scopes: Vec<String> = scope_required
        .iter()
        .map(|s| s.nfc().collect::<String>())
        .collect();
    let mut seen = std::collections::HashSet::with_capacity(scopes.len());
    for scope in &scopes {
        if !seen.insert(scope.clone()) {
            return Err(ActionRefError::DuplicateScopeRequired);
        }
    }
    scopes.sort();
    Ok(scopes)
}

/// Compute the lowercase-hex SHA-256 `action_ref` for an intent whose
/// `scope_required` is an array of scope strings, the section 4.1 shape.
///
/// The preimage is strict JCS (RFC 8785, nulls preserved) over
/// `{ agentId, actionType, scopeRequired, timestamp }`, where the scopes are
/// canonicalized by [`canonicalize_scopes`] and `created_at` is normalized to
/// second-precision UTC. Callers supplying the same scopes in a different
/// order or a different Unicode normalization form produce the same
/// `action_ref`. The caller's slice is not mutated.
///
/// Returns [`ActionRefError::DuplicateScopeRequired`] before any digest is
/// computed, so a duplicated array can never present as an identity mismatch
/// downstream: there is no `action_ref` to compare in the first place.
pub fn compute_action_ref_scopes(
    agent_id: &str,
    action_type: &str,
    scope_required: &[String],
    created_at: &str,
) -> Result<String, ActionRefError> {
    let timestamp = crate::legacy_canonical::normalize_timestamp(created_at)
        .map_err(|_| ActionRefError::InvalidTimestamp)?;
    let scopes = canonicalize_scopes(scope_required)?;
    let preimage = serde_json::json!({
        "agentId": agent_id,
        "actionType": action_type,
        "scopeRequired": scopes,
        "timestamp": timestamp,
    });
    // The preimage is built from validated scalar strings; strict JCS over it
    // cannot fail, and a failure here would be a crate defect, not bad input.
    crate::jcs::canonical_hash(&preimage).map_err(|_| ActionRefError::InvalidTimestamp)
}

/// Two receipts with the same `action_ref` describe the same request. A
/// named predicate so the semantic intent is explicit at the call site;
/// empty strings never match.
pub fn action_refs_match(a: &str, b: &str) -> bool {
    !a.is_empty() && a == b
}
