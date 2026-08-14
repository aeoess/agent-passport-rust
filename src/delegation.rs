//! Legacy APS delegation verification: single-delegation checks, scope
//! coverage, and root-to-leaf chain verification.
//!
//! Parity targets: `verifyDelegation`, `scopeCovers`, and `scopeAuthorizes`
//! in the reference `src/core/delegation.ts`, and `VerifyDelegationChain` in
//! the Go implementation (`verify/verify.go`), which carries the chain rules
//! the reference moved to its gateway store.
//!
//! Profile: a delegation signs over the legacy canonical form of itself with
//! the `signature` member removed, verified against the `delegatedBy` public
//! key. Delegations travel as raw [`serde_json::Value`] so the preimage
//! covers exactly the members the signer included.
//!
//! Out of scope in wave 1, recorded rather than merged: revocation state
//! (the reference draws it from a caller-supplied cache or the gateway
//! store) and the separate a2a-1496 composition-map chain profile with its
//! own field names and refusal codes.
//!
//! Structural checks and authorization are distinct operations with distinct
//! result types: [`verify_chain_structure`] proves narrowing shape only,
//! while [`verify_chain_authorization`] additionally requires every hop
//! signature to verify, every hop to be active at the explicit evaluation
//! time, and the root delegator to be explicitly trusted.

use serde_json::Value;

use crate::crypto::verify_ed25519;
use crate::legacy_canonical::{self, TimestampError};

/// Scope coverage, the single source of truth ported verbatim: exact match,
/// the `*` universal wildcard, hierarchical prefix (`code` covers
/// `code:deploy`), and the `prefix:*` segment wildcard (covering `prefix`
/// and `prefix:child`). Never the reverse: a child scope does not satisfy
/// its parent.
pub fn scope_covers(granted: &str, required: &str) -> bool {
    if granted == required || granted == "*" {
        return true;
    }
    if required.starts_with(&format!("{granted}:")) {
        return true;
    }
    if let Some(prefix) = granted.strip_suffix(":*") {
        if required == prefix || required.starts_with(&format!("{prefix}:")) {
            return true;
        }
    }
    false
}

/// True when any granted scope covers the required scope.
pub fn scope_authorizes(delegation_scope: &[String], required: &str) -> bool {
    delegation_scope.iter().any(|s| scope_covers(s, required))
}

/// The exact signed-bytes preimage for a delegation: legacy canonical of the
/// object with its `signature` member removed.
pub fn delegation_signature_preimage(delegation: &Value) -> Result<String, crate::jcs::JcsError> {
    let mut unsigned = delegation.as_object().cloned().unwrap_or_default();
    unsigned.remove("signature");
    legacy_canonical::canonicalize(&Value::Object(unsigned))
}

/// Verify the delegation signature against the `delegatedBy` public key.
/// Returns false for a non-object value or missing members.
pub fn verify_delegation_signature(delegation: &Value) -> bool {
    let Some(object) = delegation.as_object() else {
        return false;
    };
    let Some(signature) = object.get("signature").and_then(Value::as_str) else {
        return false;
    };
    let Some(delegated_by) = object.get("delegatedBy").and_then(Value::as_str) else {
        return false;
    };
    let Ok(canonical) = delegation_signature_preimage(delegation) else {
        return false;
    };
    verify_ed25519(canonical.as_bytes(), signature, delegated_by)
}

/// A single-delegation check failure. Stable categories; no payload content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    /// The value is not a JSON object.
    #[error("invalid delegation: not an object")]
    NotAnObject,
    /// The signature does not verify against `delegatedBy`.
    #[error("invalid delegation signature")]
    InvalidSignature,
    /// `expiresAt` is missing or unparseable; the delegation fails closed as
    /// expired, matching the reference.
    #[error("invalid expiresAt")]
    InvalidExpiry,
    /// The delegation expired before the evaluation time.
    #[error("delegation expired")]
    Expired,
    /// `notBefore` is present but unparseable.
    #[error("invalid notBefore")]
    InvalidNotBefore,
    /// The delegation is not yet valid at the evaluation time.
    #[error("delegation not yet valid")]
    NotYetValid,
    /// `currentDepth` exceeds `maxDepth`.
    #[error("depth limit exceeded")]
    DepthExceeded,
}

/// Outcome of [`verify_delegation`], mirroring the reference
/// `DelegationStatus` flags. `valid` is true exactly when `errors` is empty.
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationStatus {
    /// True when no check failed.
    pub valid: bool,
    /// The delegation is past expiry (or its expiry is unusable).
    pub expired: bool,
    /// The delegation has not reached its `notBefore` yet.
    pub not_yet_valid: bool,
    /// `currentDepth` exceeds `maxDepth`.
    pub depth_exceeded: bool,
    /// Every check that failed.
    pub errors: Vec<DelegationError>,
}

fn parse_ms(ts: &str) -> Option<i64> {
    let parsed =
        time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339).ok()?;
    Some((parsed.unix_timestamp_nanos() / 1_000_000) as i64)
}

/// Verify one delegation at an explicit evaluation time: signature over the
/// legacy preimage, expiry (missing or unparseable fails closed as expired),
/// optional `notBefore`, and the depth bound. Boundary semantics match the
/// reference: expired only when `expiresAt` is strictly earlier than the
/// evaluation time; not yet valid only when `notBefore` is strictly later.
/// Equality on either boundary is live.
///
/// Returns an error only when `evaluation_time` itself cannot be parsed.
pub fn verify_delegation(
    delegation: &Value,
    evaluation_time: &str,
) -> Result<DelegationStatus, TimestampError> {
    let now_ms = parse_ms(evaluation_time).ok_or(TimestampError)?;
    let Some(object) = delegation.as_object() else {
        return Ok(DelegationStatus {
            valid: false,
            expired: false,
            not_yet_valid: false,
            depth_exceeded: false,
            errors: vec![DelegationError::NotAnObject],
        });
    };
    let mut errors = Vec::new();

    if !verify_delegation_signature(delegation) {
        errors.push(DelegationError::InvalidSignature);
    }

    let mut expired = false;
    match object
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(parse_ms)
    {
        None => {
            errors.push(DelegationError::InvalidExpiry);
            expired = true;
        }
        Some(expiry_ms) if expiry_ms < now_ms => {
            errors.push(DelegationError::Expired);
            expired = true;
        }
        Some(_) => {}
    }

    let mut not_yet_valid = false;
    if let Some(not_before) = object.get("notBefore").and_then(Value::as_str) {
        match parse_ms(not_before) {
            None => errors.push(DelegationError::InvalidNotBefore),
            Some(nbf_ms) if nbf_ms > now_ms => {
                errors.push(DelegationError::NotYetValid);
                not_yet_valid = true;
            }
            Some(_) => {}
        }
    }

    // The depth bound trips only when both depths are present numbers,
    // matching the reference where a comparison against an absent member is
    // never true.
    let current = object.get("currentDepth").and_then(Value::as_f64);
    let max = object.get("maxDepth").and_then(Value::as_f64);
    let depth_exceeded = matches!((current, max), (Some(c), Some(m)) if c > m);
    if depth_exceeded {
        errors.push(DelegationError::DepthExceeded);
    }

    Ok(DelegationStatus {
        valid: errors.is_empty(),
        expired,
        not_yet_valid,
        depth_exceeded,
        errors,
    })
}

/// A chain violation. Stable categories; `hop` is the zero-based index of
/// the offending link (for pairwise rules, the child's index).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// The chain has no links.
    #[error("chain is empty")]
    EmptyChain,
    /// A link is not a JSON object.
    #[error("chain link {hop} is not an object")]
    NotAnObject {
        /// Index of the offending link.
        hop: usize,
    },
    /// `child.delegatedBy` does not equal `parent.delegatedTo`.
    #[error("chain linkage broken at hop {hop}")]
    BrokenLinkage {
        /// Index of the child link.
        hop: usize,
    },
    /// `child.currentDepth` is not `parent.currentDepth + 1`.
    #[error("depth not monotonic at hop {hop}")]
    DepthNotMonotonic {
        /// Index of the child link.
        hop: usize,
    },
    /// The child's depth exceeds the parent's `maxDepth`.
    #[error("depth limit exceeded at hop {hop}")]
    DepthLimitExceeded {
        /// Index of the child link.
        hop: usize,
    },
    /// A child scope is not covered by any parent scope.
    #[error("scope widening at hop {hop}")]
    ScopeWidening {
        /// Index of the child link.
        hop: usize,
    },
    /// The child's spend limit exceeds the parent's.
    #[error("spend limit widening at hop {hop}")]
    SpendLimitWidening {
        /// Index of the child link.
        hop: usize,
    },
    /// The child changed or dropped the parent's spend unit.
    #[error("spend unit change at hop {hop}")]
    SpendUnitChanged {
        /// Index of the child link.
        hop: usize,
    },
    /// A non-empty expiry failed to parse; the chain fails closed.
    #[error("expiry unparseable at hop {hop}")]
    ExpiryUnparseable {
        /// Index of the offending link.
        hop: usize,
    },
    /// The child outlives its parent, or drops an expiry the parent has.
    #[error("expiry widening at hop {hop}")]
    ExpiryWidening {
        /// Index of the child link.
        hop: usize,
    },
    /// Authorization only: a hop signature does not verify.
    #[error("invalid signature at hop {hop}")]
    InvalidSignature {
        /// Index of the offending link.
        hop: usize,
    },
    /// Authorization only: a hop is expired, not yet valid, or otherwise
    /// invalid at the evaluation time.
    #[error("hop {hop} inactive at the evaluation time")]
    HopInactive {
        /// Index of the offending link.
        hop: usize,
    },
    /// Authorization only: the root delegator is not in the trusted set.
    #[error("root delegator is not trusted")]
    UntrustedRoot,
}

fn str_field<'a>(link: &'a Value, key: &str) -> &'a str {
    link.get(key).and_then(Value::as_str).unwrap_or("")
}

fn scopes_of(link: &Value) -> Vec<String> {
    link.get("scope")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn depth_of(link: &Value, key: &str) -> Option<f64> {
    link.get(key).and_then(Value::as_f64)
}

/// Structural narrowing verification of a root-to-leaf chain, ported from
/// the Go `VerifyDelegationChain`. Proves shape only: linkage, strict depth
/// increment within the parent's `maxDepth`, scope coverage, spend limit and
/// unit narrowing, and temporal narrowing with unparseable expiries failing
/// closed. It checks no signature, no trust, and no evaluation time; use
/// [`verify_chain_authorization`] for an authorization decision.
pub fn verify_chain_structure(chain: &[Value]) -> Result<(), ChainError> {
    if chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }
    for (index, link) in chain.iter().enumerate() {
        if !link.is_object() {
            return Err(ChainError::NotAnObject { hop: index });
        }
    }
    for hop in 1..chain.len() {
        let parent = &chain[hop - 1];
        let child = &chain[hop];
        if str_field(child, "delegatedBy") != str_field(parent, "delegatedTo") {
            return Err(ChainError::BrokenLinkage { hop });
        }
        let parent_depth = depth_of(parent, "currentDepth").unwrap_or(0.0);
        let child_depth = depth_of(child, "currentDepth").unwrap_or(0.0);
        if child_depth != parent_depth + 1.0 {
            return Err(ChainError::DepthNotMonotonic { hop });
        }
        if let Some(max_depth) = depth_of(parent, "maxDepth") {
            if child_depth > max_depth {
                return Err(ChainError::DepthLimitExceeded { hop });
            }
        }
        let parent_scope = scopes_of(parent);
        for scope in scopes_of(child) {
            if !scope_authorizes(&parent_scope, &scope) {
                return Err(ChainError::ScopeWidening { hop });
            }
        }
        let parent_limit = parent.get("spendLimit").and_then(Value::as_f64);
        let child_limit = child.get("spendLimit").and_then(Value::as_f64);
        if let (Some(parent_limit), Some(child_limit)) = (parent_limit, child_limit) {
            if child_limit > parent_limit {
                return Err(ChainError::SpendLimitWidening { hop });
            }
        }
        let parent_unit = str_field(parent, "spendLimitUnit");
        let child_unit = str_field(child, "spendLimitUnit");
        if !parent_unit.is_empty() && child_limit.is_some() && child_unit != parent_unit {
            return Err(ChainError::SpendUnitChanged { hop });
        }
        let parent_expiry = match parent.get("expiresAt").and_then(Value::as_str) {
            Some(raw) if !raw.is_empty() => {
                Some(parse_ms(raw).ok_or(ChainError::ExpiryUnparseable { hop: hop - 1 })?)
            }
            _ => None,
        };
        let child_expiry = match child.get("expiresAt").and_then(Value::as_str) {
            Some(raw) if !raw.is_empty() => {
                Some(parse_ms(raw).ok_or(ChainError::ExpiryUnparseable { hop })?)
            }
            _ => None,
        };
        if let Some(parent_expiry) = parent_expiry {
            match child_expiry {
                None => return Err(ChainError::ExpiryWidening { hop }),
                Some(child_expiry) if child_expiry > parent_expiry => {
                    return Err(ChainError::ExpiryWidening { hop })
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// Proof token returned by [`verify_chain_authorization`]. Deliberately a
/// distinct type from the unit result of [`verify_chain_structure`], so a
/// structural pass can never be mistaken for an authorization pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainAuthorization {
    /// Number of links the authorization covered.
    pub hops: usize,
}

/// Authorization verification of a root-to-leaf chain at an explicit
/// evaluation time. On top of [`verify_chain_structure`] it requires:
///
/// - the root's `delegatedBy` to be present in `trusted_roots` (a chain can
///   never authorize on the strength of a self-minted root)
/// - every hop's signature to verify over the legacy preimage
/// - every hop to be fully valid at `evaluation_time` per
///   [`verify_delegation`] (active window, depth bound)
///
/// Returns an error only when `evaluation_time` itself cannot be parsed;
/// chain findings are the `Err(ChainError)` arm of the inner result.
pub fn verify_chain_authorization(
    chain: &[Value],
    trusted_roots: &[String],
    evaluation_time: &str,
) -> Result<Result<ChainAuthorization, ChainError>, TimestampError> {
    parse_ms(evaluation_time).ok_or(TimestampError)?;
    if chain.is_empty() {
        return Ok(Err(ChainError::EmptyChain));
    }
    let root_delegator = str_field(&chain[0], "delegatedBy");
    if root_delegator.is_empty() || !trusted_roots.iter().any(|r| r == root_delegator) {
        return Ok(Err(ChainError::UntrustedRoot));
    }
    if let Err(violation) = verify_chain_structure(chain) {
        return Ok(Err(violation));
    }
    for (hop, link) in chain.iter().enumerate() {
        if !verify_delegation_signature(link) {
            return Ok(Err(ChainError::InvalidSignature { hop }));
        }
        let status = verify_delegation(link, evaluation_time)?;
        if !status.valid {
            return Ok(Err(ChainError::HopInactive { hop }));
        }
    }
    Ok(Ok(ChainAuthorization { hops: chain.len() }))
}
