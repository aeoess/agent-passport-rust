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
//! Revocation state arrives from OUTSIDE the artifact, through a caller
//! supplied resolver ([`verify_chain_authorization_with_revocation`]). It is
//! never a member of a chain link: links are signed wire objects and adding a
//! member would change the bytes the delegator signed. Out of scope, recorded
//! rather than merged: the separate a2a-1496 composition-map chain profile
//! with its own field names and refusal codes.
//!
//! Structural checks and authorization are distinct operations with distinct
//! result types: [`verify_chain_structure`] proves narrowing shape only,
//! while [`verify_chain_authorization`] additionally requires every hop
//! signature to verify, every hop to be active at the explicit evaluation
//! time, and the root delegator to be explicitly trusted. Neither claims
//! anything about revocation; [`verify_chain_authorization_with_revocation`]
//! is the one that does, and it reports INDETERMINATE rather than a positive
//! verdict when the resolver cannot answer.

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
/// LENIENT PROFILE, deliberate and pinned. This single-delegation path mirrors
/// the TypeScript reference rather than the chain path's stricter domain, and
/// the difference is load bearing for parity:
///
/// - `currentDepth` and `maxDepth` are read with `as_f64`, so FRACTIONAL depths
///   are accepted and compared numerically (1.5 under a maxDepth of 3 is
///   valid), where [`verify_chain_structure`] requires integers.
/// - a `currentDepth` or `maxDepth` of the wrong TYPE (a string, a boolean) is
///   read as absent and the depth bound simply does not trip, where the chain
///   path reports `DepthNotAnInteger`.
/// - a non-string `notBefore` is skipped rather than refused.
/// - negative depths are accepted here; the chain path refuses them.
///
/// None of this can widen authority: the bound it can fail to impose is a
/// per-link depth bound, and every chain the authorization path accepts has
/// been through [`verify_chain_structure`] first, which applies the strict
/// domain to every link. Callers who want the strict domain on a single
/// delegation should run it as a one-link chain.
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
    /// A present `currentDepth` or `maxDepth` is not an integral JSON
    /// number representable in i64. The Go reference rejects these at
    /// deserialization (`*int`); at baseline a fractional chain such as
    /// -1.5 followed by -0.5 satisfied the +1 rule through f64 arithmetic.
    #[error("depth is not an integer at hop {hop}")]
    DepthNotAnInteger {
        /// Index of the offending link.
        hop: usize,
    },
    /// A `currentDepth` or `maxDepth` is below zero. `currentDepth` is a
    /// POSITION in a chain, so it is never negative, and the depth ceiling only
    /// bounds chain LENGTH once there is a floor: with `maxDepth` 2 and a root
    /// at `currentDepth` -5, an eight-link chain incremented by exactly one at
    /// every hop and stayed at or below the ceiling throughout. The rule held
    /// to the letter and failed in purpose.
    #[error("depth below zero at hop {hop}")]
    DepthBelowZero {
        /// Index of the offending link.
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
    /// A scope array carries a non-string, non-null element. The Go
    /// reference rejects this at deserialization (`Scope []string`) for
    /// every link of the chain; a verifier must never silently discard a
    /// scope member. A null element is not this error: Go's decoder leaves
    /// it at the string zero value, so it is kept as the inert empty
    /// string.
    #[error("scope element is not a string at hop {hop}")]
    ScopeElementNotAString {
        /// Index of the offending link.
        hop: usize,
    },
    /// The child's spend limit exceeds the effective inherited ceiling.
    #[error("spend limit widening at hop {hop}")]
    SpendLimitWidening {
        /// Index of the child link.
        hop: usize,
    },
    /// A present `spendLimit` is not a JSON number. The Go reference rejects
    /// these at deserialization (`*float64`). At baseline the ceiling was read
    /// through a bare `as_f64`, which yields `None` for a string, a boolean, an
    /// array, or an object, and `None` was indistinguishable from absent: a
    /// malformed ceiling silently disabled the check. An explicit JSON null is
    /// NOT this error; it is the absent case, as it is for depth.
    #[error("spend limit is not a number at hop {hop}")]
    SpendLimitNotANumber {
        /// Index of the offending link.
        hop: usize,
    },
    /// The child's `maxDepth` exceeds the effective inherited `maxDepth`.
    #[error("depth limit widening at hop {hop}")]
    DepthLimitWidening {
        /// Index of the child link.
        hop: usize,
    },
    /// A present `delegatedBy`, `delegatedTo`, `spendLimitUnit`, `expiresAt`,
    /// or `notBefore` is not a JSON string. The Go reference rejects these at
    /// deserialization (`string` fields). Reading them through
    /// `as_str().unwrap_or("")` turned a malformed member into the empty
    /// string, which disabled the unit check and made two links with non-string
    /// identities compare equal to each other in the linkage check.
    #[error("member is not a string at hop {hop}")]
    MemberNotAString {
        /// Index of the offending link.
        hop: usize,
    },
    /// A non-empty `notBefore` failed to parse; the chain fails closed.
    #[error("notBefore unparseable at hop {hop}")]
    NotBeforeUnparseable {
        /// Index of the offending link.
        hop: usize,
    },
    /// The child activates earlier than the effective inherited `notBefore`.
    #[error("activation widening at hop {hop}")]
    ActivationWidening {
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
    /// Authorization only: the resolver reported a hop revoked at the
    /// evaluation time.
    #[error("hop {hop} is revoked")]
    HopRevoked {
        /// Index of the revoked hop.
        hop: usize,
    },
    /// Authorization only: revocation state could not be established for a
    /// hop, so authorization is INDETERMINATE. This is not a positive
    /// authorization and not a refusal on the merits. Treating "cannot check"
    /// as "not revoked" is the fail-open this state exists to prevent.
    #[error("revocation state is indeterminate at hop {hop}")]
    RevocationIndeterminate {
        /// Index of the hop whose revocation state is unknown.
        hop: usize,
    },
}

fn str_field<'a>(link: &'a Value, key: &str) -> &'a str {
    link.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Checked scope extraction, the only place chain code reads `scope`.
///
/// An absent, null, or non-array `scope` member yields an empty list (the
/// Go reference accepts absent and null as a nil slice; the non-array case
/// is recorded in the phase 0 matrix as an instruction-limited leniency). A
/// scope ARRAY is extracted element by element: strings are kept, a JSON
/// null element becomes the inert empty string exactly as Go's decoder
/// leaves it, and any other element type is an error, never a silent
/// discard.
fn scopes_of(link: &Value) -> Result<Vec<String>, ()> {
    match link.get("scope") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(scope) => Ok(scope.clone()),
                Value::Null => Ok(String::new()),
                _ => Err(()),
            })
            .collect(),
        _ => Ok(Vec::new()),
    }
}

/// Checked string extraction, the only place chain code reads an identity,
/// a spend unit, or a timestamp.
///
/// Absent and null are the Go zero value (the empty string). A present member
/// must be a JSON string; any other type is an error, never a silent empty
/// string. Go rejects those at deserialization, and the empty string is load
/// bearing here: it disables the unit check and makes two links whose
/// identities are both malformed compare equal in the linkage check.
fn text_of<'a>(link: &'a Value, key: &str) -> Result<&'a str, ()> {
    match link.get(key) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(()),
    }
}

/// Checked spend-ceiling extraction, the only place chain code reads
/// `spendLimit`.
///
/// Absent and null are the Go nil default (no ceiling stated), exactly as for
/// depth. A present ceiling must be a JSON number; a string, boolean, array, or
/// object is an error. A malformed ceiling must FAIL rather than silently
/// disable the check, which is what a bare `as_f64` did by collapsing every
/// malformed type into the same `None` that absence produces.
fn spend_limit_of(link: &Value) -> Result<Option<f64>, ()> {
    match link.get("spendLimit") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number.as_f64().map(Some).ok_or(()),
        Some(_) => Err(()),
    }
}

/// The spend unit a link ASSERTS. A bare `spendLimit` with no explicit
/// `spendLimitUnit` asserts the default unit `currency`, matching the reference
/// SDK (`src/core/delegation.ts`). Without that default, a currency budget could
/// be relabelled by omitting the unit one hop down. An empty result means the
/// link binds no spend dimension at all.
fn stated_unit(link: &Value) -> Result<&str, ()> {
    let unit = text_of(link, "spendLimitUnit")?;
    if !unit.is_empty() {
        return Ok(unit);
    }
    if spend_limit_of(link)?.is_some() {
        return Ok("currency");
    }
    Ok("")
}

/// Checked depth extraction, the only place chain code reads `currentDepth`
/// or `maxDepth`.
///
/// Absent and null are the Go nil default (no value). A present depth must
/// be an integral JSON number representable in i64, the domain the Go
/// reference accepts at deserialization (`*int`), with one observed corner:
/// the literal `-0`, which Go accepts as 0 and serde_json parses to the
/// IEEE double -0.0. Negative integers stay accepted (Go verifies chains at
/// negative depths). Fractional, exponent-form, string, boolean, and
/// out-of-range values are an error.
fn depth_of(link: &Value, key: &str) -> Result<Option<i64>, ()> {
    match link.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => {
            if let Some(depth) = number.as_i64() {
                Ok(Some(depth))
            } else {
                match number.as_f64() {
                    Some(double) if double == 0.0 && double.is_sign_negative() => Ok(Some(0)),
                    _ => Err(()),
                }
            }
        }
        Some(_) => Err(()),
    }
}

/// The authority ceiling a chain carries from its root down to the link being
/// checked. It is derived only from the artifacts in the chain: a CEILING,
/// never a remaining balance. Remaining balances belong to the ledger and a
/// stateless verifier does not reconstruct them.
///
/// A bounded ancestor facet never becomes unconstrained because a descendant
/// omitted the field. The effective spend ceiling is the MINIMUM `spendLimit`
/// over the bounded ancestors, with the unit carried from the NEAREST bounded
/// ancestor; `maxDepth` narrows the same way, and `notBefore` narrows upward as
/// the MAXIMUM over the bounded ancestors. An omitted facet inherits; it never
/// means infinity.
#[derive(Default)]
struct EffectiveBound {
    spend_limit: Option<f64>,
    spend_unit: String,
    max_depth: Option<i64>,
    not_before: Option<i64>,
}

impl EffectiveBound {
    /// Fold one link's stated bounds into the effective ceiling, returning the
    /// first violation. A stated bound may only tighten what it inherited; an
    /// omitted bound inherits the ancestor bound unchanged.
    fn narrow(&mut self, link: &Value, hop: usize) -> Result<(), ChainError> {
        let stated = stated_unit(link).map_err(|()| self.member_error(link, hop))?;
        if self.spend_unit.is_empty() {
            // No ancestor has bound the unit yet: this link may introduce one,
            // which is narrowing rather than conversion.
            self.spend_unit = stated.to_string();
        } else if !stated.is_empty() && stated != self.spend_unit {
            return Err(ChainError::SpendUnitChanged { hop });
        }

        if let Some(limit) =
            spend_limit_of(link).map_err(|()| ChainError::SpendLimitNotANumber { hop })?
        {
            match self.spend_limit {
                Some(effective) if limit > effective => {
                    return Err(ChainError::SpendLimitWidening { hop })
                }
                Some(effective) if limit < effective => self.spend_limit = Some(limit),
                Some(_) => {}
                None => self.spend_limit = Some(limit),
            }
        }

        if let Some(max_depth) =
            depth_of(link, "maxDepth").map_err(|()| ChainError::DepthNotAnInteger { hop })?
        {
            match self.max_depth {
                Some(effective) if max_depth > effective => {
                    return Err(ChainError::DepthLimitWidening { hop })
                }
                _ => {
                    if self.max_depth.is_none_or(|effective| max_depth < effective) {
                        self.max_depth = Some(max_depth);
                    }
                }
            }
        }

        let not_before =
            text_of(link, "notBefore").map_err(|()| ChainError::MemberNotAString { hop })?;
        if !not_before.is_empty() {
            let parsed = parse_ms(not_before).ok_or(ChainError::NotBeforeUnparseable { hop })?;
            if self.not_before.is_some_and(|effective| parsed < effective) {
                return Err(ChainError::ActivationWidening { hop });
            }
            self.not_before = Some(parsed);
        }
        Ok(())
    }

    /// Which malformed member produced a stated_unit error.
    fn member_error(&self, link: &Value, hop: usize) -> ChainError {
        if text_of(link, "spendLimitUnit").is_err() {
            ChainError::MemberNotAString { hop }
        } else {
            ChainError::SpendLimitNotANumber { hop }
        }
    }
}

/// Refuse a negative depth. Kept separate from [`depth_of`], which owns the
/// TYPE domain: a negative integer is still a valid integer, and this is the
/// VALUE rule that a position in a chain cannot be below zero.
fn check_depth_floor(link: &Value, hop: usize) -> Result<(), ChainError> {
    for key in ["currentDepth", "maxDepth"] {
        if let Some(depth) =
            depth_of(link, key).map_err(|()| ChainError::DepthNotAnInteger { hop })?
        {
            if depth < 0 {
                return Err(ChainError::DepthBelowZero { hop });
            }
        }
    }
    Ok(())
}

/// Structural narrowing verification of a root-to-leaf chain, ported from
/// the Go `VerifyDelegationChain`. Proves shape only: linkage, per-link
/// scope, depth, spend and string member type validity, strict depth
/// increment within the effective `maxDepth`, scope coverage, spend limit and
/// unit narrowing, activation-floor narrowing, and EXPIRY narrowing (a child
/// may not outlive its parent, with unparseable expiries failing closed). It
/// checks no signature, no trust, and no evaluation time; use
/// [`verify_chain_authorization`] for an authorization decision.
///
/// Every optional bound is evaluated against the EFFECTIVE ceiling carried
/// from the root (see [`EffectiveBound`]), not against the immediate parent
/// alone. Under a pairwise reading, a three-hop chain that omits the bound in
/// the middle hop laundered it back to unbounded: 100 -> absent -> 1,000,000
/// passed both pairwise steps. Two hops cannot distinguish the two readings;
/// three can.
///
/// Expiry stays a pairwise rule. Its omission under a bounded parent already
/// fails closed, which makes pairwise containment transitively equal to the
/// effective minimum.
pub fn verify_chain_structure(chain: &[Value]) -> Result<(), ChainError> {
    if chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }
    for (index, link) in chain.iter().enumerate() {
        if !link.is_object() {
            return Err(ChainError::NotAnObject { hop: index });
        }
        // Scope element, depth, spend and string member types gate the whole
        // chain up front, matching the Go reference where deserialization of
        // ANY link (including a single-link chain with no pairwise step) fails
        // before the verifier runs.
        scopes_of(link).map_err(|()| ChainError::ScopeElementNotAString { hop: index })?;
        depth_of(link, "currentDepth")
            .map_err(|()| ChainError::DepthNotAnInteger { hop: index })?;
        depth_of(link, "maxDepth").map_err(|()| ChainError::DepthNotAnInteger { hop: index })?;
        spend_limit_of(link).map_err(|()| ChainError::SpendLimitNotANumber { hop: index })?;
        for member in [
            "delegatedBy",
            "delegatedTo",
            "spendLimitUnit",
            "expiresAt",
            "notBefore",
        ] {
            text_of(link, member).map_err(|()| ChainError::MemberNotAString { hop: index })?;
        }
    }

    // Seed the effective ceiling from the root, and check the root against it.
    // An earlier revision left the root unchecked, on the argument that a
    // link's own depth is answered by verify_delegation on the authorization
    // path. Preserving a pinned refusal index is not a security argument, and
    // the structural check is reached by callers that never run the
    // authorization path at all.
    let mut bound = EffectiveBound::default();
    bound.narrow(&chain[0], 0)?;
    check_depth_floor(&chain[0], 0)?;
    let root_depth = depth_of(&chain[0], "currentDepth")
        .map_err(|()| ChainError::DepthNotAnInteger { hop: 0 })?
        .unwrap_or(0);
    if bound.max_depth.is_some_and(|max| root_depth > max) {
        return Err(ChainError::DepthLimitExceeded { hop: 0 });
    }

    for hop in 1..chain.len() {
        let parent = &chain[hop - 1];
        let child = &chain[hop];
        if text_of(child, "delegatedBy").map_err(|()| ChainError::MemberNotAString { hop })?
            != text_of(parent, "delegatedTo")
                .map_err(|()| ChainError::MemberNotAString { hop: hop - 1 })?
        {
            return Err(ChainError::BrokenLinkage { hop });
        }
        bound.narrow(child, hop)?;
        let parent_depth = depth_of(parent, "currentDepth")
            .map_err(|()| ChainError::DepthNotAnInteger { hop: hop - 1 })?
            .unwrap_or(0);
        let child_depth = depth_of(child, "currentDepth")
            .map_err(|()| ChainError::DepthNotAnInteger { hop })?
            .unwrap_or(0);
        match parent_depth.checked_add(1) {
            Some(expected) if child_depth == expected => {}
            // A parent depth of exactly i64::MAX has no +1 child. Go's int
            // wraps here and can accept; the checked form keeps the
            // baseline rejection (recorded in the phase 0 matrix).
            _ => return Err(ChainError::DepthNotMonotonic { hop }),
        }
        check_depth_floor(child, hop)?;
        if bound.max_depth.is_some_and(|max| child_depth > max) {
            return Err(ChainError::DepthLimitExceeded { hop });
        }
        let parent_scope =
            scopes_of(parent).map_err(|()| ChainError::ScopeElementNotAString { hop: hop - 1 })?;
        for scope in scopes_of(child).map_err(|()| ChainError::ScopeElementNotAString { hop })? {
            if !scope_authorizes(&parent_scope, &scope) {
                return Err(ChainError::ScopeWidening { hop });
            }
        }
        let parent_expiry = match text_of(parent, "expiresAt")
            .map_err(|()| ChainError::MemberNotAString { hop: hop - 1 })?
        {
            "" => None,
            raw => Some(parse_ms(raw).ok_or(ChainError::ExpiryUnparseable { hop: hop - 1 })?),
        };
        let child_expiry =
            match text_of(child, "expiresAt").map_err(|()| ChainError::MemberNotAString { hop })? {
                "" => None,
                raw => Some(parse_ms(raw).ok_or(ChainError::ExpiryUnparseable { hop })?),
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
    /// Whether revocation state was established for every hop.
    ///
    /// Always `true`: no entry point returns a token without revocation
    /// evidence. It stays on the token so a caller reading one can see what it
    /// establishes rather than having to know the API contract, and it mirrors
    /// the Go ChainAuthorization field of the same meaning.
    pub revocation_checked: bool,
}

/// Resolves whether a chain link is revoked at the evaluation time. `None`
/// means the resolver cannot answer, which is not the same as answering "not
/// revoked".
///
/// Revocation state is NOT carried on the link. Legacy chain links are signed
/// wire objects and adding a member to them would change the bytes the
/// delegator signed, so the state arrives from outside, through this resolver.
pub type RevocationResolver<'a> = &'a dyn Fn(&Value) -> Option<bool>;

/// Authorization verification of a root-to-leaf chain at an explicit
/// evaluation time. On top of [`verify_chain_structure`] it requires:
///
/// - the root's `delegatedBy` to be present in `trusted_roots` (a chain can
///   never authorize on the strength of a self-minted root)
/// - every hop's signature to verify over the legacy preimage
/// - every hop to be fully valid at `evaluation_time` per
///   [`verify_delegation`] (active window, depth bound)
///
/// It has NO revocation context, so it cannot return a positive
/// authorization: on the path where every other gate passes it reports
/// [`ChainError::RevocationIndeterminate`], matching the Go
/// VerifyChainAuthorization, which returns REVOCATION_INDETERMINATE for the
/// same input. It previously returned a token here, which read as a positive
/// authorization for a chain whose hops may all have been revoked. Use
/// [`verify_chain_authorization_with_revocation`] to reach a positive verdict.
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
    Ok(Err(ChainError::RevocationIndeterminate { hop: 0 }))
}

/// Authorization verification with revocation context.
///
/// Everything [`verify_chain_authorization`] requires, plus a resolvable
/// not-revoked state for every hop. A resolver that returns `None` for a hop
/// yields [`ChainError::RevocationIndeterminate`] rather than a positive
/// authorization: treating "cannot check" as "not revoked" is exactly the
/// fail-open this function exists to prevent.
///
/// The token this returns always has `revocation_checked` set.
pub fn verify_chain_authorization_with_revocation(
    chain: &[Value],
    trusted_roots: &[String],
    evaluation_time: &str,
    revocation: RevocationResolver<'_>,
) -> Result<Result<ChainAuthorization, ChainError>, TimestampError> {
    match verify_chain_authorization(chain, trusted_roots, evaluation_time)? {
        // The indeterminate arm is exactly the path where every other gate
        // passed and only revocation was missing, which is the path this
        // function supplies the evidence for.
        Err(ChainError::RevocationIndeterminate { .. }) => {
            for (hop, link) in chain.iter().enumerate() {
                match revocation(link) {
                    None => return Ok(Err(ChainError::RevocationIndeterminate { hop })),
                    Some(true) => return Ok(Err(ChainError::HopRevoked { hop })),
                    Some(false) => {}
                }
            }
            Ok(Ok(ChainAuthorization {
                hops: chain.len(),
                revocation_checked: true,
            }))
        }
        Err(violation) => Ok(Err(violation)),
        Ok(token) => Ok(Ok(token)),
    }
}
