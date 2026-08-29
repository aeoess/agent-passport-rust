//! Effective-bound regressions for chain narrowing.
//!
//! A bounded ancestor facet never becomes unconstrained because a descendant
//! omitted the field. The effective bound at verify is the MINIMUM spendLimit
//! over the bounded ancestors, with the unit carried from the NEAREST bounded
//! ancestor. It is a ceiling derived from the artifacts, never a remaining
//! balance.
//!
//! These vectors need THREE hops to be verdict-visible: with two hops the
//! pairwise reading and the effective reading give the same answer.

mod common;

use agent_passport::delegation::{verify_chain_structure, ChainError};
use serde_json::{json, Value};

fn link(by: &str, to: &str, depth: i64, extra: Value) -> Value {
    let mut base = json!({
        "delegatedBy": by,
        "delegatedTo": to,
        "scope": ["x"],
        "maxDepth": 5,
        "currentDepth": depth
    });
    if let Some(extra) = extra.as_object() {
        for (k, v) in extra {
            base[k] = v.clone();
        }
    }
    base
}

fn spend(limit: Option<f64>) -> Value {
    match limit {
        Some(value) => json!({ "spendLimit": value }),
        None => json!({}),
    }
}

/// The five-row spend table, executed over three hops.
#[test]
fn three_hop_spend_table() {
    let cases: [(&str, Option<f64>, Option<f64>, bool); 5] = [
        ("100 -> absent -> 1000000", None, Some(1_000_000.0), true),
        ("100 -> absent -> 50", None, Some(50.0), false),
        ("100 -> 100 -> 100", Some(100.0), Some(100.0), false),
        ("100 -> 50 -> 50", Some(50.0), Some(50.0), false),
        ("100 -> 101 -> 101", Some(101.0), Some(101.0), true),
    ];
    for (name, mid, leaf, expect_reject) in cases {
        let chain = [
            link("root", "a", 0, spend(Some(100.0))),
            link("a", "b", 1, spend(mid)),
            link("b", "c", 2, spend(leaf)),
        ];
        let result = verify_chain_structure(&chain);
        assert_eq!(
            result.is_err(),
            expect_reject,
            "{name}: got {result:?}, expected reject = {expect_reject}"
        );
    }
}

/// Neighbour guard: the direct parent/child rows keep the verdicts they had
/// before the effective bound existed.
#[test]
fn two_hop_spend_table_is_unchanged() {
    for (name, child, expect_reject) in [
        ("100 -> 100", 100.0, false),
        ("100 -> 50", 50.0, false),
        ("100 -> 101", 101.0, true),
    ] {
        let chain = [
            link("root", "a", 0, spend(Some(100.0))),
            link("a", "b", 1, spend(Some(child))),
        ];
        assert_eq!(
            verify_chain_structure(&chain).is_err(),
            expect_reject,
            "{name}"
        );
    }
}

/// A USD-bound authority cannot erase the unit by omitting the spend facet and
/// reappear as JPY or unitless.
#[test]
fn spend_unit_survives_an_omitted_hop() {
    let root = link(
        "root",
        "a",
        0,
        json!({"spendLimit": 100, "spendLimitUnit": "USD"}),
    );
    let silent = link("a", "b", 1, json!({}));

    let jpy = [
        root.clone(),
        silent.clone(),
        link(
            "b",
            "c",
            2,
            json!({"spendLimit": 50, "spendLimitUnit": "JPY"}),
        ),
    ];
    assert_eq!(
        verify_chain_structure(&jpy),
        Err(ChainError::SpendUnitChanged { hop: 2 }),
        "USD -> absent -> JPY must be refused"
    );

    let unitless = [
        root.clone(),
        silent.clone(),
        link("b", "c", 2, json!({"spendLimit": 50})),
    ];
    assert_eq!(
        verify_chain_structure(&unitless),
        Err(ChainError::SpendUnitChanged { hop: 2 }),
        "USD -> absent -> unitless-with-limit must be refused"
    );

    let inherit = [root.clone(), silent.clone(), link("b", "c", 2, json!({}))];
    assert_eq!(
        verify_chain_structure(&inherit),
        Ok(()),
        "omitting the facet entirely inherits USD"
    );

    let over = [
        root.clone(),
        silent.clone(),
        link(
            "b",
            "c",
            2,
            json!({"spendLimit": 101, "spendLimitUnit": "USD"}),
        ),
    ];
    assert_eq!(
        verify_chain_structure(&over),
        Err(ChainError::SpendLimitWidening { hop: 2 }),
        "the inherited unit still carries the inherited ceiling"
    );

    let under = [
        root,
        silent,
        link(
            "b",
            "c",
            2,
            json!({"spendLimit": 50, "spendLimitUnit": "USD"}),
        ),
    ];
    assert_eq!(verify_chain_structure(&under), Ok(()));
}

/// maxDepth omission must not erase an ancestor depth constraint, and a
/// descendant must not raise it.
#[test]
fn max_depth_survives_an_omitted_hop() {
    fn depth_link(by: &str, to: &str, depth: i64, max: Option<i64>) -> Value {
        let mut base = json!({
            "delegatedBy": by, "delegatedTo": to, "scope": ["x"], "currentDepth": depth
        });
        if let Some(max) = max {
            base["maxDepth"] = json!(max);
        }
        base
    }
    let launder = [
        depth_link("root", "a", 0, Some(1)),
        depth_link("a", "b", 1, None),
        depth_link("b", "c", 2, None),
    ];
    assert_eq!(
        verify_chain_structure(&launder),
        Err(ChainError::DepthLimitExceeded { hop: 2 }),
        "maxDepth 1 -> absent -> depth 2 must be refused"
    );

    let raise = [
        depth_link("root", "a", 0, Some(1)),
        depth_link("a", "b", 1, Some(99)),
        depth_link("b", "c", 2, Some(99)),
    ];
    assert_eq!(
        verify_chain_structure(&raise),
        Err(ChainError::DepthLimitWidening { hop: 1 }),
        "a descendant may not raise the ancestor maxDepth"
    );

    let within = [
        depth_link("root", "a", 0, Some(2)),
        depth_link("a", "b", 1, None),
        depth_link("b", "c", 2, None),
    ];
    assert_eq!(verify_chain_structure(&within), Ok(()));
}

/// A malformed spendLimit must fail rather than silently disable the ceiling.
/// depth_of and scopes_of already return Err on the same inputs; the spend
/// ceiling read them through a bare as_f64, which yields None for a string, a
/// boolean, or an object, and None was indistinguishable from absent.
#[test]
fn malformed_spend_limit_types_fail_rather_than_disable_the_check() {
    for bad in [json!("999"), json!(true), json!([5]), json!({"amount": 5})] {
        let chain = [
            link("root", "a", 0, json!({ "spendLimit": bad })),
            link("a", "b", 1, json!({"spendLimit": 1000000})),
        ];
        assert_eq!(
            verify_chain_structure(&chain),
            Err(ChainError::SpendLimitNotANumber { hop: 0 }),
            "parent spendLimit {bad} must be refused, not treated as absent"
        );
        let chain = [
            link("root", "a", 0, json!({"spendLimit": 100})),
            link("a", "b", 1, json!({ "spendLimit": bad })),
        ];
        assert_eq!(
            verify_chain_structure(&chain),
            Err(ChainError::SpendLimitNotANumber { hop: 1 }),
            "child spendLimit {bad} must be refused, not treated as absent"
        );
    }
    // An explicit JSON null is the absent case, exactly as for depth: Go's
    // *float64 decoder leaves it nil. Absent inherits, so the leaf is capped.
    let chain = [
        link("root", "a", 0, json!({"spendLimit": 100})),
        link("a", "b", 1, json!({ "spendLimit": Value::Null })),
        link("b", "c", 2, json!({"spendLimit": 1000000})),
    ];
    assert_eq!(
        verify_chain_structure(&chain),
        Err(ChainError::SpendLimitWidening { hop: 2 })
    );
}

/// An activation floor set by an ancestor is not erased by a descendant that
/// omits notBefore, and a descendant may not activate earlier than the
/// effective inherited floor. notBefore containment was not checked at all.
#[test]
fn not_before_survives_an_omitted_hop() {
    let root = link("root", "a", 0, json!({"notBefore": "2026-06-01T00:00:00Z"}));
    let silent = link("a", "b", 1, json!({}));

    let earlier = [
        root.clone(),
        silent.clone(),
        link("b", "c", 2, json!({"notBefore": "2020-01-01T00:00:00Z"})),
    ];
    assert_eq!(
        verify_chain_structure(&earlier),
        Err(ChainError::ActivationWidening { hop: 2 })
    );

    let inherit = [root.clone(), silent.clone(), link("b", "c", 2, json!({}))];
    assert_eq!(verify_chain_structure(&inherit), Ok(()));

    let later = [
        root.clone(),
        silent,
        link("b", "c", 2, json!({"notBefore": "2026-07-01T00:00:00Z"})),
    ];
    assert_eq!(verify_chain_structure(&later), Ok(()));

    let garbage = [root, link("a", "b", 1, json!({"notBefore": "whenever"}))];
    assert_eq!(
        verify_chain_structure(&garbage),
        Err(ChainError::NotBeforeUnparseable { hop: 1 })
    );
}

/// A malformed string member must fail rather than collapse to the empty
/// string. The empty string was load bearing: it disabled the unit check, and
/// it made two links whose identities are both malformed compare equal in the
/// linkage check.
#[test]
fn malformed_string_members_fail_rather_than_collapse_to_empty() {
    for member in [
        "delegatedBy",
        "delegatedTo",
        "spendLimitUnit",
        "expiresAt",
        "notBefore",
    ] {
        let mut bad = link("a", "b", 1, json!({}));
        bad[member] = json!(42);
        let chain = [link("root", "a", 0, json!({})), bad];
        assert_eq!(
            verify_chain_structure(&chain),
            Err(ChainError::MemberNotAString { hop: 1 }),
            "{member} of the wrong type must be refused"
        );
    }
    // Two links whose identities are both non-strings previously both read as
    // "" and satisfied the linkage check against each other.
    let mut root = link("root", "a", 0, json!({}));
    root["delegatedTo"] = json!(7);
    let mut child = link("a", "b", 1, json!({}));
    child["delegatedBy"] = json!(7);
    assert_eq!(
        verify_chain_structure(&[root, child]),
        Err(ChainError::MemberNotAString { hop: 0 })
    );
}

/// Absence of a SET decodes to EMPTY, which is zero authority and fails closed.
/// This is the other half of the classification rule and it already held; the
/// test pins it so the numeric-ceiling repair cannot drift into it.
#[test]
fn scope_absence_is_zero_authority() {
    fn scope_link(by: &str, to: &str, depth: i64, scope: Option<Value>) -> Value {
        let mut base = json!({"delegatedBy": by, "delegatedTo": to, "currentDepth": depth});
        if let Some(scope) = scope {
            base["scope"] = scope;
        }
        base
    }
    let launder = [
        scope_link("root", "a", 0, Some(json!(["data:read"]))),
        scope_link("a", "b", 1, None),
        scope_link("b", "c", 2, Some(json!(["data:*"]))),
    ];
    assert_eq!(
        verify_chain_structure(&launder),
        Err(ChainError::ScopeWidening { hop: 2 })
    );
    let narrowed = [
        scope_link("root", "a", 0, Some(json!(["data:read"]))),
        scope_link("a", "b", 1, None),
        scope_link("b", "c", 2, None),
    ];
    assert_eq!(verify_chain_structure(&narrowed), Ok(()));
}

/// A chain that is internally well signed under a trusted root is still not a
/// revocation-aware authorization. The token says which of the two it is, and
/// the revocation-aware entry point refuses to return a positive verdict when
/// the resolver cannot answer.
#[test]
fn authorization_without_revocation_context_is_indeterminate() {
    use agent_passport::delegation::{
        delegation_signature_preimage, verify_chain_authorization,
        verify_chain_authorization_with_revocation, ChainError,
    };
    use common::{public_key_hex, seed_from, sign_hex};

    let root_seed = seed_from("revocation-root");
    let mid_seed = seed_from("revocation-mid");
    let root_public = public_key_hex(&root_seed);
    let mid_public = public_key_hex(&mid_seed);
    let leaf_public = public_key_hex(&seed_from("revocation-leaf"));

    let mut root = json!({
        "delegatedBy": root_public, "delegatedTo": mid_public, "scope": ["repo:write"],
        "maxDepth": 3, "currentDepth": 0, "expiresAt": "2027-01-01T00:00:00Z"
    });
    root["signature"] = json!(sign_hex(
        &delegation_signature_preimage(&root).unwrap(),
        &root_seed
    ));
    let mut child = json!({
        "delegatedBy": mid_public, "delegatedTo": leaf_public, "scope": ["repo:write"],
        "maxDepth": 3, "currentDepth": 1, "expiresAt": "2026-12-01T00:00:00Z"
    });
    child["signature"] = json!(sign_hex(
        &delegation_signature_preimage(&child).unwrap(),
        &mid_seed
    ));
    let chain = vec![root, child];
    let trusted = vec![root_public];
    let now = "2026-06-01T00:00:00Z";

    // The no-revocation entry point succeeds, and says on the token that it
    // established nothing about revocation.
    let token = verify_chain_authorization(&chain, &trusted, now)
        .unwrap()
        .expect("trusted root, valid signatures, live hops");
    assert_eq!(token.hops, 2);
    assert!(!token.revocation_checked);

    // A resolver that cannot answer yields indeterminate, never a positive
    // authorization.
    let unknown = |_: &Value| None;
    assert_eq!(
        verify_chain_authorization_with_revocation(&chain, &trusted, now, &unknown).unwrap(),
        Err(ChainError::RevocationIndeterminate { hop: 0 })
    );

    // A resolver that reports a revocation refuses.
    let revoked = |_: &Value| Some(true);
    assert_eq!(
        verify_chain_authorization_with_revocation(&chain, &trusted, now, &revoked).unwrap(),
        Err(ChainError::HopRevoked { hop: 0 })
    );

    // A resolver that can answer produces a token that says so.
    let live = |_: &Value| Some(false);
    let token = verify_chain_authorization_with_revocation(&chain, &trusted, now, &live)
        .unwrap()
        .expect("trusted root and a resolver that can answer");
    assert_eq!(token.hops, 2);
    assert!(token.revocation_checked);
}
