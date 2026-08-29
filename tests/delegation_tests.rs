//! Delegation verification: scope coverage table, single-delegation checks
//! with temporal boundaries, and the chain rules ported from the Go
//! verify suite (chain_narrowing_sweep_test.go, continuity_test.go),
//! plus authorization with explicit trusted roots.

mod common;

use agent_passport::delegation::{
    delegation_signature_preimage, scope_authorizes, scope_covers, verify_chain_authorization,
    verify_chain_structure, verify_delegation, verify_delegation_signature, ChainError,
    DelegationError,
};
use common::{public_key_hex, seed_from, sign_hex};
use serde_json::{json, Value};

const NOW: &str = "2026-06-01T00:00:00Z";

fn signed_delegation(seed_label: &str, mut body: Value) -> Value {
    let seed = seed_from(seed_label);
    body["delegatedBy"] = json!(public_key_hex(&seed));
    let canonical = delegation_signature_preimage(&body).unwrap();
    body["signature"] = json!(sign_hex(&canonical, &seed));
    body
}

#[test]
fn scope_coverage_table() {
    // Ported from the reference scopeCovers rules.
    let cases = [
        ("code", "code", true),
        ("*", "anything:at:all", true),
        ("code", "code:deploy", true),
        ("commerce:*", "commerce", true),
        ("commerce:*", "commerce:checkout", true),
        ("commerce:*", "commercex", false),
        ("code:deploy", "code", false),
        ("code", "codex", false),
        ("repo:write", "repo:read", false),
    ];
    for (granted, required, expected) in cases {
        assert_eq!(
            scope_covers(granted, required),
            expected,
            "scope_covers({granted}, {required})"
        );
    }
    let scopes = vec!["data:read".to_string(), "commerce:*".to_string()];
    assert!(scope_authorizes(&scopes, "commerce:checkout"));
    assert!(!scope_authorizes(&scopes, "admin:keys"));
}

#[test]
fn signature_and_status_checks() {
    let delegation = signed_delegation(
        "delegation-root-key",
        json!({
            "delegationId": "del_test0001",
            "delegatedTo": "agent-b",
            "scope": ["repo:write"],
            "expiresAt": "2027-01-01T00:00:00Z",
            "notBefore": "2026-01-01T00:00:00Z",
            "maxDepth": 3,
            "currentDepth": 0,
            "createdAt": "2026-01-01T00:00:00Z"
        }),
    );
    assert!(verify_delegation_signature(&delegation));
    let status = verify_delegation(&delegation, NOW).unwrap();
    assert!(status.valid, "{status:?}");

    // Tamper each signed field: the signature breaks.
    for (field, value) in [
        ("scope", json!(["*"])),
        ("delegatedTo", json!("mallory")),
        ("expiresAt", json!("2030-01-01T00:00:00Z")),
        ("maxDepth", json!(99)),
    ] {
        let mut tampered = delegation.clone();
        tampered[field] = value;
        assert!(
            !verify_delegation_signature(&tampered),
            "tampered {field} must fail"
        );
    }

    // An explicit null member is stripped by the legacy profile, so adding
    // one does not break the signature; a value does.
    let mut with_null = delegation.clone();
    with_null["obligationBundleHash"] = Value::Null;
    assert!(verify_delegation_signature(&with_null));
    let mut with_value = delegation.clone();
    with_value["obligationBundleHash"] = json!("h");
    assert!(!verify_delegation_signature(&with_value));

    assert!(!verify_delegation_signature(&Value::Null));
    let not_object = verify_delegation(&json!("nope"), NOW).unwrap();
    assert_eq!(not_object.errors, vec![DelegationError::NotAnObject]);
}

#[test]
fn temporal_boundaries_and_fail_closed_expiry() {
    let live = signed_delegation(
        "delegation-root-key",
        json!({
            "delegatedTo": "agent-b",
            "scope": ["x"],
            "expiresAt": "2026-06-01T00:00:00Z",
            "notBefore": "2026-06-01T00:00:00Z"
        }),
    );
    // Equality on both boundaries is live.
    let status = verify_delegation(&live, NOW).unwrap();
    assert!(status.valid, "{status:?}");
    // Strictly past expiry.
    let status = verify_delegation(&live, "2026-06-01T00:00:01Z").unwrap();
    assert!(status.expired);
    assert!(status.errors.contains(&DelegationError::Expired));
    // Strictly before notBefore.
    let status = verify_delegation(&live, "2026-05-31T23:59:59Z").unwrap();
    assert!(status.not_yet_valid);

    // Missing or unparseable expiry fails closed as expired.
    for expiry in [None, Some("not-a-timestamp")] {
        let mut body = json!({
            "delegatedTo": "agent-b",
            "scope": ["x"]
        });
        if let Some(raw) = expiry {
            body["expiresAt"] = json!(raw);
        }
        let delegation = signed_delegation("delegation-root-key", body);
        let status = verify_delegation(&delegation, NOW).unwrap();
        assert!(status.expired, "{expiry:?}");
        assert!(status.errors.contains(&DelegationError::InvalidExpiry));
    }

    // Unparseable notBefore is an error without flipping not_yet_valid.
    let garbled = signed_delegation(
        "delegation-root-key",
        json!({
            "delegatedTo": "agent-b",
            "scope": ["x"],
            "expiresAt": "2027-01-01T00:00:00Z",
            "notBefore": "garbage"
        }),
    );
    let status = verify_delegation(&garbled, NOW).unwrap();
    assert!(status.errors.contains(&DelegationError::InvalidNotBefore));
    assert!(!status.not_yet_valid);

    // Depth bound.
    let deep = signed_delegation(
        "delegation-root-key",
        json!({
            "delegatedTo": "agent-b",
            "scope": ["x"],
            "expiresAt": "2027-01-01T00:00:00Z",
            "maxDepth": 1,
            "currentDepth": 2
        }),
    );
    let status = verify_delegation(&deep, NOW).unwrap();
    assert!(status.depth_exceeded);

    assert!(verify_delegation(&live, "bad-time").is_err());
}

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

// --- chain structure, ported from the Go sweep tests ---

#[test]
fn chain_rejects_flat_depth() {
    let root = link("root", "a", 0, json!({}));
    let flat = link("a", "b", 0, json!({}));
    assert_eq!(
        verify_chain_structure(&[root.clone(), flat]),
        Err(ChainError::DepthNotMonotonic { hop: 1 })
    );
    let good = link("a", "b", 1, json!({}));
    assert_eq!(verify_chain_structure(&[root, good]), Ok(()));
}

#[test]
fn chain_rejects_spend_unit_change() {
    let root = link(
        "root",
        "a",
        0,
        json!({"spendLimit": 5, "spendLimitUnit": "invocations"}),
    );
    let flip = link(
        "a",
        "b",
        1,
        json!({"spendLimit": 5, "spendLimitUnit": "currency"}),
    );
    assert_eq!(
        verify_chain_structure(&[root.clone(), flip]),
        Err(ChainError::SpendUnitChanged { hop: 1 })
    );
    let dropped = link("a", "b", 1, json!({"spendLimit": 5}));
    assert_eq!(
        verify_chain_structure(&[root.clone(), dropped]),
        Err(ChainError::SpendUnitChanged { hop: 1 })
    );
    let same = link(
        "a",
        "b",
        1,
        json!({"spendLimit": 3, "spendLimitUnit": "invocations"}),
    );
    assert_eq!(verify_chain_structure(&[root, same]), Ok(()));
}

#[test]
fn chain_rejects_spend_limit_widening() {
    let root = link("root", "a", 0, json!({"spendLimit": 5}));
    let wide = link("a", "b", 1, json!({"spendLimit": 6}));
    assert_eq!(
        verify_chain_structure(&[root, wide]),
        Err(ChainError::SpendLimitWidening { hop: 1 })
    );
}

#[test]
fn chain_rejects_missing_child_expiry() {
    let root = link(
        "root",
        "a",
        0,
        json!({"expiresAt": "2030-01-01T00:00:00.000Z"}),
    );
    let child = link("a", "b", 1, json!({}));
    assert_eq!(
        verify_chain_structure(&[root, child]),
        Err(ChainError::ExpiryWidening { hop: 1 })
    );
}

#[test]
fn chain_rejects_unparseable_expiry_fail_closed() {
    let root = link(
        "root",
        "a",
        0,
        json!({"expiresAt": "2030-01-01T00:00:00.000Z"}),
    );
    let garbage = link("a", "b", 1, json!({"expiresAt": "not-a-timestamp"}));
    assert_eq!(
        verify_chain_structure(&[root.clone(), garbage]),
        Err(ChainError::ExpiryUnparseable { hop: 1 })
    );
    let bad_parent = link("root", "a", 0, json!({"expiresAt": "garbage"}));
    let child = link(
        "a",
        "b",
        1,
        json!({"expiresAt": "2029-01-01T00:00:00.000Z"}),
    );
    assert_eq!(
        verify_chain_structure(&[bad_parent, child.clone()]),
        Err(ChainError::ExpiryUnparseable { hop: 0 })
    );
    let good = link(
        "a",
        "b",
        1,
        json!({"expiresAt": "2029-01-01T00:00:00.000Z"}),
    );
    assert_eq!(verify_chain_structure(&[root, good]), Ok(()));
}

#[test]
fn chain_rejects_broken_linkage_scope_widening_and_depth_bound() {
    let root = link("root", "a", 0, json!({}));
    let unlinked = link("mallory", "b", 1, json!({}));
    assert_eq!(
        verify_chain_structure(&[root.clone(), unlinked]),
        Err(ChainError::BrokenLinkage { hop: 1 })
    );
    let widened = link("a", "b", 1, json!({"scope": ["x", "y"]}));
    assert_eq!(
        verify_chain_structure(&[root.clone(), widened]),
        Err(ChainError::ScopeWidening { hop: 1 })
    );
    let shallow_root = link("root", "a", 0, json!({"maxDepth": 1}));
    let hop1 = link("a", "b", 1, json!({"maxDepth": 1}));
    let hop2 = link("b", "c", 2, json!({"maxDepth": 1}));
    assert_eq!(
        verify_chain_structure(&[shallow_root, hop1, hop2]),
        Err(ChainError::DepthLimitExceeded { hop: 2 })
    );
    assert_eq!(verify_chain_structure(&[]), Err(ChainError::EmptyChain));
    assert_eq!(
        verify_chain_structure(&[json!("nope")]),
        Err(ChainError::NotAnObject { hop: 0 })
    );
}

// --- authorization: signatures, activity, trusted root ---

fn signed_chain() -> (Vec<Value>, String) {
    let root_seed = seed_from("chain-root-key");
    let mid_seed = seed_from("chain-mid-key");
    let root_public = public_key_hex(&root_seed);
    let mid_public = public_key_hex(&mid_seed);
    let leaf_public = public_key_hex(&seed_from("chain-leaf-key"));

    let mut root = json!({
        "delegatedBy": root_public,
        "delegatedTo": mid_public,
        "scope": ["repo:write", "commerce:*"],
        "maxDepth": 3,
        "currentDepth": 0,
        "expiresAt": "2027-01-01T00:00:00Z",
        "notBefore": "2026-01-01T00:00:00Z"
    });
    let canonical = delegation_signature_preimage(&root).unwrap();
    root["signature"] = json!(sign_hex(&canonical, &root_seed));

    let mut child = json!({
        "delegatedBy": mid_public,
        "delegatedTo": leaf_public,
        "scope": ["commerce:checkout"],
        "maxDepth": 3,
        "currentDepth": 1,
        "expiresAt": "2026-12-01T00:00:00Z",
        "notBefore": "2026-01-01T00:00:00Z"
    });
    let canonical = delegation_signature_preimage(&child).unwrap();
    child["signature"] = json!(sign_hex(&canonical, &mid_seed));

    (vec![root, child], root_public)
}

#[test]
fn authorization_requires_a_trusted_root() {
    let (chain, root_public) = signed_chain();
    let trusted = vec![root_public];
    let authorized = verify_chain_authorization(&chain, &trusted, NOW).unwrap();
    let proof = authorized.expect("chain authorizes under its trusted root");
    assert_eq!(proof.hops, 2);

    let untrusted: Vec<String> = vec![public_key_hex(&seed_from("someone-else"))];
    assert_eq!(
        verify_chain_authorization(&chain, &untrusted, NOW).unwrap(),
        Err(ChainError::UntrustedRoot)
    );
    let none: Vec<String> = Vec::new();
    assert_eq!(
        verify_chain_authorization(&chain, &none, NOW).unwrap(),
        Err(ChainError::UntrustedRoot)
    );
}

#[test]
fn authorization_rejects_bad_signature_and_inactive_hop() {
    let (chain, root_public) = signed_chain();
    let trusted = vec![root_public];

    let mut forged = chain.clone();
    forged[1]["scope"] = json!(["commerce:refund"]);
    assert_eq!(
        verify_chain_authorization(&forged, &trusted, NOW).unwrap(),
        Err(ChainError::InvalidSignature { hop: 1 })
    );

    // After the child's expiry, the leaf hop is inactive even though the
    // structure still narrows correctly.
    assert_eq!(
        verify_chain_authorization(&chain, &trusted, "2026-12-15T00:00:00Z").unwrap(),
        Err(ChainError::HopInactive { hop: 1 })
    );
    // Before notBefore, the whole chain is inactive starting at the root.
    assert_eq!(
        verify_chain_authorization(&chain, &trusted, "2025-12-31T00:00:00Z").unwrap(),
        Err(ChainError::HopInactive { hop: 0 })
    );
    assert!(verify_chain_authorization(&chain, &trusted, "junk").is_err());
}

// --- wave 1.1 item 1: scope element type (phase 0 matrix, Go parity) ---

fn chain_doc(doc: &str) -> Vec<Value> {
    serde_json::from_str(doc).expect("probe chain document parses")
}

#[test]
fn chain_refuses_non_string_scope_element() {
    // The defect case: at baseline the 42 was silently discarded and the
    // remaining string was covered, so the chain verified. The specific
    // variant is asserted so a signature failure can never mask this.
    let chain = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read",42],"currentDepth":1}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&chain),
        Err(ChainError::ScopeElementNotAString { hop: 1 })
    );
}

#[test]
fn chain_refuses_mixed_scope_on_any_link() {
    // Go's deserialization gate covers every link, including a single-link
    // chain that has no pairwise narrowing step, and a parent link.
    let single = chain_doc(
        r#"[{"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read",42],"currentDepth":0}]"#,
    );
    assert_eq!(
        verify_chain_structure(&single),
        Err(ChainError::ScopeElementNotAString { hop: 0 })
    );
    let parent_mixed = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read",true],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":1}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&parent_mixed),
        Err(ChainError::ScopeElementNotAString { hop: 0 })
    );
    let object_element = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read",["x"]],"currentDepth":1}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&object_element),
        Err(ChainError::ScopeElementNotAString { hop: 1 })
    );
}

#[test]
fn chain_scope_member_leniency_is_preserved() {
    // Accepted states from the phase 0 matrix stay accepted: absent, null,
    // and [] child scope (Go: nil slice, vacuous narrowing pass), and the
    // instruction-limited non-array leniency.
    for child_scope_member in [
        r#""currentDepth":1"#,
        r#""scope":null,"currentDepth":1"#,
        r#""scope":[],"currentDepth":1"#,
        r#""scope":"read","currentDepth":1"#,
    ] {
        let chain = chain_doc(&format!(
            r#"[
            {{"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0}},
            {{"delegatedBy":"agent-a","delegatedTo":"agent-b",{child_scope_member}}}
            ]"#,
        ));
        assert_eq!(
            verify_chain_structure(&chain),
            Ok(()),
            "{child_scope_member}"
        );
    }
}

#[test]
fn chain_null_scope_element_is_the_inert_empty_string() {
    // Go's decoder leaves a null string element at the zero value "", so
    // the member survives (it is not discarded) and must itself be covered
    // by the parent: widening under a non-covering parent, valid under "*".
    let widened = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read",null],"currentDepth":1}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&widened),
        Err(ChainError::ScopeWidening { hop: 1 })
    );
    let covered = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["*"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read",null],"currentDepth":1}
        ]"#,
    );
    assert_eq!(verify_chain_structure(&covered), Ok(()));
}

// --- wave 1.1 item 2: depth value domain (phase 0 matrix, Go parity) ---

#[test]
fn chain_refuses_non_integral_depths() {
    // The defect case: at baseline -1.5 followed by -0.5 satisfied the +1
    // rule through f64 arithmetic. The parent's fractional depth is caught
    // by the up-front per-link gate at index 0.
    let fractional = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":-1.5},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":-0.5}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&fractional),
        Err(ChainError::DepthNotAnInteger { hop: 0 })
    );
    // Every non-integral class Go rejects at deserialization, on the child.
    for child_depth in ["1.5", "1e0", "\"1\"", "true", "9223372036854775808"] {
        let chain = chain_doc(&format!(
            r#"[
            {{"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":0}},
            {{"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":{child_depth}}}
            ]"#,
        ));
        assert_eq!(
            verify_chain_structure(&chain),
            Err(ChainError::DepthNotAnInteger { hop: 1 }),
            "currentDepth {child_depth}"
        );
    }
    // maxDepth shares the domain.
    for max_depth in ["1.5", "1e0", "\"1\"", "true", "9223372036854775808"] {
        let chain = chain_doc(&format!(
            r#"[
            {{"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":0,"maxDepth":{max_depth}}},
            {{"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":1}}
            ]"#,
        ));
        assert_eq!(
            verify_chain_structure(&chain),
            Err(ChainError::DepthNotAnInteger { hop: 0 }),
            "maxDepth {max_depth}"
        );
    }
}

#[test]
fn chain_depth_accepted_states_are_preserved() {
    // Null and absent stay the Go nil default (0); the literal -0 is accepted
    // as 0 (Go parses it to 0); a negative maxDepth stays a value-domain
    // rejection at the verifier layer, not a type error.
    //
    // The negative-depth cases below moved from Ok(()) to DepthBelowZero. They
    // are still TYPE-domain assertions and still make their original point: a
    // negative integer parses as an integer, so the refusal is DepthBelowZero
    // and never DepthNotAnInteger. What changed is the VALUE rule. A negative
    // currentDepth is what let an eight-link chain fit inside a maxDepth of 2,
    // so a depth ceiling did not bound chain length until the floor existed.
    let null_child = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":-1},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":null}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&null_child),
        Err(ChainError::DepthBelowZero { hop: 0 })
    );
    let negative = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":-2},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":-1}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&negative),
        Err(ChainError::DepthBelowZero { hop: 0 })
    );
    // The literal -0 is still parsed as the integer 0, not rejected as a
    // fractional or out-of-domain number, and 0 is not below the floor.
    let minus_zero = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":-0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":1}
        ]"#,
    );
    assert_eq!(verify_chain_structure(&minus_zero), Ok(()));
    // An absent child depth under a parent at 0 is still the monotonicity
    // rejection, exactly as Go refuses it (default 0 is not 0 + 1).
    let absent_child = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"]}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&absent_child),
        Err(ChainError::DepthNotMonotonic { hop: 1 })
    );
    let negative_bound = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":0,"maxDepth":-1},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":1}
        ]"#,
    );
    // A negative maxDepth is now caught by the floor at the root, before the
    // pairwise step reaches it. The refusal index moved from hop 1 to hop 0
    // because the root is checked against its own bounds at all now; the point
    // the case makes, that a negative ceiling is a value rejection rather than
    // a type error, is unchanged.
    assert_eq!(
        verify_chain_structure(&negative_bound),
        Err(ChainError::DepthBelowZero { hop: 0 })
    );
    // A parent at exactly i64::MAX has no +1 child: the checked add keeps
    // the baseline rejection (Go's int wraps here; recorded divergence).
    let saturated = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":9223372036854775807},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":-9223372036854775808}
        ]"#,
    );
    assert_eq!(
        verify_chain_structure(&saturated),
        Err(ChainError::DepthNotMonotonic { hop: 1 })
    );
}

#[test]
fn single_delegation_depth_stays_dynamic() {
    // verify_delegation is the TS-referenced path: the phase 0 matrix
    // records TS accepting fractional depths there (plain > comparison),
    // so the chain-path integral domain must NOT leak into it.
    let fractional_live = signed_delegation(
        "delegation-root-key",
        json!({
            "delegatedTo": "agent-b",
            "scope": ["x"],
            "expiresAt": "2027-01-01T00:00:00Z",
            "maxDepth": 3,
            "currentDepth": 1.5
        }),
    );
    let status = verify_delegation(&fractional_live, NOW).unwrap();
    assert!(status.valid, "{status:?}");
    let fractional_deep = signed_delegation(
        "delegation-root-key",
        json!({
            "delegatedTo": "agent-b",
            "scope": ["x"],
            "expiresAt": "2027-01-01T00:00:00Z",
            "maxDepth": 2,
            "currentDepth": 2.5
        }),
    );
    let status = verify_delegation(&fractional_deep, NOW).unwrap();
    assert!(status.depth_exceeded);
}

#[test]
fn chain_authorization_routes_through_checked_scope_extraction() {
    // The authorization path reports the typed scope error, not a
    // signature or trust failure: the links are unsigned, but the root is
    // trusted and the structural gate runs before signature checks.
    let chain = chain_doc(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read",42],"currentDepth":1}
        ]"#,
    );
    let trusted = vec!["root-key".to_string()];
    assert_eq!(
        verify_chain_authorization(&chain, &trusted, NOW).unwrap(),
        Err(ChainError::ScopeElementNotAString { hop: 1 })
    );
}

#[test]
fn structural_pass_is_not_authorization() {
    // The same chain that passes the structural check still refuses
    // authorization without a trusted root: the two operations return
    // different types and cannot be conflated.
    let (chain, _) = signed_chain();
    assert_eq!(verify_chain_structure(&chain), Ok(()));
    let none: Vec<String> = Vec::new();
    assert!(verify_chain_authorization(&chain, &none, NOW)
        .unwrap()
        .is_err());
}
