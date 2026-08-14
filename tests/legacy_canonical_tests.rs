//! Legacy canonical profile parity with the reference src/core/canonical.ts
//! and its tests, plus the profile-divergence regression the two-canonicalizer
//! design requires.

use agent_passport::{jcs, legacy_canonical};
use serde_json::{json, Value};

fn legacy(raw: &str) -> String {
    let value: Value = serde_json::from_str(raw).unwrap();
    legacy_canonical::canonicalize(&value).unwrap()
}

#[test]
fn sorts_keys_and_omits_null() {
    assert_eq!(
        legacy(r#"{"z":1,"a":"hello","m":null,"b":[3,1,2]}"#),
        r#"{"a":"hello","b":[3,1,2],"z":1}"#
    );
}

#[test]
fn nested_objects_recurse() {
    assert_eq!(
        legacy(r#"{"outer":{"z":true,"a":1},"list":[{"b":2,"a":1}]}"#),
        r#"{"list":[{"a":1,"b":2}],"outer":{"a":1,"z":true}}"#
    );
}

#[test]
fn empty_containers_and_primitives() {
    assert_eq!(legacy("{}"), "{}");
    assert_eq!(legacy("[]"), "[]");
    assert_eq!(legacy("null"), "null");
    assert_eq!(legacy("\"hello\""), "\"hello\"");
    assert_eq!(legacy("42"), "42");
    assert_eq!(legacy("true"), "true");
    assert_eq!(legacy("false"), "false");
}

#[test]
fn null_preserved_in_arrays_stripped_in_objects() {
    assert_eq!(legacy("[1,null,3]"), "[1,null,3]");
    assert_eq!(legacy("[null]"), "[null]");
    assert_eq!(legacy("[null,null]"), "[null,null]");
    assert_eq!(legacy(r#"{"a":1,"b":null,"c":3}"#), r#"{"a":1,"c":3}"#);
}

#[test]
fn deeply_nested_structures() {
    assert_eq!(
        legacy(r#"{"z":{"y":{"x":{"w":"deep"}}},"a":[{"c":3,"a":1,"b":2}]}"#),
        r#"{"a":[{"a":1,"b":2,"c":3}],"z":{"y":{"x":{"w":"deep"}}}}"#
    );
}

#[test]
fn published_cross_language_vectors_legacy_expectations() {
    // expected_legacy from the reference getTestVectors(); the three vectors
    // that carry nulls are where the profiles diverge.
    let cases: &[(&str, &str, &str)] = &[
        (
            "cv-002",
            r#"{"agentId":"agent-001","metadata":null,"scope":"read"}"#,
            r#"{"agentId":"agent-001","scope":"read"}"#,
        ),
        (
            "cv-004",
            r#"{"outer":{"inner":null,"value":42},"top":"ok"}"#,
            r#"{"outer":{"value":42},"top":"ok"}"#,
        ),
        (
            "cv-009",
            r#"{"delegationId":"del_abc123","delegatedBy":"did:aps:principal001","delegatedTo":"did:aps:agent002","scope":["data:read","commerce:checkout"],"spendLimit":500,"obligationBundleHash":null,"expiresAt":"2026-04-01T00:00:00Z","notBefore":null,"maxDepth":3,"currentDepth":1,"createdAt":"2026-03-29T00:00:00Z"}"#,
            r#"{"createdAt":"2026-03-29T00:00:00Z","currentDepth":1,"delegatedBy":"did:aps:principal001","delegatedTo":"did:aps:agent002","delegationId":"del_abc123","expiresAt":"2026-04-01T00:00:00Z","maxDepth":3,"scope":["data:read","commerce:checkout"],"spendLimit":500}"#,
        ),
        (
            "cv-005",
            r#"{"items":[1,null,3]}"#,
            r#"{"items":[1,null,3]}"#,
        ),
        (
            "cv-006",
            r#"{"integer":42,"negative":-7,"float":3.14,"zero":0}"#,
            r#"{"float":3.14,"integer":42,"negative":-7,"zero":0}"#,
        ),
        (
            "cv-008",
            r#"{"name":"Тимофій","emoji":"🔐"}"#,
            r#"{"emoji":"🔐","name":"Тимофій"}"#,
        ),
    ];
    for (id, input, expected) in cases {
        assert_eq!(&legacy(input), expected, "{id}");
    }
}

#[test]
fn profiles_differ_on_a_nested_null_and_agree_otherwise() {
    // The regression the dual-profile design requires: the two canonicalizers
    // must differ exactly on null-valued object members.
    let with_null: Value =
        serde_json::from_str(r#"{"outer":{"inner":null,"value":42},"top":"ok"}"#).unwrap();
    let legacy_form = legacy_canonical::canonicalize(&with_null).unwrap();
    let jcs_form = jcs::canonicalize(&with_null).unwrap();
    assert_eq!(legacy_form, r#"{"outer":{"value":42},"top":"ok"}"#);
    assert_eq!(
        jcs_form,
        r#"{"outer":{"inner":null,"value":42},"top":"ok"}"#
    );
    assert_ne!(legacy_form, jcs_form);
    assert_ne!(
        legacy_canonical::canonical_hash(&with_null).unwrap(),
        jcs::canonical_hash(&with_null).unwrap()
    );

    let no_null: Value = serde_json::from_str(r#"{"a":1,"b":[null,2]}"#).unwrap();
    assert_eq!(
        legacy_canonical::canonicalize(&no_null).unwrap(),
        jcs::canonicalize(&no_null).unwrap(),
        "without object nulls the profiles agree, array nulls included"
    );
}

#[test]
fn canonical_hash_shape_and_determinism() {
    let value = json!({
        "agentId": "agent_x",
        "actionType": "code_execution",
        "scope": "repo:write",
        "timestamp": "2026-04-05T03:39:31Z"
    });
    let hash = legacy_canonical::canonical_hash(&value).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(hash, legacy_canonical::canonical_hash(&value).unwrap());
    let changed = json!({
        "agentId": "agent_x",
        "actionType": "code_execution",
        "scope": "repo:read",
        "timestamp": "2026-04-05T03:39:31Z"
    });
    assert_ne!(hash, legacy_canonical::canonical_hash(&changed).unwrap());
}

#[test]
fn key_insertion_order_is_irrelevant() {
    assert_eq!(
        legacy(r#"{"z":1,"a":2,"m":3}"#),
        legacy(r#"{"m":3,"a":2,"z":1}"#)
    );
}

#[test]
fn normalize_timestamp_matches_reference() {
    assert_eq!(
        legacy_canonical::normalize_timestamp("2026-04-05T03:39:31.123Z").unwrap(),
        "2026-04-05T03:39:31Z"
    );
    assert_eq!(
        legacy_canonical::normalize_timestamp("2026-04-05T03:39:31Z").unwrap(),
        "2026-04-05T03:39:31Z"
    );
    assert_eq!(
        legacy_canonical::normalize_timestamp("2026-04-05T06:39:31+03:00").unwrap(),
        "2026-04-05T03:39:31Z"
    );
    // Fractional seconds truncate toward zero.
    assert_eq!(
        legacy_canonical::normalize_timestamp("2026-12-31T23:59:59.999Z").unwrap(),
        "2026-12-31T23:59:59Z"
    );
    assert!(legacy_canonical::normalize_timestamp("not-a-date").is_err());
    assert!(legacy_canonical::normalize_timestamp("").is_err());
}
