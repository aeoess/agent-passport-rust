//! action_ref parity against the frozen actionref-canonical-fixture-v1
//! vectors: all four positive vectors byte-identical, both negative duplicate
//! vectors rejected, and the input slice never mutated.

use agent_passport::action_ref::{
    action_refs_match, canonicalize_scopes, compute_action_ref_scopes, ActionRefError,
};
use serde_json::Value;

#[derive(serde::Deserialize)]
struct FixtureDoc {
    vectors: Vec<FixtureVector>,
}

#[derive(serde::Deserialize)]
struct FixtureVector {
    name: String,
    input: FixtureInput,
    #[serde(default)]
    canonical_scope_order: Option<Vec<String>>,
    #[serde(default)]
    action_ref: Option<String>,
    #[serde(default)]
    expected_verification: Option<bool>,
    #[serde(default)]
    rejection_kind: Option<String>,
}

#[derive(serde::Deserialize)]
struct FixtureInput {
    #[serde(rename = "agentId")]
    agent_id: String,
    #[serde(rename = "actionType")]
    action_type: String,
    #[serde(rename = "scopeRequired")]
    scope_required: Vec<String>,
    timestamp: String,
}

fn fixture() -> FixtureDoc {
    serde_json::from_str(include_str!("vectors/actionref-canonical-fixture-v1.json")).unwrap()
}

#[test]
fn all_six_fixture_vectors_consumed() {
    let doc = fixture();
    assert_eq!(doc.vectors.len(), 6, "fixture must carry 6 vectors");
    let mut positive = 0;
    let mut negative = 0;
    for v in &doc.vectors {
        let original = v.input.scope_required.clone();
        let result = compute_action_ref_scopes(
            &v.input.agent_id,
            &v.input.action_type,
            &v.input.scope_required,
            &v.input.timestamp,
        );
        match (&v.action_ref, v.expected_verification) {
            (Some(expected), _) => {
                positive += 1;
                let got = result.unwrap_or_else(|e| panic!("{}: {e}", v.name));
                assert_eq!(&got, expected, "{}: action_ref", v.name);
                let canonical = canonicalize_scopes(&v.input.scope_required).unwrap();
                assert_eq!(
                    Some(&canonical),
                    v.canonical_scope_order.as_ref(),
                    "{}: canonical scope order",
                    v.name
                );
            }
            (None, Some(false)) => {
                negative += 1;
                assert_eq!(
                    result,
                    Err(ActionRefError::DuplicateScopeRequired),
                    "{}: must reject duplicates",
                    v.name
                );
                assert_eq!(
                    v.rejection_kind.as_deref(),
                    Some("duplicate_scope_required"),
                    "{}: rejection kind pinned by the fixture",
                    v.name
                );
            }
            other => panic!("{}: unexpected vector shape {other:?}", v.name),
        }
        assert_eq!(
            original, v.input.scope_required,
            "{}: input slice must not be mutated",
            v.name
        );
    }
    assert_eq!(positive, 4);
    assert_eq!(negative, 2);
}

#[test]
fn scope_order_and_normalization_are_identity_invariant() {
    // Same scopes, shuffled order and NFD spelling: same action_ref.
    let doc = fixture();
    let multi = doc
        .vectors
        .iter()
        .find(|v| v.name == "unsorted-multi-scope-ascii")
        .unwrap();
    let mut reversed = multi.input.scope_required.clone();
    reversed.reverse();
    let a = compute_action_ref_scopes(
        &multi.input.agent_id,
        &multi.input.action_type,
        &multi.input.scope_required,
        &multi.input.timestamp,
    )
    .unwrap();
    let b = compute_action_ref_scopes(
        &multi.input.agent_id,
        &multi.input.action_type,
        &reversed,
        &multi.input.timestamp,
    )
    .unwrap();
    assert_eq!(a, b);

    // NFD spelling of the nfd-scope vector computes the same identity as the
    // fixture's NFC expectation.
    let nfd = doc
        .vectors
        .iter()
        .find(|v| v.name == "nfd-scope-normalizes-to-nfc")
        .unwrap();
    let decomposed = vec!["cafe\u{0301}:read".to_string()];
    let got = compute_action_ref_scopes(
        &nfd.input.agent_id,
        &nfd.input.action_type,
        &decomposed,
        &nfd.input.timestamp,
    )
    .unwrap();
    assert_eq!(Some(&got), nfd.action_ref.as_ref());
}

#[test]
fn duplicate_detection_runs_after_nfc() {
    // U+00E9 versus e followed by U+0301: equal only after NFC, still a
    // duplicate.
    let scopes = vec![
        "caf\u{00E9}:read".to_string(),
        "cafe\u{0301}:read".to_string(),
    ];
    assert_eq!(
        canonicalize_scopes(&scopes),
        Err(ActionRefError::DuplicateScopeRequired)
    );
}

#[test]
fn case_is_not_folded() {
    let scopes = vec!["Repo:Write".to_string(), "repo:write".to_string()];
    let canonical = canonicalize_scopes(&scopes).unwrap();
    assert_eq!(canonical.len(), 2, "case-distinct scopes stay distinct");
}

#[test]
fn timestamp_normalizes_before_hashing() {
    let doc = fixture();
    let plain = doc
        .vectors
        .iter()
        .find(|v| v.name == "plain-single-scope-ascii")
        .unwrap();
    // Same instant spelled with milliseconds and with an offset: identical
    // action_ref.
    for spelling in ["2026-07-10T00:00:00.000Z", "2026-07-10T03:00:00+03:00"] {
        let got = compute_action_ref_scopes(
            &plain.input.agent_id,
            &plain.input.action_type,
            &plain.input.scope_required,
            spelling,
        )
        .unwrap();
        assert_eq!(Some(&got), plain.action_ref.as_ref(), "{spelling}");
    }
    assert_eq!(
        compute_action_ref_scopes("a", "b", &[], "not-a-date"),
        Err(ActionRefError::InvalidTimestamp)
    );
}

#[test]
fn astral_sort_is_code_point_order() {
    // The astral fixture vector's scope order pins this with frozen bytes;
    // this spells the same fact directly. U+FF21 (BMP) sorts before U+10400
    // (astral) in code-point order, though UTF-16 code units would reverse
    // them.
    let value: Value =
        serde_json::from_str(include_str!("vectors/actionref-canonical-fixture-v1.json")).unwrap();
    let astral = value["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "astral-scope-orders-after-bmp-high")
        .unwrap();
    let expected: Vec<String> = astral["canonical_scope_order"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    let scopes: Vec<String> = astral["input"]["scopeRequired"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert_eq!(canonicalize_scopes(&scopes).unwrap(), expected);
}

#[test]
fn match_predicate_never_matches_empty() {
    assert!(action_refs_match("abc", "abc"));
    assert!(!action_refs_match("abc", "abd"));
    assert!(!action_refs_match("", ""));
}
