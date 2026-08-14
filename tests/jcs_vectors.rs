//! Strict-JCS wrapper parity against the frozen vectors, plus the ported Go
//! surrogate and raw-JSON suites (jcs/lone_surrogate_test.go,
//! lone_surrogate_rawjson_test.go, lone_surrogate_adversarial_test.go,
//! lone_surrogate_crosssdk_test.go, canonical_bytes_vectors_test.go,
//! esnumber_test.go). Runs standalone from vendored vectors: no sibling
//! repository, network, clock, or environment input.

use agent_passport::jcs;
use serde_json::{json, Value};

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(serde::Deserialize)]
struct VectorDoc {
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    input: Value,
    #[serde(default)]
    canonical: Option<String>,
    canonical_bytes_hex: String,
    canonical_sha256: String,
}

#[test]
fn wrapper_matches_canonical_bytes_vectors() {
    let doc: VectorDoc =
        serde_json::from_str(include_str!("vectors/canonical-bytes-jcs-v1.json")).unwrap();
    assert_eq!(doc.vectors.len(), 8, "expected 8 vectors");
    for v in &doc.vectors {
        let canonical = jcs::canonicalize(&v.input).unwrap();
        if let Some(expected) = &v.canonical {
            assert_eq!(&canonical, expected, "{}: canonical", v.name);
        }
        assert_eq!(
            hex::encode(canonical.as_bytes()),
            v.canonical_bytes_hex,
            "{}: bytes",
            v.name
        );
        assert_eq!(
            jcs::canonical_hash(&v.input).unwrap(),
            v.canonical_sha256,
            "{}: sha256",
            v.name
        );
        assert_eq!(sha256_hex(&canonical), v.canonical_sha256);
    }
}

#[test]
fn wrapper_matches_bilateral_vectors() {
    let doc: VectorDoc =
        serde_json::from_str(include_str!("vectors/canonicalize-fixture-v1.json")).unwrap();
    assert_eq!(doc.vectors.len(), 10, "expected 10 vectors");
    for v in &doc.vectors {
        let canonical = jcs::canonicalize(&v.input).unwrap();
        assert_eq!(
            hex::encode(canonical.as_bytes()),
            v.canonical_bytes_hex,
            "{}: bytes",
            v.name
        );
        assert_eq!(
            jcs::canonical_hash(&v.input).unwrap(),
            v.canonical_sha256,
            "{}: sha256",
            v.name
        );
    }
}

#[test]
fn wrapper_matches_published_cross_language_vectors() {
    // cv-001 through cv-010 from the reference getTestVectors(), strict-JCS
    // expectations.
    let cases: &[(&str, &str, &str)] = &[
        (
            "cv-001",
            r#"{"agentId":"agent-001","scope":"read"}"#,
            r#"{"agentId":"agent-001","scope":"read"}"#,
        ),
        (
            "cv-002",
            r#"{"agentId":"agent-001","metadata":null,"scope":"read"}"#,
            r#"{"agentId":"agent-001","metadata":null,"scope":"read"}"#,
        ),
        (
            "cv-003",
            r#"{"zebra":1,"alpha":2,"middle":3}"#,
            r#"{"alpha":2,"middle":3,"zebra":1}"#,
        ),
        (
            "cv-004",
            r#"{"outer":{"inner":null,"value":42},"top":"ok"}"#,
            r#"{"outer":{"inner":null,"value":42},"top":"ok"}"#,
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
            "cv-007",
            r#"{"emptyArr":[],"emptyObj":{}}"#,
            r#"{"emptyArr":[],"emptyObj":{}}"#,
        ),
        (
            "cv-008",
            r#"{"name":"Тимофій","emoji":"🔐"}"#,
            r#"{"emoji":"🔐","name":"Тимофій"}"#,
        ),
        (
            "cv-009",
            r#"{"delegationId":"del_abc123","delegatedBy":"did:aps:principal001","delegatedTo":"did:aps:agent002","scope":["data:read","commerce:checkout"],"spendLimit":500,"obligationBundleHash":null,"expiresAt":"2026-04-01T00:00:00Z","notBefore":null,"maxDepth":3,"currentDepth":1,"createdAt":"2026-03-29T00:00:00Z"}"#,
            r#"{"createdAt":"2026-03-29T00:00:00Z","currentDepth":1,"delegatedBy":"did:aps:principal001","delegatedTo":"did:aps:agent002","delegationId":"del_abc123","expiresAt":"2026-04-01T00:00:00Z","maxDepth":3,"notBefore":null,"obligationBundleHash":null,"scope":["data:read","commerce:checkout"],"spendLimit":500}"#,
        ),
        (
            "cv-010",
            r#"{"active":true,"revoked":false}"#,
            r#"{"active":true,"revoked":false}"#,
        ),
    ];
    for (id, input, expected) in cases {
        let value: Value = serde_json::from_str(input).unwrap();
        assert_eq!(&jcs::canonicalize(&value).unwrap(), expected, "{id}");
    }
}

#[test]
fn wrapper_matches_es_number_boundaries() {
    let cases: &[(f64, &str)] = &[
        (1e21, "1e+21"),
        (1.5e21, "1.5e+21"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (1e-8, "1e-8"),
        (0.1, "0.1"),
        (100.5, "100.5"),
        (1e16, "10000000000000000"),
        (5e-324, "5e-324"),
        (1e308, "1e+308"),
        (-0.0001, "-0.0001"),
        (6.022e23, "6.022e+23"),
        (1.0, "1"),
        (-1.0, "-1"),
        (123456789.0, "123456789"),
    ];
    for (input, expected) in cases {
        let value = json!(input);
        assert_eq!(
            &jcs::canonicalize(&value).unwrap(),
            expected,
            "esNumber({input})"
        );
    }
}

#[test]
fn wrapper_forces_u64_through_the_double_view() {
    // JSON.parse in the reference rounds every number to an IEEE double. A
    // u64 above 2^53 must round identically, never keep 64-bit fidelity.
    let value: Value = serde_json::from_str(r#"{"v":18446744073709551615}"#).unwrap();
    assert_eq!(
        jcs::canonicalize(&value).unwrap(),
        "{\"v\":18446744073709552000}"
    );
}

// --- ported from jcs/lone_surrogate_test.go (programmatic layer) ---
//
// A Rust String cannot carry a lone surrogate or invalid UTF-8, so the
// programmatic rejection tests from Go (WTF-8 bytes inside a native string)
// have no reachable input here; the type system provides the guarantee those
// tests pin. The observable halves are ported: valid non-BMP scalars and
// U+D7FF pass through unchanged, and byte-level inputs reject.

#[test]
fn valid_non_bmp_scalar_unchanged() {
    let got = jcs::canonicalize(&json!({ "v": "\u{1F600}" })).unwrap();
    assert_eq!(got, "{\"v\":\"\u{1F600}\"}");
    assert_eq!(got.as_bytes()[6], 0xF0, "raw UTF-8 emoji bytes expected");
}

#[test]
fn valid_hangul_d7ff_not_flagged() {
    // U+D7FF sits directly below the surrogate range and must pass.
    let got = jcs::canonicalize(&json!({ "v": "\u{D7FF}" })).unwrap();
    assert_eq!(got, "{\"v\":\"\u{D7FF}\"}");
}

#[test]
fn wtf8_surrogate_bytes_reject_at_the_byte_boundary() {
    // The WTF-8 encodings of U+D800 and U+DFFF are invalid UTF-8 and reject
    // at the raw-text boundary, matching the Go raw-text layer.
    for bytes in [&[0xED, 0xA0, 0x80][..], &[0xED, 0xBF, 0xBF][..]] {
        let mut raw = b"{\"v\":\"".to_vec();
        raw.extend_from_slice(bytes);
        raw.extend_from_slice(b"\"}");
        assert_eq!(
            jcs::validate_json_text(&raw),
            Err(jcs::JcsError::InvalidUnicode {
                reason: "invalid_utf8"
            })
        );
    }
}

// --- ported from jcs/lone_surrogate_rawjson_test.go ---

#[test]
fn raw_json_rejects_lone_surrogate() {
    let cases: &[(&str, &str)] = &[
        ("value", r#"{"x":"\uD800"}"#),
        ("lone-low", r#"{"x":"\uDC00"}"#),
        ("member-name", r#"{"\uD800":"x"}"#),
        ("nested", r#"{"a":{"b":"\uD800"}}"#),
        ("array-element", r#"{"a":["\uD800"]}"#),
        ("mid-string", r#"{"x":"a\uD800b"}"#),
    ];
    let lone = jcs::JcsError::InvalidUnicode {
        reason: "lone_surrogate",
    };
    for (name, raw) in cases {
        assert_eq!(
            jcs::validate_json_text(raw.as_bytes()),
            Err(lone.clone()),
            "{name}: validate_json_text"
        );
        assert_eq!(
            jcs::canonicalize_json(raw.as_bytes()),
            Err(lone.clone()),
            "{name}: canonicalize_json"
        );
    }
}

#[test]
fn raw_json_accepts_genuine_replacement_char() {
    let raw = "{\"x\":\"\u{FFFD}\"}";
    let got = jcs::canonicalize_json(raw.as_bytes()).unwrap();
    assert_eq!(got, "{\"x\":\"\u{FFFD}\"}");
}

#[test]
fn raw_json_escaped_backslash_not_flagged() {
    // An escaped backslash then the literal text uD800: a valid string.
    let raw = r#"{"x":"\\uD800"}"#;
    assert_eq!(jcs::validate_json_text(raw.as_bytes()), Ok(()));
}

#[test]
fn raw_json_escaped_valid_pair_accepted() {
    let raw = r#"{"x":"😀"}"#;
    let got = jcs::canonicalize_json(raw.as_bytes()).unwrap();
    assert_eq!(got, "{\"x\":\"\u{1F600}\"}");
}

#[test]
fn raw_json_valid_pair_followed_by_lone_low_rejects() {
    let raw = r#"{"x":"😀\uDC00"}"#;
    assert_eq!(
        jcs::validate_json_text(raw.as_bytes()),
        Err(jcs::JcsError::InvalidUnicode {
            reason: "lone_surrogate"
        })
    );
}

#[test]
fn reject_general_invalid_utf8_bytes() {
    let mut raw = b"{\"v\":\"".to_vec();
    raw.extend_from_slice(&[0xFF, 0xFE]);
    raw.extend_from_slice(b"\"}");
    assert_eq!(
        jcs::validate_json_text(&raw),
        Err(jcs::JcsError::InvalidUnicode {
            reason: "invalid_utf8"
        })
    );
}

#[test]
fn error_contract_is_stable_and_leak_free() {
    let raw = r#"{"secret-value-x":"\uD800"}"#;
    let err = jcs::canonicalize_json(raw.as_bytes()).unwrap_err();
    assert_eq!(err.category(), "invalid_unicode");
    let message = err.to_string();
    assert!(
        message.contains("lone_surrogate"),
        "reason must appear: {message}"
    );
    assert!(
        !message.contains("secret-value-x") && !message.contains('\u{FFFD}'),
        "error message must not leak input: {message}"
    );
}

#[test]
fn valid_inputs_unchanged_by_raw_layer() {
    let raw = r#"{"b":1,"a":"x","n":[1,2,3],"z":null}"#;
    let via_raw = jcs::canonicalize_json(raw.as_bytes()).unwrap();
    assert_eq!(via_raw, r#"{"a":"x","b":1,"n":[1,2,3],"z":null}"#);
    let value: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(jcs::canonicalize(&value).unwrap(), via_raw);
}

// --- ported from jcs/lone_surrogate_adversarial_test.go ---

#[test]
fn scanner_adversarial_cases() {
    let reject: &[(&str, &str)] = &[
        ("space-separated-non-adjacent", r#"{"v":"\uD800 \uDC00"}"#),
        (
            "newline-separated-non-adjacent",
            "{\"v\":\"\\uD800\\n\\uDC00\"}",
        ),
        ("lone-low-first", r#"{"v":"\uDC00"}"#),
        ("low-then-high", r#"{"v":"\uDC00\uD800"}"#),
        ("high-then-literal-low", r#"{"v":"\uD800\\uDC00"}"#),
        ("lone-in-key", r#"{"\uD800":"x"}"#),
        ("lowercase-hex", r#"{"v":"\ud800"}"#),
        ("literal-backslash-then-lone", r#"{"v":"\\\uD800"}"#),
    ];
    for (name, raw) in reject {
        assert_eq!(
            jcs::validate_json_text(raw.as_bytes()),
            Err(jcs::JcsError::InvalidUnicode {
                reason: "lone_surrogate"
            }),
            "{name}"
        );
    }

    let accept: &[(&str, &str)] = &[
        ("valid-adjacent-pair", r#"{"v":"😀"}"#),
        ("escaped-backslash-literal", r#"{"v":"\\uD800"}"#),
        ("double-backslash-literal", r#"{"v":"\\\\uD800"}"#),
    ];
    for (name, raw) in accept {
        assert_eq!(jcs::validate_json_text(raw.as_bytes()), Ok(()), "{name}");
    }
}

// --- ported from jcs/lone_surrogate_crosssdk_test.go (standalone half) ---
//
// The Go test shells out to Python and the TypeScript checkout; the committed
// Rust suite must run standalone, so this pins the same terminal states from
// vendored inputs. The live cross-implementation check against the pinned
// TypeScript checkout runs as a handoff gate, not here.

#[test]
fn cross_sdk_terminal_states_standalone() {
    // The lone surrogate, reaching this SDK as text, is rejected before
    // anything could sign it.
    assert!(jcs::canonicalize_json(br#"{"v":"\uD800"}"#).is_err());
    // The valid non-BMP scalar is accepted.
    assert_eq!(
        jcs::canonicalize_json("{\"v\":\"\u{1F600}\"}".as_bytes()).unwrap(),
        "{\"v\":\"\u{1F600}\"}"
    );
}
