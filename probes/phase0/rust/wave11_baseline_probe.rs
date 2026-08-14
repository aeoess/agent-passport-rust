//! TEMPORARY wave 1.1 Phase 0 probe, run at BASELINE
//! 5a1b03084c573b062461e9772e907656ecebc424 and then deleted; never
//! committed. Captures the Rust baseline column of the reference behavior
//! matrix, the item 4 corrected duplicate-member test against the baseline
//! implementation, and the item 5 Rust rows.

use agent_passport::crypto::verify_ed25519;
use agent_passport::delegation::verify_chain_structure;
use agent_passport::jcs::{parse_strict_ijson_default, IJsonError};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

fn chain(doc: &str) -> Vec<Value> {
    serde_json::from_str::<Value>(doc)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn row(id: &str, outcome: &str, detail: &str) {
    println!("ROW|{id}|baseline|{outcome}|{detail}");
}

#[test]
fn baseline_matrix_rows() {
    // Item 1 defect: a non-string scope element is silently discarded.
    let mixed_covered = chain(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read",42],"currentDepth":1}
        ]"#,
    );
    match verify_chain_structure(&mixed_covered) {
        Ok(()) => row("scope-child-mixed-type", "ACCEPT", "42 silently discarded"),
        Err(e) => row("scope-child-mixed-type", "REJECT", &format!("{e:?}")),
    }
    let mixed_widening = chain(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["evil",42],"currentDepth":1}
        ]"#,
    );
    match verify_chain_structure(&mixed_widening) {
        Ok(()) => row("scope-child-mixed-widening", "ACCEPT", "unexpected"),
        Err(e) => row(
            "scope-child-mixed-widening",
            "REJECT",
            &format!("{e:?} (only the string element was examined)"),
        ),
    }
    let single_mixed = chain(
        r#"[{"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read",42],"currentDepth":0}]"#,
    );
    match verify_chain_structure(&single_mixed) {
        Ok(()) => row("scope-single-link-mixed", "ACCEPT", "single link never examined"),
        Err(e) => row("scope-single-link-mixed", "REJECT", &format!("{e:?}")),
    }
    let non_array = chain(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":"read","currentDepth":1}
        ]"#,
    );
    match verify_chain_structure(&non_array) {
        Ok(()) => row("scope-child-string", "ACCEPT", "non-array scope treated as empty"),
        Err(e) => row("scope-child-string", "REJECT", &format!("{e:?}")),
    }

    // Item 2 defect: fractional depths flow through as f64.
    let fractional = chain(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":-1.5},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":-0.5}
        ]"#,
    );
    match verify_chain_structure(&fractional) {
        Ok(()) => row("depth-fractional-negative-chain", "ACCEPT", "-1.5 -> -0.5 satisfies +1"),
        Err(e) => row("depth-fractional-negative-chain", "REJECT", &format!("{e:?}")),
    }
    let string_depth = chain(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":-1},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":"1"}
        ]"#,
    );
    match verify_chain_structure(&string_depth) {
        Ok(()) => row("depth-child-string", "ACCEPT", "string depth treated as absent (0)"),
        Err(e) => row("depth-child-string", "REJECT", &format!("{e:?}")),
    }
    let exponent = chain(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":0},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":1e0}
        ]"#,
    );
    match verify_chain_structure(&exponent) {
        Ok(()) => row("depth-child-exponent", "ACCEPT", "1e0 read as 1.0"),
        Err(e) => row("depth-child-exponent", "REJECT", &format!("{e:?}")),
    }
    let negative = chain(
        r#"[
        {"delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read"],"currentDepth":-2},
        {"delegatedBy":"agent-a","delegatedTo":"agent-b","scope":["read"],"currentDepth":-1}
        ]"#,
    );
    match verify_chain_structure(&negative) {
        Ok(()) => row("depth-negative-chain", "ACCEPT", "negative integral chain"),
        Err(e) => row("depth-negative-chain", "REJECT", &format!("{e:?}")),
    }

    // serde_json wire representation corners that shape the item 2 design.
    let minus_zero: Value = serde_json::from_str("-0").unwrap();
    row(
        "serde-minus-zero",
        "INFO",
        &format!(
            "is_i64={} is_f64={} as_f64={:?} sign_negative={:?}",
            minus_zero.is_i64(),
            minus_zero.is_f64(),
            minus_zero.as_f64(),
            minus_zero.as_f64().map(f64::is_sign_negative)
        ),
    );
    let minus_zero_frac: Value = serde_json::from_str("-0.0").unwrap();
    row(
        "serde-minus-zero-fractional",
        "INFO",
        &format!(
            "is_i64={} is_f64={} sign_negative={:?}",
            minus_zero_frac.is_i64(),
            minus_zero_frac.is_f64(),
            minus_zero_frac.as_f64().map(f64::is_sign_negative)
        ),
    );
    let exponent_num: Value = serde_json::from_str("1e0").unwrap();
    row(
        "serde-exponent",
        "INFO",
        &format!("is_i64={} is_f64={}", exponent_num.is_i64(), exponent_num.is_f64()),
    );
    let plain_one: Value = serde_json::from_str("1").unwrap();
    row(
        "serde-plain-integer",
        "INFO",
        &format!("is_i64={} is_f64={}", plain_one.is_i64(), plain_one.is_f64()),
    );
}

#[test]
fn item4_corrected_duplicate_alias_test_at_baseline() {
    // The corrected form of the vacuous wave 1 test: the second member name
    // is the JSON escape alias of the first. The input is assembled with an
    // explicit 0x5C backslash byte so no source-encoding or transport layer
    // can silently decode the escape, and the bytes are asserted to
    // physically carry the escape sequence.
    let mut raw: Vec<u8> = Vec::new();
    raw.extend_from_slice(br#"{"a":1,""#);
    raw.push(0x5C);
    raw.extend_from_slice(b"u0061");
    raw.extend_from_slice(br#"":2}"#);
    let escape: [u8; 6] = [0x5C, b'u', b'0', b'0', b'6', b'1'];
    assert!(
        raw.windows(6).any(|w| w == escape),
        "probe input must contain the literal escape bytes"
    );
    let result = parse_strict_ijson_default(&raw);
    row(
        "item4-escaped-alias-duplicate",
        if result == Err(IJsonError::DuplicateMember) {
            "REJECT-DuplicateMember"
        } else {
            "UNEXPECTED"
        },
        &format!("{result:?}"),
    );
    assert_eq!(result, Err(IJsonError::DuplicateMember));
}

#[test]
fn item5_rust_rows() {
    let small_order_pub = format!("01{}", "00".repeat(31));
    let small_order_sig = format!("01{}{}", "00".repeat(31), "00".repeat(32));
    let msg = b"APS wave1.1 small order probe";
    row(
        "smallorder-rust-verify_ed25519",
        if verify_ed25519(msg, &small_order_sig, &small_order_pub) {
            "ACCEPT"
        } else {
            "REJECT"
        },
        "crate public path",
    );
    let key_bytes: [u8; 32] = hex::decode(&small_order_pub).unwrap().try_into().unwrap();
    let sig_bytes: [u8; 64] = hex::decode(&small_order_sig).unwrap().try_into().unwrap();
    let key = VerifyingKey::from_bytes(&key_bytes).unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    row(
        "smallorder-dalek-verify_strict",
        if key.verify_strict(msg, &sig).is_ok() {
            "ACCEPT"
        } else {
            "REJECT"
        },
        "ed25519_dalek::VerifyingKey::verify_strict directly",
    );
}
