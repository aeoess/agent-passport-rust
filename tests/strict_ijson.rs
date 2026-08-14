//! The bounded raw-JSON entry point for signed receipt-core inputs, ported
//! from the reference parseStrictIJson (src/v2/receipt-core/jcs.ts) and its
//! safety contract.

use agent_passport::jcs::{
    self, parse_strict_ijson, parse_strict_ijson_default, IJsonError, DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_UTF8_BYTES,
};
use serde_json::{json, Value};

#[test]
fn defaults_match_the_reference_contract() {
    assert_eq!(DEFAULT_MAX_UTF8_BYTES, 1_048_576);
    assert_eq!(DEFAULT_MAX_DEPTH, 128);
}

#[test]
fn parses_valid_document_preserving_null_versus_omitted() {
    let value = parse_strict_ijson_default(br#"{"present":null,"other":1}"#).unwrap();
    let object = value.as_object().unwrap();
    assert!(object.contains_key("present"), "explicit null is present");
    assert_eq!(object["present"], Value::Null);
    assert!(
        !object.contains_key("absent"),
        "omitted member stays absent"
    );
}

#[test]
fn rejects_oversized_input() {
    let raw = format!("\"{}\"", "a".repeat(64));
    assert_eq!(
        parse_strict_ijson(raw.as_bytes(), 32, DEFAULT_MAX_DEPTH),
        Err(IJsonError::SizeLimit)
    );
    assert!(parse_strict_ijson(raw.as_bytes(), 1_024, DEFAULT_MAX_DEPTH).is_ok());
}

#[test]
fn rejects_excessive_depth_and_accepts_the_boundary() {
    let at_limit = format!("{}1{}", "[".repeat(9), "]".repeat(9));
    assert!(parse_strict_ijson(at_limit.as_bytes(), 1_024, 10).is_ok());
    let beyond = format!("{}1{}", "[".repeat(10), "]".repeat(10));
    assert_eq!(
        parse_strict_ijson(beyond.as_bytes(), 1_024, 10),
        Err(IJsonError::DepthLimit)
    );
}

#[test]
fn rejects_invalid_utf8() {
    assert_eq!(
        parse_strict_ijson_default(&[0x22, 0xFF, 0xFE, 0x22]),
        Err(IJsonError::InvalidUtf8)
    );
}

#[test]
fn rejects_lone_surrogate_escapes_and_accepts_pairs() {
    assert_eq!(
        parse_strict_ijson_default(br#""\uD800""#),
        Err(IJsonError::LoneSurrogate)
    );
    assert_eq!(
        parse_strict_ijson_default(br#""\uDC00""#),
        Err(IJsonError::LoneSurrogate)
    );
    assert_eq!(
        parse_strict_ijson_default(r#""😀""#.as_bytes()).unwrap(),
        Value::String("\u{1F600}".to_string())
    );
    // A genuine U+FFFD is a valid scalar.
    assert_eq!(
        parse_strict_ijson_default("\"\u{FFFD}\"".as_bytes()).unwrap(),
        Value::String("\u{FFFD}".to_string())
    );
}

#[test]
fn rejects_duplicate_members_after_escape_decoding() {
    assert_eq!(
        parse_strict_ijson_default(br#"{"a":1,"a":2}"#),
        Err(IJsonError::DuplicateMember)
    );
    // "a" decodes to "a": the alias is the same member name.
    assert_eq!(
        parse_strict_ijson_default(br#"{"a":1,"a":2}"#),
        Err(IJsonError::DuplicateMember)
    );
}

#[test]
fn rejects_trailing_data() {
    assert_eq!(
        parse_strict_ijson_default(br#"{"a":1} extra"#),
        Err(IJsonError::Malformed)
    );
    assert_eq!(
        parse_strict_ijson_default(br#"{"a":1}{"b":2}"#),
        Err(IJsonError::Malformed)
    );
    // Trailing whitespace alone is fine.
    assert!(parse_strict_ijson_default(b"{\"a\":1} \t\r\n").is_ok());
}

#[test]
fn rejects_unescaped_control_characters() {
    assert_eq!(
        parse_strict_ijson_default(b"\"a\x01b\""),
        Err(IJsonError::Malformed)
    );
}

#[test]
fn rejects_non_finite_and_unsafe_integers() {
    // 1e400 overflows the double range; JSON.parse gives Infinity and the
    // reference rejects non-finite.
    assert_eq!(
        parse_strict_ijson_default(b"1e400"),
        Err(IJsonError::UnsafeNumber)
    );
    // 2^53 - 1 is the last interoperable integer.
    assert_eq!(
        parse_strict_ijson_default(b"9007199254740991").unwrap(),
        json!(9007199254740991i64)
    );
    assert_eq!(
        parse_strict_ijson_default(b"9007199254740992"),
        Err(IJsonError::UnsafeNumber)
    );
    assert_eq!(
        parse_strict_ijson_default(b"-9007199254740992"),
        Err(IJsonError::UnsafeNumber)
    );
    // 1e21 is integral and far outside the safe range: the strict layer
    // rejects it even though generic JCS parity accepts it.
    assert_eq!(
        parse_strict_ijson_default(b"1e21"),
        Err(IJsonError::UnsafeNumber)
    );
    assert!(jcs::canonicalize(&json!(1e21)).is_ok());
}

#[test]
fn strict_and_generic_profiles_split_on_2pow53_plus_2() {
    // The frozen canonical-bytes vector integer-above-2pow53 pins the generic
    // profile accepting 9007199254740994. The strict receipt-core layer
    // rejects the same value. Both behaviors are the reference's.
    let value: Value = serde_json::from_str("9007199254740994").unwrap();
    assert_eq!(jcs::canonicalize(&value).unwrap(), "9007199254740994");
    assert_eq!(
        parse_strict_ijson_default(b"9007199254740994"),
        Err(IJsonError::UnsafeNumber)
    );
    assert_eq!(jcs::assert_ijson(&value), Err(IJsonError::UnsafeNumber));
}

#[test]
fn rejects_malformed_documents() {
    for raw in [
        &b"{"[..],
        b"{\"a\"}",
        b"{\"a\":}",
        b"{\"a\":1,}",
        b"[1,]",
        b"01",
        b"+1",
        b".5",
        b"\"unterminated",
        b"nul",
        b"",
        b"{1:2}",
    ] {
        assert!(
            parse_strict_ijson_default(raw).is_err(),
            "must reject: {raw:?}"
        );
    }
}

#[test]
fn integer_tokens_stay_integers_for_typed_consumers() {
    let value = parse_strict_ijson_default(br#"{"depth":3,"rate":0.5}"#).unwrap();
    assert!(
        value["depth"].is_i64(),
        "plain integer token stays integral"
    );
    assert!(value["rate"].is_f64());
}

#[test]
fn strict_jcs_round_trip_matches_generic_on_conforming_input() {
    let raw = br#"{"b":1,"a":"x","n":[1,2,3],"z":null}"#;
    let value = parse_strict_ijson_default(raw).unwrap();
    assert_eq!(
        jcs::strict_jcs(&value).unwrap(),
        r#"{"a":"x","b":1,"n":[1,2,3],"z":null}"#
    );
    assert_eq!(
        jcs::strict_jcs_hash(&value).unwrap(),
        jcs::canonical_hash(&value).unwrap()
    );
}
