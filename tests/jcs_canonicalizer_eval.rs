//! Evaluation gate for the serde_json_canonicalizer dependency, run before it
//! was accepted behind the crate's own wrapper: every named JCS vector plus
//! the Go ES-number boundary cases must pass through the library directly.
//! The wrapper's own parity run lives in jcs_vectors.rs.

use serde_json::Value;

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(serde::Deserialize)]
struct CanonicalBytesDoc {
    vectors: Vec<CanonicalBytesVector>,
}

#[derive(serde::Deserialize)]
struct CanonicalBytesVector {
    name: String,
    input: Value,
    canonical: String,
    canonical_bytes_hex: String,
    canonical_sha256: String,
}

#[test]
fn library_passes_canonical_bytes_vectors() {
    let raw = include_str!("vectors/canonical-bytes-jcs-v1.json");
    let doc: CanonicalBytesDoc = serde_json::from_str(raw).expect("fixture parses");
    assert_eq!(doc.vectors.len(), 8, "fixture must carry 8 vectors");
    for vector in &doc.vectors {
        let got = serde_json_canonicalizer::to_string(&vector.input)
            .unwrap_or_else(|e| panic!("{}: canonicalizer error {e}", vector.name));
        assert_eq!(got, vector.canonical, "{}: canonical string", vector.name);
        assert_eq!(
            hex::encode(got.as_bytes()),
            vector.canonical_bytes_hex,
            "{}: canonical bytes",
            vector.name
        );
        assert_eq!(
            sha256_hex(&got),
            vector.canonical_sha256,
            "{}: canonical sha256",
            vector.name
        );
    }
}

#[derive(serde::Deserialize)]
struct BilateralDoc {
    vectors: Vec<BilateralVector>,
}

#[derive(serde::Deserialize)]
struct BilateralVector {
    name: String,
    input: Value,
    canonical_bytes_hex: String,
    canonical_sha256: String,
}

#[test]
fn library_passes_bilateral_vectors() {
    let raw = include_str!("vectors/canonicalize-fixture-v1.json");
    let doc: BilateralDoc = serde_json::from_str(raw).expect("fixture parses");
    assert_eq!(doc.vectors.len(), 10, "fixture must carry 10 vectors");
    for vector in &doc.vectors {
        let got = serde_json_canonicalizer::to_string(&vector.input)
            .unwrap_or_else(|e| panic!("{}: canonicalizer error {e}", vector.name));
        assert_eq!(
            hex::encode(got.as_bytes()),
            vector.canonical_bytes_hex,
            "{}: canonical bytes",
            vector.name
        );
        assert_eq!(
            sha256_hex(&got),
            vector.canonical_sha256,
            "{}: canonical sha256",
            vector.name
        );
    }
}

#[test]
fn library_passes_es_number_boundaries() {
    // From the Go jcs/esnumber_test.go table, validated there against Node
    // JSON.stringify over 20k values.
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
        let got = serde_json_canonicalizer::to_string(input).expect("number canonicalizes");
        assert_eq!(&got, expected, "esNumber({input})");
    }
    // Negative zero prints as 0, per RFC 8785.
    assert_eq!(
        serde_json_canonicalizer::to_string(&-0.0f64).expect("negative zero"),
        "0"
    );
}

#[test]
fn library_handles_surrogate_boundary_content() {
    // Rust strings cannot carry a lone surrogate, so the library only ever
    // sees scalar values. Pin the two boundary behaviors that remain: a valid
    // non-BMP scalar emits raw UTF-8, and a genuine U+FFFD is preserved.
    let emoji = serde_json::json!({ "v": "\u{1F600}" });
    let got = serde_json_canonicalizer::to_string(&emoji).expect("non-BMP scalar");
    assert_eq!(got, "{\"v\":\"\u{1F600}\"}");
    assert_eq!(got.as_bytes()[6], 0xF0, "raw 4-byte UTF-8, not an escape");

    let replacement = serde_json::json!({ "v": "\u{FFFD}" });
    assert_eq!(
        serde_json_canonicalizer::to_string(&replacement).expect("U+FFFD"),
        "{\"v\":\"\u{FFFD}\"}"
    );
}

#[test]
fn library_sorts_keys_by_utf16_code_unit() {
    // U+1D306 (astral, UTF-16 lead 0xD834) must sort before U+FF61 (BMP,
    // 0xFF61) even though its code point is higher. A byte or code-point sort
    // gets this backwards; the astral-key-ordering fixture vector pins the
    // same fact with frozen bytes.
    let value = serde_json::json!({ "\u{1D306}": 2, "\u{FF61}": 1 });
    let got = serde_json_canonicalizer::to_string(&value).expect("astral keys");
    assert_eq!(got, "{\"\u{1D306}\":2,\"\u{FF61}\":1}");
}
