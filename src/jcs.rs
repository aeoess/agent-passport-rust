//! Strict RFC 8785 (JCS) canonicalization, the strict I-JSON validator, and
//! the bounded raw-JSON entry point for signed receipt-core inputs.
//!
//! Byte parity target: `canonicalizeJCS` in the reference TypeScript SDK
//! (`src/core/canonical-jcs.ts`) and the frozen conformance vectors. The
//! reference runs on JavaScript doubles, so [`canonicalize`] converts every
//! JSON number to an IEEE 754 double before formatting, exactly as
//! `JSON.parse` does. An integer above 2 to the 53 loses precision here on
//! purpose; keeping 64-bit fidelity would produce bytes the reference cannot
//! produce.
//!
//! Lone UTF-16 surrogates cannot exist inside a Rust `String`, so the
//! programmatic-string rejection the TypeScript and Go SDKs perform is
//! structurally guaranteed for already-constructed values. The raw-text entry
//! points ([`validate_json_text`], [`canonicalize_json`],
//! [`parse_strict_ijson`]) enforce it for text input, where a lone surrogate
//! can appear as a `\uXXXX` escape or as invalid UTF-8 bytes.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Largest integer the reference treats as interoperable: 2^53 - 1.
const MAX_SAFE_INTEGER: f64 = 9007199254740991.0;

/// Default byte bound for [`parse_strict_ijson`], matching the reference
/// receipt-core layer (1 MiB).
pub const DEFAULT_MAX_UTF8_BYTES: usize = 1_048_576;

/// Default nesting bound for [`parse_strict_ijson`], matching the reference
/// receipt-core layer.
pub const DEFAULT_MAX_DEPTH: usize = 128;

/// Canonicalization failure. The offending input is never included in the
/// message: signed payloads may be sensitive.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum JcsError {
    /// The input contains a string that is not a sequence of Unicode scalar
    /// values. `reason` is `lone_surrogate` or `invalid_utf8`; the category,
    /// shared across the APS SDKs, is `invalid_unicode`.
    #[error("jcs: invalid_unicode ({reason}); RFC 8785 requires rejection")]
    InvalidUnicode {
        /// Specific failure: `lone_surrogate` or `invalid_utf8`.
        reason: &'static str,
    },
    /// The raw text is not a single well-formed JSON document.
    #[error("jcs: input is not a single well-formed JSON document")]
    MalformedJson,
    /// A number is not representable as a finite IEEE 754 double.
    #[error("jcs: Infinity and NaN are not valid JSON numbers")]
    NonFinite,
}

impl JcsError {
    /// Stable machine-readable category shared across the APS SDKs.
    pub fn category(&self) -> &'static str {
        match self {
            JcsError::InvalidUnicode { .. } => "invalid_unicode",
            JcsError::MalformedJson => "malformed_json",
            JcsError::NonFinite => "non_finite_number",
        }
    }
}

fn lone_surrogate() -> JcsError {
    JcsError::InvalidUnicode {
        reason: "lone_surrogate",
    }
}

fn invalid_utf8() -> JcsError {
    JcsError::InvalidUnicode {
        reason: "invalid_utf8",
    }
}

/// RFC 8785 canonical form of an already-constructed JSON value.
///
/// Invariants pinned to the reference:
/// - object keys sort by UTF-16 code unit, not by code point or byte
/// - null members are preserved (the legacy profile strips them; see
///   [`crate::legacy_canonical`])
/// - numbers format per the ECMAScript Number-to-String algorithm after
///   conversion to an IEEE 754 double, so `-0` becomes `0` and an integer
///   above 2^53 rounds exactly as `JSON.parse` rounds it
/// - only `"`, `\` and control characters below U+0020 are escaped, with
///   lowercase hex in `\u00xx` escapes
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let normalized = to_double_view(value)?;
    serde_json_canonicalizer::to_string(&normalized).map_err(|_| JcsError::NonFinite)
}

/// Lowercase-hex SHA-256 of [`canonicalize`] output, the strict-JCS hash used
/// for `action_ref` and other cross-implementation pins.
pub fn canonical_hash(value: &Value) -> Result<String, JcsError> {
    let canonical = canonicalize(value)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Rebuild `value` with every number passed through an IEEE 754 double,
/// mirroring what `JSON.parse` in the reference implementation produces.
fn to_double_view(value: &Value) -> Result<Value, JcsError> {
    Ok(match value {
        Value::Number(n) => {
            let double = n.as_f64().ok_or(JcsError::NonFinite)?;
            if !double.is_finite() {
                return Err(JcsError::NonFinite);
            }
            Value::Number(serde_json::Number::from_f64(double).ok_or(JcsError::NonFinite)?)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(to_double_view)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Object(members) => {
            let mut rebuilt = Map::new();
            for (key, member) in members {
                rebuilt.insert(key.clone(), to_double_view(member)?);
            }
            Value::Object(rebuilt)
        }
        other => other.clone(),
    })
}

fn hex4(bytes: &[u8]) -> Option<u32> {
    let mut v: u32 = 0;
    for &c in bytes {
        v <<= 4;
        match c {
            b'0'..=b'9' => v |= u32::from(c - b'0'),
            b'a'..=b'f' => v |= u32::from(c - b'a') + 10,
            b'A'..=b'F' => v |= u32::from(c - b'A') + 10,
            _ => return None,
        }
    }
    Some(v)
}

/// Scan raw JSON text for an unpaired `\uXXXX` surrogate escape inside a
/// string. String-aware and escape-aware: an escaped backslash followed by
/// literal `uD800` text is not flagged, and a valid escaped pair passes.
/// Must run on the unparsed text, before any decoder can substitute U+FFFD.
fn has_lone_surrogate_escape(bytes: &[u8]) -> bool {
    let n = bytes.len();
    let mut i = 0;
    let mut in_string = false;
    while i < n {
        let c = bytes[i];
        if !in_string {
            if c == b'"' {
                in_string = true;
            }
            i += 1;
            continue;
        }
        if c == b'\\' {
            if i + 1 >= n {
                return false; // malformed; the JSON decoder reports it
            }
            if bytes[i + 1] == b'u' {
                if i + 6 > n {
                    i += 2;
                    continue;
                }
                let Some(code) = hex4(&bytes[i + 2..i + 6]) else {
                    i += 6;
                    continue;
                };
                if (0xD800..=0xDBFF).contains(&code) {
                    if i + 12 <= n && bytes[i + 6] == b'\\' && bytes[i + 7] == b'u' {
                        if let Some(lo) = hex4(&bytes[i + 8..i + 12]) {
                            if (0xDC00..=0xDFFF).contains(&lo) {
                                i += 12; // valid pair
                                continue;
                            }
                        }
                    }
                    return true;
                }
                if (0xDC00..=0xDFFF).contains(&code) {
                    return true;
                }
                i += 6;
                continue;
            }
            i += 2;
            continue;
        }
        if c == b'"' {
            in_string = false;
        }
        i += 1;
    }
    false
}

/// Unicode validator for raw JSON text, not a JSON-grammar validator.
///
/// Rejects text that cannot canonicalize to Unicode scalar values: invalid
/// UTF-8 bytes, or an unpaired `\uXXXX` surrogate escape inside a string.
/// Runs before any decoding, because a decoder that substitutes U+FFFD
/// destroys the evidence. A genuine U+FFFD in the input is a valid scalar and
/// is accepted. Two linear passes, no allocation.
pub fn validate_json_text(raw: &[u8]) -> Result<(), JcsError> {
    if std::str::from_utf8(raw).is_err() {
        return Err(invalid_utf8());
    }
    if has_lone_surrogate_escape(raw) {
        return Err(lone_surrogate());
    }
    Ok(())
}

/// Validate raw JSON text ([`validate_json_text`]), parse it, and
/// canonicalize. The safe generic entry point for raw JSON text that may
/// carry a lone surrogate. For signed receipt-core inputs use
/// [`parse_strict_ijson`], which additionally bounds size and depth and
/// rejects duplicate member names.
pub fn canonicalize_json(raw: &[u8]) -> Result<String, JcsError> {
    validate_json_text(raw)?;
    let value: Value = serde_json::from_slice(raw).map_err(|_| JcsError::MalformedJson)?;
    canonicalize(&value)
}

/// Strict I-JSON violation at the signed receipt-core input boundary. The
/// offending input is never included in the message.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IJsonError {
    /// Input exceeds the UTF-8 byte bound.
    #[error("strict i-json: raw JSON size limit exceeded")]
    SizeLimit,
    /// Input exceeds the nesting bound.
    #[error("strict i-json: JSON nesting limit exceeded")]
    DepthLimit,
    /// Input is not valid UTF-8.
    #[error("strict i-json: invalid UTF-8")]
    InvalidUtf8,
    /// A string carries an unpaired UTF-16 surrogate escape.
    #[error("strict i-json: unpaired surrogate")]
    LoneSurrogate,
    /// An object repeats a member name after JSON escape decoding.
    #[error("strict i-json: duplicate object member")]
    DuplicateMember,
    /// A number is non-finite or an integer outside the interoperable
    /// IEEE 754 range (|n| > 2^53 - 1).
    #[error("strict i-json: number outside the interoperable range")]
    UnsafeNumber,
    /// The text is not a single well-formed strict JSON document.
    #[error("strict i-json: malformed JSON")]
    Malformed,
}

/// Validate an already-constructed value against the strict I-JSON rules the
/// reference receipt-core layer enforces: finite numbers only, and integral
/// values must stay within |n| <= 2^53 - 1. This is deliberately stricter
/// than [`canonicalize`], whose frozen parity vectors include the exactly
/// representable value 9007199254740994.
pub fn assert_ijson(value: &Value) -> Result<(), IJsonError> {
    match value {
        Value::Number(n) => {
            let double = n.as_f64().ok_or(IJsonError::UnsafeNumber)?;
            if !double.is_finite() {
                return Err(IJsonError::UnsafeNumber);
            }
            if double.fract() == 0.0 && double.abs() > MAX_SAFE_INTEGER {
                return Err(IJsonError::UnsafeNumber);
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(assert_ijson),
        Value::Object(members) => members.values().try_for_each(assert_ijson),
        _ => Ok(()),
    }
}

/// Canonicalize under the strict I-JSON contract: [`assert_ijson`] first,
/// then RFC 8785. The receipt-core preimage path.
pub fn strict_jcs(value: &Value) -> Result<String, IJsonError> {
    assert_ijson(value)?;
    canonicalize(value).map_err(|error| match error {
        JcsError::InvalidUnicode {
            reason: "lone_surrogate",
        } => IJsonError::LoneSurrogate,
        JcsError::InvalidUnicode { .. } => IJsonError::InvalidUtf8,
        JcsError::NonFinite => IJsonError::UnsafeNumber,
        JcsError::MalformedJson => IJsonError::Malformed,
    })
}

/// Lowercase-hex SHA-256 of [`strict_jcs`] output.
pub fn strict_jcs_hash(value: &Value) -> Result<String, IJsonError> {
    let canonical = strict_jcs(value)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Parse bounded raw JSON for the signed receipt-core boundary, without
/// losing duplicate member names, invalid-Unicode evidence, number fidelity,
/// or field presence.
///
/// Contract, matching the reference `parseStrictIJson`:
/// - at most `max_utf8_bytes` UTF-8 bytes (default 1 MiB)
/// - at most `max_depth` nesting levels (default 128)
/// - invalid UTF-8 rejected
/// - lone surrogate escapes rejected; valid pairs and genuine U+FFFD accepted
/// - duplicate object member names rejected after escape decoding, so `"a"`
///   and `"a"` are the same member name
/// - trailing data rejected
/// - non-finite numbers and integers outside |n| <= 2^53 - 1 rejected
/// - omitted members and explicit null stay distinguishable in the result
pub fn parse_strict_ijson(
    raw: &[u8],
    max_utf8_bytes: usize,
    max_depth: usize,
) -> Result<Value, IJsonError> {
    if max_utf8_bytes < 1 || raw.len() > max_utf8_bytes {
        return Err(IJsonError::SizeLimit);
    }
    if max_depth < 1 {
        return Err(IJsonError::DepthLimit);
    }
    let text = std::str::from_utf8(raw).map_err(|_| IJsonError::InvalidUtf8)?;
    let mut parser = StrictParser {
        bytes: text.as_bytes(),
        offset: 0,
        max_depth,
    };
    let value = parser.parse_value(1)?;
    parser.skip_whitespace();
    if parser.offset != parser.bytes.len() {
        return Err(IJsonError::Malformed);
    }
    Ok(value)
}

/// [`parse_strict_ijson`] with the reference defaults (1 MiB, depth 128).
pub fn parse_strict_ijson_default(raw: &[u8]) -> Result<Value, IJsonError> {
    parse_strict_ijson(raw, DEFAULT_MAX_UTF8_BYTES, DEFAULT_MAX_DEPTH)
}

struct StrictParser<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_depth: usize,
}

impl StrictParser<'_> {
    fn skip_whitespace(&mut self) {
        while let Some(&c) = self.bytes.get(self.offset) {
            if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
                self.offset += 1;
            } else {
                break;
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, IJsonError> {
        debug_assert_eq!(self.bytes[self.offset], b'"');
        self.offset += 1;
        let mut out = String::new();
        loop {
            let &c = self.bytes.get(self.offset).ok_or(IJsonError::Malformed)?;
            match c {
                b'"' => {
                    self.offset += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.offset += 1;
                    let &esc = self.bytes.get(self.offset).ok_or(IJsonError::Malformed)?;
                    self.offset += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let code = self.parse_hex4()?;
                            if (0xDC00..=0xDFFF).contains(&code) {
                                return Err(IJsonError::LoneSurrogate);
                            }
                            if (0xD800..=0xDBFF).contains(&code) {
                                if self.bytes.get(self.offset) != Some(&b'\\')
                                    || self.bytes.get(self.offset + 1) != Some(&b'u')
                                {
                                    return Err(IJsonError::LoneSurrogate);
                                }
                                self.offset += 2;
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(IJsonError::LoneSurrogate);
                                }
                                let scalar = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                out.push(char::from_u32(scalar).ok_or(IJsonError::Malformed)?);
                            } else {
                                out.push(char::from_u32(code).ok_or(IJsonError::Malformed)?);
                            }
                        }
                        _ => return Err(IJsonError::Malformed),
                    }
                }
                0x00..=0x1F => return Err(IJsonError::Malformed),
                _ => {
                    // Copy one UTF-8 encoded character. The input is already
                    // validated UTF-8, so the boundary math cannot fail.
                    let start = self.offset;
                    let width = utf8_width(c);
                    self.offset += width;
                    let chunk = self
                        .bytes
                        .get(start..start + width)
                        .ok_or(IJsonError::Malformed)?;
                    out.push_str(std::str::from_utf8(chunk).map_err(|_| IJsonError::InvalidUtf8)?);
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, IJsonError> {
        let chunk = self
            .bytes
            .get(self.offset..self.offset + 4)
            .ok_or(IJsonError::Malformed)?;
        let code = hex4(chunk).ok_or(IJsonError::Malformed)?;
        self.offset += 4;
        Ok(code)
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, IJsonError> {
        if depth > self.max_depth {
            return Err(IJsonError::DepthLimit);
        }
        self.skip_whitespace();
        let &token = self.bytes.get(self.offset).ok_or(IJsonError::Malformed)?;
        match token {
            b'"' => Ok(Value::String(self.parse_string()?)),
            b'{' => {
                self.offset += 1;
                let mut members = Map::new();
                self.skip_whitespace();
                if self.bytes.get(self.offset) == Some(&b'}') {
                    self.offset += 1;
                    return Ok(Value::Object(members));
                }
                loop {
                    self.skip_whitespace();
                    if self.bytes.get(self.offset) != Some(&b'"') {
                        return Err(IJsonError::Malformed);
                    }
                    let name = self.parse_string()?;
                    if members.contains_key(&name) {
                        return Err(IJsonError::DuplicateMember);
                    }
                    self.skip_whitespace();
                    if self.bytes.get(self.offset) != Some(&b':') {
                        return Err(IJsonError::Malformed);
                    }
                    self.offset += 1;
                    let member = self.parse_value(depth + 1)?;
                    members.insert(name, member);
                    self.skip_whitespace();
                    let &separator = self.bytes.get(self.offset).ok_or(IJsonError::Malformed)?;
                    self.offset += 1;
                    match separator {
                        b'}' => return Ok(Value::Object(members)),
                        b',' => {}
                        _ => return Err(IJsonError::Malformed),
                    }
                }
            }
            b'[' => {
                self.offset += 1;
                let mut items = Vec::new();
                self.skip_whitespace();
                if self.bytes.get(self.offset) == Some(&b']') {
                    self.offset += 1;
                    return Ok(Value::Array(items));
                }
                loop {
                    items.push(self.parse_value(depth + 1)?);
                    self.skip_whitespace();
                    let &separator = self.bytes.get(self.offset).ok_or(IJsonError::Malformed)?;
                    self.offset += 1;
                    match separator {
                        b']' => return Ok(Value::Array(items)),
                        b',' => {}
                        _ => return Err(IJsonError::Malformed),
                    }
                }
            }
            _ => {
                for (literal, value) in [
                    (&b"true"[..], Value::Bool(true)),
                    (&b"false"[..], Value::Bool(false)),
                    (&b"null"[..], Value::Null),
                ] {
                    if self.bytes[self.offset..].starts_with(literal) {
                        self.offset += literal.len();
                        return Ok(value);
                    }
                }
                self.parse_number()
            }
        }
    }

    fn parse_number(&mut self) -> Result<Value, IJsonError> {
        let start = self.offset;
        let bytes = self.bytes;
        let mut i = self.offset;
        if bytes.get(i) == Some(&b'-') {
            i += 1;
        }
        match bytes.get(i) {
            Some(b'0') => i += 1,
            Some(b'1'..=b'9') => {
                while matches!(bytes.get(i), Some(b'0'..=b'9')) {
                    i += 1;
                }
            }
            _ => return Err(IJsonError::Malformed),
        }
        let mut is_integer_token = true;
        if bytes.get(i) == Some(&b'.') {
            is_integer_token = false;
            i += 1;
            if !matches!(bytes.get(i), Some(b'0'..=b'9')) {
                return Err(IJsonError::Malformed);
            }
            while matches!(bytes.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        if matches!(bytes.get(i), Some(b'e') | Some(b'E')) {
            is_integer_token = false;
            i += 1;
            if matches!(bytes.get(i), Some(b'+') | Some(b'-')) {
                i += 1;
            }
            if !matches!(bytes.get(i), Some(b'0'..=b'9')) {
                return Err(IJsonError::Malformed);
            }
            while matches!(bytes.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        self.offset = i;
        let token = std::str::from_utf8(&bytes[start..i]).map_err(|_| IJsonError::InvalidUtf8)?;
        let double: f64 = token.parse().map_err(|_| IJsonError::Malformed)?;
        if !double.is_finite() {
            return Err(IJsonError::UnsafeNumber);
        }
        if double.fract() == 0.0 && double.abs() > MAX_SAFE_INTEGER {
            return Err(IJsonError::UnsafeNumber);
        }
        // A plain integer token stays an integer in the parsed value so typed
        // consumers see it as one; the safe-range check above guarantees it
        // fits an i64 exactly.
        if is_integer_token {
            let integer = double as i64;
            return Ok(Value::Number(serde_json::Number::from(integer)));
        }
        Ok(Value::Number(
            serde_json::Number::from_f64(double).ok_or(IJsonError::UnsafeNumber)?,
        ))
    }
}

fn utf8_width(first_byte: u8) -> usize {
    match first_byte {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}
