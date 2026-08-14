//! The legacy APS canonical form: sorted keys with null-valued object members
//! removed, plus the shared timestamp normalizer.
//!
//! Byte parity target: `canonicalize` in the reference TypeScript SDK
//! (`src/core/canonical.ts`). Null-stripping is intentional and consistent
//! across all APS implementations: `{a:1}` and `{a:1,b:null}` produce the
//! same canonical form, so no security-critical field may use null as a
//! meaningful value. Passports and legacy delegations sign over this form.
//! `action_ref` and receipt-core use strict JCS ([`crate::jcs`]) instead,
//! which preserves nulls; the two profiles must never be swapped.
//!
//! Array elements are not stripped: a null inside an array serializes as
//! `null` in both profiles.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::jcs::JcsError;

/// Legacy canonical form of a JSON value: object keys sorted (UTF-16 code
/// unit order, the JavaScript default sort), null-valued object members
/// removed, array nulls preserved, leaves formatted exactly as the strict
/// JCS profile formats them.
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_legacy(&mut out, value)?;
    Ok(out)
}

/// Lowercase-hex SHA-256 of [`canonicalize`] output, matching the reference
/// `canonicalHash`.
pub fn canonical_hash(value: &Value) -> Result<String, JcsError> {
    let canonical = canonicalize(value)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn write_legacy(out: &mut String, value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_legacy(out, item)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut keys: Vec<&String> = members
                .keys()
                .filter(|key| !members[key.as_str()].is_null())
                .collect();
            keys.sort_by_key(|a| utf16_units(a));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_legacy(out, &Value::String((*key).clone()))?;
                out.push(':');
                write_legacy(out, &members[key.as_str()])?;
            }
            out.push('}');
        }
        // Leaves (null, bool, number, string) format identically in both
        // profiles; delegate to the strict JCS serializer so the two paths
        // cannot drift on number or escape formatting.
        leaf => out.push_str(&crate::jcs::canonicalize(leaf)?),
    }
    Ok(())
}

fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Timestamp normalization failure. The input is echoed only by length, never
/// by content.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("normalize_timestamp: invalid timestamp")]
pub struct TimestampError;

/// Normalize an RFC 3339 timestamp to second-precision UTC,
/// `YYYY-MM-DDTHH:MM:SSZ`, matching the reference `normalizeTimestamp`
/// (`new Date(ts).toISOString()` with the millisecond suffix stripped).
/// Fractional seconds truncate toward zero; offsets convert to UTC.
///
/// The reference accepts every string the JavaScript `Date` constructor
/// parses. This port, like the Go implementation, accepts the interoperable
/// subset: RFC 3339 with an explicit offset or `Z`. Anything else is
/// rejected rather than guessed.
pub fn normalize_timestamp(ts: &str) -> Result<String, TimestampError> {
    let parsed = time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
        .map_err(|_| TimestampError)?;
    let utc = parsed.to_offset(time::UtcOffset::UTC);
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    ))
}
