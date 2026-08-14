//! Ed25519 verification over the raw hex encodings the APS SDKs exchange.
//!
//! Parity target: `verify` in the reference TypeScript SDK
//! (`src/crypto/keys.ts`, Node crypto over OpenSSL) and `VerifyEd25519` in
//! the Go implementation (`verify/verify.go`, crypto/ed25519). All three
//! implement the RFC 8032 verification equation without the additional
//! `verify_strict` checks: `ed25519_dalek::VerifyingKey::verify` is used
//! deliberately, because `verify_strict` rejects some inputs (for example
//! small-order public keys) that Node and Go accept, and byte-for-byte
//! compatibility with the reference decides. The pinned boundary behaviors
//! are: mixed-case hex accepted, wrong lengths rejected before any parsing,
//! and a signature whose scalar is not canonical (S plus the group order)
//! rejected, as all three implementations reject it.
//!
//! This module is verification-only. There is no key generation and no
//! signing.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify a raw Ed25519 signature over `message`.
///
/// `public_key_hex` must be exactly 64 hex characters (32 bytes) and
/// `signature_hex` exactly 128 hex characters (64 bytes); any other length
/// returns `false` before any decoding, closing the key-equivocation gap the
/// reference closes (a longer key whose leading 32 bytes are valid must not
/// verify). Uppercase and lowercase hex are both accepted, matching the
/// reference SDKs. Malformed hex, an invalid point encoding, a wrong key, a
/// modified message, and a modified or non-canonical signature all return
/// `false`.
///
/// This is the one deliberately `bool`-valued primitive in the crate: it
/// answers exactly one question. Higher-level verifiers wrap it in typed
/// results.
pub fn verify_ed25519(message: &[u8], signature_hex: &str, public_key_hex: &str) -> bool {
    if public_key_hex.len() != 64 || signature_hex.len() != 128 {
        return false;
    }
    let Ok(public_key_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(signature_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(public_key_array): Result<[u8; 32], _> = public_key_bytes.try_into() else {
        return false;
    };
    let Ok(signature_array): Result<[u8; 64], _> = signature_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key_array) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_array);
    verifying_key.verify(message, &signature).is_ok()
}
