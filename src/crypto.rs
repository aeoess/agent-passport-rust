//! Ed25519 verification over the raw hex encodings the APS SDKs exchange.
//!
//! Admissibility target: the behavior on which the two strict reference
//! implementations agree, libsodium (`agent-passport-python`
//! `src/agent_passport/crypto.py`) and `ed25519_dalek::VerifyingKey::
//! verify_strict` (`agent-passport-system` `crates/aps-verifier-core`). The
//! two were run over a corpus of 2534 vectors that includes the Wycheproof
//! Ed25519 suite, all eight small-order points in every encoding, small-order
//! R under honest keys, non-canonical encodings, s >= L, and 2048 ordinary
//! generated keys. They agreed on every vector, so that agreed behavior is
//! the rule and this crate implements it: a public key or an R that decodes
//! to a small-order point is inadmissible, a non-canonically encoded public
//! key or R is inadmissible, and a scalar s that is not reduced modulo the
//! group order is inadmissible. `verify_strict` is the dalek entry point that
//! enforces exactly that set.
//!
//! A small-order public key makes the RFC 8032 equation degenerate so one
//! signature verifies under every message, which is why permissive acceptance
//! is not a compatibility choice a verifier may make.
//!
//! The pinned boundary behaviors are unchanged: mixed-case hex accepted,
//! wrong lengths rejected before any parsing, and a signature whose scalar is
//! not canonical (S plus the group order) rejected.
//!
//! This module is verification-only. There is no key generation and no
//! signing. Signature preimages and canonical bytes are untouched.

use ed25519_dalek::{Signature, VerifyingKey};

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
/// A public key or an R that decodes to a small-order point, a non-canonical
/// encoding of either, and a non-reduced scalar are all rejected here, so no
/// caller can reach an artifact check with inadmissible key material.
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
    verifying_key.verify_strict(message, &signature).is_ok()
}
