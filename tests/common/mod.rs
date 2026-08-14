//! Test-only deterministic signing helper. The crate's public API is
//! verification-only; tests need signed fixtures, so they derive Ed25519
//! seeds from fixed strings via SHA-256 (the same derivation the conformance
//! runners use) and sign with ed25519_dalek directly. No clock, no RNG.

// Each integration-test binary compiles this module independently and uses
// a different subset, so unused-item lints are expected per binary.
#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

pub fn seed_from(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

pub fn public_key_hex(seed: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

pub fn sign_hex(message: &str, seed: &[u8; 32]) -> String {
    hex::encode(
        SigningKey::from_bytes(seed)
            .sign(message.as_bytes())
            .to_bytes(),
    )
}
