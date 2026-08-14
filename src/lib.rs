#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Verification-first Rust implementation of the Agent Passport System (APS)
//! artifact verifiers.
//!
//! This crate verifies existing APS artifacts. It does not create them: there
//! is no key generation, no signing, no issuance, and no revocation store.
//! The TypeScript SDK (`agent-passport-system`) is the reference
//! implementation; every byte contract here is pinned to it and to the frozen
//! conformance vectors vendored under `tests/vectors`.
//!
//! # Canonicalization profiles
//!
//! APS uses two canonical JSON forms, and routing an artifact through the
//! wrong one produces a different preimage and a failed signature check:
//!
//! - Legacy canonical: sorts object keys and removes null-valued object
//!   members. Passports and legacy APS delegations sign over this form.
//! - Strict JCS: RFC 8785. Null members are preserved. `action_ref` and
//!   receipt-core artifacts hash and sign over this form.
//!
//! The two profiles differ exactly on null-valued object members; a
//! regression test pins the difference.
//!
//! # Invariants
//!
//! - No verifier reads the wall clock. Time-aware verification takes an
//!   explicit evaluation time.
//! - No verifier trusts a self-minted root. Authorization verification takes
//!   explicit trust inputs; verification without them reports a
//!   structural-only status.
//! - Error messages never contain signed payload contents, keys, or
//!   signatures.

pub mod action_ref;
pub mod crypto;
pub mod delegation;
pub mod jcs;
pub mod legacy_canonical;
pub mod passport;
pub mod receipt_core;
