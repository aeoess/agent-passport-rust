# agent-passport-system

Verification-first Rust implementation of Agent Passport System (APS) artifact
verifiers.

This crate verifies existing APS artifacts. It creates none: no key generation,
no signing, no issuance, no revocation store.

```toml
[dependencies]
agent-passport-system = "0.1"
```

```rust
use agent_passport::delegation::{verify_chain_structure, verify_chain_authorization};
```

The package is `agent-passport-system`, matching the npm and PyPI packages. The
library is `agent_passport`.

## Scope

APS is specified in the Internet-Draft `draft-pidlisnyi-aps-03`, an individual
submission. That revision defines a delegation record whose `authority` object
carries seven required facets.

**This crate does not implement that record.** It verifies the artifact shapes
the current reference implementations emit, which the draft's Implementation
Status appendix describes as predating the wire formats of the revision. If you
are verifying artifacts produced by the TypeScript, Python, or Go packages
today, this crate is the matching verifier. If you are looking for an
implementation of the seven-facet authority object, it does not exist yet in any
language.

## What it verifies

- **Canonicalization.** Two profiles, because routing an artifact through the
  wrong one produces a different preimage and a failed signature check. Legacy
  canonical sorts object keys and removes null-valued members; passports and
  legacy delegations sign over this form. Strict JCS is RFC 8785 and preserves
  null members; `action_ref` and receipt-core artifacts use it. The two differ
  exactly on null-valued object members, and a regression test pins the
  difference.
- **Ed25519 signatures** over raw hex keys and signatures, using RFC 8032
  verification.
- **Passports**, over the legacy canonical profile.
- **Delegations**, single-artifact and root-to-leaf chain.
- **ReceiptV1** structural validation with domain-separated preimages.
- **`action_ref`** scope canonicalization and computation.

## What it does not do, and what a pass does not prove

Read this section before relying on a result.

**A structural pass is not an authorization.** `verify_chain_structure` returns
the unit type. `verify_chain_authorization` returns a `ChainAuthorization`
value. They are deliberately different types so a structural result cannot be
mistaken for an authorization result at a call site.

**Chain narrowing is checked against the effective ceiling carried from the
root.** Spend limit, spend unit, depth ceiling and activation floor are folded
into a bound as the chain is walked: the minimum spendLimit over the bounded
ancestors, the unit from the nearest bounded ancestor, the minimum maxDepth,
and the maximum notBefore. A link that omits one of those fields inherits the
ancestor bound rather than disabling the comparison, so a descendant cannot hold
a ceiling an ancestor bounded. Scope containment and expiry containment reject
an omitting child outright, which is transitively the same result. The ceiling
is derived only from the artifacts; it is never a remaining balance.

**Signatures establish static limits and not consumed state.** Nothing here
knows how much of a budget has been spent. A verified chain says what the
signed ceilings are. It does not say what capacity remains.

**Key admissibility is not checked.** Signature verification follows RFC 8032,
matching the Node and Go reference behavior. A low-order public key is accepted
by all three. Such a key admits one message-independent signature, so a signer
who chooses one can later repudiate everything they signed while verifiers
report the signature valid. This crate does not reject that key class, because
doing so unilaterally would diverge from the references. A committed test pins
the behavior.

**Unparseable timestamps fail open in the reference and here.** A non-parsing
`expiresAt` or `notBefore` on a passport skips the check rather than failing it.
This is ported faithfully from the TypeScript reference and flagged rather than
corrected, because changing it is a reference decision.

**No verifier reads the wall clock.** Time-aware verification takes an explicit
evaluation time. No verifier trusts a self-minted root; authorization takes
explicit trust inputs, and verification without them reports a structural-only
status. Error messages never contain signed payload contents, keys, or
signatures.

## Conformance basis

Byte contracts are pinned to the TypeScript reference and to frozen conformance
vectors vendored under `tests/vectors`, including the adversarial
canonical-bytes set, ECMAScript number boundaries, lone-surrogate cases, and
`action_ref` parity fixtures. Where the Go and TypeScript references disagreed,
the port stopped on a named failing test rather than picking silently.

This is a fourth implementation by the same maintainer as the others. It is not
an independent implementation and does not establish independent verification of
the protocol.

## Status

0.2.0. Verification only. The crate forbids unsafe code and denies missing
documentation.

## License

Apache-2.0. Copyright Tymofii Pidlisnyi (Agent Passport System).
