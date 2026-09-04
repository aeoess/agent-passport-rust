# Changelog

## 0.3.0 (2026-09-04)

Security release. The full cross-SDK account, including the affected version
ranges and the severity assessment, is in the security advisory for this
release. [The verification boundary](https://github.com/aeoess/agent-passport-rust/blob/main/docs/verification-boundary.md)
draws the authority-against-integrity line, names the surface this release
classified, and records that the other exported verification surfaces here were
not individually classified.

Several exported verification functions returned a successful verification
result (`valid: true` or an equivalent) without establishing all of the trust
and temporal conditions the result implied. In the paths affected here, a
passport verified with no caller-supplied trusted issuer, so the only key
behind the result was the one the artifact carried, or an unreadable timestamp
compared as neither expired nor stale. A relying party that treated those
results as authorization could accept an artifact an attacker produced with
keys the attacker controls.

This release changes what the affected functions establish. Passport
verification establishes issuer authority only from a caller-supplied
trusted-issuer list, and a self-signed passport is accepted only under an
explicit opt-in that marks the result integrity-only. A timestamp the verifier
cannot read fails closed and is reported separately from a timestamp that was
read and found to have passed.

### Affected surfaces

One row per exported surface and defect class; a surface with two defect classes
appears twice. Copied from the security advisory for this release.

| package | exported name | module path | defect class | consumer change |
|---|---|---|---|---|
| rust | `verify_passport` | agent_passport::passport (src/passport.rs) | invalid time fails open | Two breaks. Behaviourally, a passport with an absent, non-string or unparseable expiresAt, or a present-but-unreadable notBefore, now verifies invalid where it verified valid. Structurally, callers that match PassportError or PassportWarning exhaustively must add arms, because neither enum carries #[non_exhaustive]. A conforming producer is unaffected: an explicit-offset timestamp in the past is still reported Expired, not InvalidExpiry |
| rust | `PassportError::InvalidExpiry` | agent_passport::passport::PassportError (src/passport.rs) | invalid time fails open | Source-breaking addition. PassportError is a pub enum with no #[non_exhaustive] , so any downstream exhaustive match on PassportError fails to compile until an arm is added. This is the consumer break, not a runtime one |
| rust | `PassportError::InvalidNotBefore` | agent_passport::passport::PassportError (src/passport.rs) | invalid time fails open | Source-breaking addition on the same non_exhaustive-free pub enum, so exhaustive matches on PassportError must add this arm too.  |
| rust | `PassportWarning::DelegationInvalidExpiry` | agent_passport::passport::PassportWarning (src/passport.rs) | invalid time fails open | Source-breaking addition: PassportWarning is a pub enum with no #[non_exhaustive], so exhaustive matches must add an arm. No verdict change, since warnings never affect valid; a result that was valid stays valid and simply carries one more warning |
| rust | `verify_passport` | src/passport.rs | authority false accept | a new required input: PassportVerifyOptions gains the public field allow_self_signed, so every struct literal must name it; PassportVerification gains issuer_trust_checked and self_signed_accepted and PassportError gains AuthorityNotEstablished; downstream exhaustive matches must add that arm |

### Migration

| package | old call shape | new call shape | unmigrated call | artifacts reissued |
|---|---|---|---|---|
| rust | `exhaustive match on PassportError or PassportWarning compiled against the before the fixed version variant set` | `add arms for PassportError::InvalidExpiry, PassportError::InvalidNotBefore and PassportWarning::DelegationInvalidExpiry` | compile error: neither enum carries #[non_exhaustive], so an exhaustive match compiled against the previous variant set no longer compiles | no: type-level only, no artifact changes |
| rust | `verify_passport(&signed, &options) returned valid true for a passport whose expiresAt was absent, non-string or unparseable, and for a present-but-unreadable notBefore` | `same call with a passport carrying an RFC 3339 expiresAt; notBefore stays optional but must parse when present` | valid false: errors carry InvalidExpiry or InvalidNotBefore, reported separately from Expired and NotYetValid | yes: passports that never stated a readable expiresAt, and passports with an unreadable notBefore; a conforming producer is unaffected |
| rust | `verify_passport(&signed, &PassportVerifyOptions { trusted_issuers, evaluation_time, allowed_clock_skew_ms })` returned valid true on an empty trusted_issuers list | `the same call with allow_self_signed added to the struct literal: true for an integrity-only path, or supply trusted_issuers and leave it false` | compile error: PassportVerifyOptions gains a public field, so every struct literal fails to build until it names allow_self_signed; a match on PassportError or PassportWarning also fails, neither being non_exhaustive | no: no serialized bytes move and the countersignature preimage is untouched |
