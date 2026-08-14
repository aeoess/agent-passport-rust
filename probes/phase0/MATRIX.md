# Wave 1.1 Phase 0: reference behavior matrix (observed, not inferred)

Every cell below is the result of executing the named path. Raw outputs are in
`out/go-matrix.txt`, `out/ts-matrix.txt`, and `out/rust-baseline.txt`; the
probe sources are `go/main.go`, `ts/matrix.mts`, and
`rust/wave11_baseline_probe.rs` (the Rust probe ran as a temporary
integration test at BASELINE and was then deleted from `tests/`; the copy
here is the record).

## Provenance

| item | value |
|---|---|
| Go reference | ~/agent-passport-go @ 13c38ece211b64df80fd7666d3c925a2b1cd488d, clean |
| TS reference | ~/agent-passport-system @ b70537574c07987afbe4e1aedb54d728104c3bd4, clean before and after |
| Rust baseline | ~/agent-passport-rust @ 5a1b03084c573b062461e9772e907656ecebc424 |
| Go runtime | go1.26.3 darwin/arm64 |
| Node runtime | v24.11.1, tsx 4.23.11 via npx |
| Rust runtime | rustc 1.95.0, cargo 1.95.0 |
| Go command | `cd probes/go && go mod tidy && go run .` (replace directive links the read-only reference) |
| TS command | `cd probes && npx -y tsx@4.23.11 ts/matrix.mts` (imports the reference by absolute path; writes nothing into it) |
| Rust command | `cargo test --test wave11_baseline_probe -- --nocapture` at BASELINE |

## Paths probed

- Go chain path: `json.Unmarshal` into `[]types.Delegation`
  (types/types.go: `Scope []string`, `MaxDepth *int`, `CurrentDepth *int`)
  followed by `verify.VerifyDelegationChain` (verify/verify.go:219). This is
  how raw JSON reaches the Go chain verifier; the layer column records
  whether the outcome was decided at deserialization or in verifier logic.
- Go also has a map-shaped `verify.ValidateChain` for the a2a-1496
  composition profile. It is a different artifact shape (validityWindow,
  action_categories) that wave 1 recorded as out of scope and did not port;
  it is not the parity target for these classes.
- TS single-delegation path: `verifyDelegation` (src/core/delegation.ts:260)
  on a correctly signed object carrying the probe class, so the observed
  outcome isolates the class.
- TS chain path: `validateChain` throws
  "This function has moved to DelegationStore in @aeoess/gateway"
  (observed). TS chain validation is NO PATH at the pinned revision.
- TS scope primitive: `scopeAuthorizes` (src/core/delegation.ts:457).
- Go has no single-delegation verifier in the verify package (exported
  surface: VerifyEd25519, VerifyCanonicalSignature, ScopeCovers,
  ValidateChain, VerifyDelegationChain).

## Scope input classes

Chain columns place the class on the child of a two-link chain unless noted.
"treated as empty" means the verifier saw a nil/empty scope list.

| class | Go chain (layer: outcome) | TS chain | TS verifyDelegation | Rust baseline chain |
|---|---|---|---|---|
| absent | verifier: ACCEPT (nil scope, vacuous narrowing pass) | NO PATH | ACCEPT | ACCEPT (treated as empty) |
| null | verifier: ACCEPT (same as absent) | NO PATH | ACCEPT | ACCEPT (treated as empty) |
| [] | verifier: ACCEPT | NO PATH | ACCEPT | ACCEPT |
| ["read"] | verifier: ACCEPT | NO PATH | ACCEPT | ACCEPT |
| ["read", 42] | deserialization: REJECT (cannot unmarshal number into string) | NO PATH | ACCEPT (scope never inspected) | ACCEPT, 42 silently discarded (the defect) |
| "read" | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT (treated as empty) |
| {} | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT (treated as empty) |
| true | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT (treated as empty) |

Parent-side rows: Go accepts absent/null/[] on the parent at
deserialization and then refuses any non-empty child scope as widening
(verifier layer); a mixed-type parent rejects at deserialization. A mixed
scope in a SINGLE-link chain also rejects at deserialization in Go
(the unmarshal gate covers every link, including chains with no pairwise
step), while baseline Rust never examines it.

Scope ELEMENT subclasses (observed, decisive for the item 1 shape):

| element | Go chain (layer: outcome) | TS verifyDelegation | Rust baseline chain |
|---|---|---|---|
| null element, parent ["read","x"] | deserialization: ACCEPT (null leaves the zero value ""); verifier: REJECT scope widening ("" uncovered) | ACCEPT | ACCEPT (null discarded) |
| null element, parent ["*"] | verifier: ACCEPT (chain valid; "*" covers "") | ACCEPT | ACCEPT |
| "" element, parent ["read","x"] | verifier: REJECT scope widening | not probed separately (scope never inspected) | ACCEPT ("" kept) |
| "" element, parent ["*"] | verifier: ACCEPT | not probed separately | ACCEPT |
| array element ["x"] | deserialization: REJECT (cannot unmarshal array into string) | not probed separately | ACCEPT (discarded) |

A null element and an explicit "" element are indistinguishable to the Go
verifier: encoding/json leaves a JSON null on a string element unchanged
(the zero value ""), with no error. TS scopeAuthorizes on a null element is
again order dependent: short-circuits to true when a preceding string
matches, throws `TypeError: Cannot read properties of null (reading
'endsWith')` when the null is reached.

TS scopeAuthorizes on the mixed class is order dependent (observed):
`['read', 42]` with required "read" returns true without touching 42
(Array.some short-circuits); `['x', 42]` throws
`TypeError: granted.endsWith is not a function`. Rust's typed
`scope_authorizes(&[String], &str)` cannot receive a non-string element, so
this quirk is unrepresentable there.

## Depth input classes (currentDepth)

| class | Go chain (layer: outcome) | TS chain | TS verifyDelegation | Rust baseline chain |
|---|---|---|---|---|
| absent | deserialization: ACCEPT as nil; verifier treats as 0 | NO PATH | ACCEPT | ACCEPT as 0 |
| null | deserialization: ACCEPT as nil; verifier treats as 0 (observed: parent -1, child null is a valid chain) | NO PATH | ACCEPT | ACCEPT as 0 |
| 0 | verifier: decides on value | NO PATH | ACCEPT | same |
| positive integer | verifier: decides on value | NO PATH | ACCEPT | same |
| negative integer | verifier: ACCEPT (chain -2 then -1 is valid) | NO PATH | ACCEPT | ACCEPT |
| fractional (1.5) | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT (the defect: -1.5 then -0.5 satisfies +1) |
| exponent (1e0) | deserialization: REJECT (literal grammar, not value) | NO PATH | ACCEPT | ACCEPT as 1.0 |
| string "1" | deserialization: REJECT | NO PATH | ACCEPT ("1" > 3 is false) | ACCEPT, treated as absent (0) |
| boolean | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT, treated as absent |
| beyond i64 (2^63) | deserialization: REJECT (out of range) | NO PATH | REJECT at verifier as depthExceeded (9.2e18 > maxDepth, value processed numerically) | REJECT via f64 comparison in the single path; chain treats numerically |
| -0 (supplementary) | deserialization: ACCEPT, value 0 (chain parent -1, child -0 is valid) | NO PATH | ACCEPT | ACCEPT (f64 -0.0) |
| -0.0 (supplementary) | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT (f64 -0.0) |

serde_json wire representations (observed at BASELINE): `-0` and `-0.0`
both parse to the identical f64-backed Value -0.0 with a negative sign bit;
`1e0` is f64-backed; `1` is i64-backed. Rust therefore cannot distinguish
the literal `-0` (which Go accepts, value 0) from `-0.0` (which Go rejects)
after parsing.

## Depth input classes (maxDepth, on the parent)

| class | Go chain (layer: outcome) | TS chain | TS verifyDelegation | Rust baseline chain |
|---|---|---|---|---|
| absent | ACCEPT (no bound) | NO PATH | ACCEPT | ACCEPT (no bound) |
| null | ACCEPT (no bound) | NO PATH | ACCEPT | ACCEPT (no bound) |
| 0 | verifier: REJECT depth limit exceeded (child depth 1) | NO PATH | ACCEPT (0 > 0 false) | same as Go |
| negative (-1) | deserialization: ACCEPT; verifier: REJECT depth limit exceeded | NO PATH | REJECT depthExceeded (0 > -1) | same |
| fractional (1.5) | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT as 1.5 |
| exponent (1e0) | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT as 1.0 |
| string "1" | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT, treated as absent |
| boolean | deserialization: REJECT | NO PATH | ACCEPT | ACCEPT, treated as absent |
| beyond i64 (2^63) | deserialization: REJECT | NO PATH | ACCEPT (bound 9.2e18, never trips) | ACCEPT as 9.2e18 |

## Item 5: small order boundary vector (four-way, observed)

Vector: public key = the canonical encoding of the Edwards identity point
(order 1): hex `01` followed by 31 zero bytes. Signature: R = the same
encoding, S = 0 (32 zero bytes). Message: "APS wave1.1 small order probe".
The RFC 8032 equation [S]B = R + [k]A degenerates to identity = identity
for every message; a control row confirms message independence in both
references.

| path | result |
|---|---|
| TS `verify` (src/crypto/keys.ts, Node v24.11.1 / OpenSSL) | ACCEPT |
| TS `verifyDelegation` full path (delegatedBy = small order key) | ACCEPT (valid=true) |
| Go `verify.VerifyEd25519` (go1.26.3 crypto/ed25519) | ACCEPT |
| Go `verify.VerifyCanonicalSignature` full path | ACCEPT |
| Rust `agent_passport::crypto::verify_ed25519` (ed25519-dalek 2.2, `verify`) | ACCEPT |
| `ed25519_dalek::VerifyingKey::verify_strict` directly | REJECT |

Both references and Rust plain `verify` agree; `verify_strict` alone
differs. This is exactly the configuration that substantiates the wave 1
`verify`-over-`verify_strict` decision.

## Item 4 at BASELINE

The corrected duplicate-member test (raw bytes physically carrying
`a` as backslash, u, 0061, asserted on the byte array) returns
`Err(DuplicateMember)` at BASELINE. The implementation is correct; the
wave 1 test was vacuous, so the fix is test-only and no STOP applies.

## What the matrix permits (wave 1.1 dispositions)

- Item 1: reject a non-string, NON-NULL element inside a scope ARRAY on
  the chain path, on every link (Go rejects numbers, booleans, objects,
  and arrays at deserialization for any link count; TS chain is NO PATH).
  A null ELEMENT is NOT a typed error: Go observably accepts it as the
  inert empty string "" (rows above), so Rust maps a null element to ""
  rather than discarding it or rejecting it; a typed error here would
  newly reject the parent-"*" case Go accepts, which the parity
  discipline forbids. This is the one place the item's "becomes a typed
  error" wording is narrowed by observation, and it is called out in the
  handoff. Absent, null, and [] as the scope MEMBER stay accepted (Go
  accepts them). Non-array scope stays treated-as-empty: Go rejects it at
  deserialization but TS chain is NO PATH, so the matrix does not show
  both references rejecting, and the job authorizes only the element-type
  correction. `verify_delegation` (TS-referenced) keeps never inspecting
  scope: TS accepts every scope class there, observed.
- Item 2: on the chain path, a PRESENT depth must be an integral JSON
  number representable in i64, plus the literal -0 corner accepted as 0
  (Go accepts -0, value 0). Null and absent stay accepted as the Go nil
  default. Negative integers stay accepted (Go accepts chains at negative
  depths). Fractional, exponent-form, string, boolean, and out-of-range
  classes become a typed error (all reject in Go at deserialization).
  `verify_delegation` depth handling stays dynamic-comparison (TS parity,
  observed above).
- Residual divergences Rust cannot close from a parsed Value, all
  preserved from baseline, none newly introduced: `-0.0` (and any other
  literal parsing to IEEE -0.0) accepted as 0 where Go accepts only `-0`;
  non-array scope treated as empty where Go rejects at deserialization
  (instruction-limited, see item 1); a parent depth of exactly i64::MAX
  rejects the next hop (checked add) where Go wraps and can accept.
