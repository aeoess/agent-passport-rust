// Wave 1.1 Phase 0 probe: OBSERVED behavior of the complete TypeScript
// delegation verification path (verifyDelegation in src/core/delegation.ts)
// for every scope and depth input class, the scopeAuthorizes primitive, the
// chain path (expected NO PATH: validateChain is a deprecation stub), and
// the item 5 small order boundary vector through the SDK verify() and the
// full verifyDelegation path. The pinned reference worktree is read only;
// this script imports it by absolute path and writes nothing into it.
// Every ROW line is an executed result, not an inference.

import {
  verifyDelegation,
  scopeAuthorizes,
  validateChain,
} from '/Users/tima/agent-passport-system/src/core/delegation.ts'
import { canonicalize } from '/Users/tima/agent-passport-system/src/core/canonical.ts'
import {
  sign,
  verify,
  generateKeyPair,
} from '/Users/tima/agent-passport-system/src/crypto/keys.ts'

console.log(`RUNTIME|node ${process.version}`)

function row(id: string, layer: string, outcome: string, detail: string) {
  console.log(`ROW|${id}|${layer}|${outcome}|${detail}`)
}

const kp = generateKeyPair()

// Build a delegation carrying the probe class, correctly signed over the
// exact object handed to verifyDelegation, so the observed outcome isolates
// the input class rather than a signature mismatch. verifyDelegation reads
// the wall clock; the window below is live for centuries either way.
function signedDelegation(overrides: Record<string, unknown>): any {
  const body: Record<string, unknown> = {
    delegationId: 'del_probe0001',
    delegatedTo: 'agent-b',
    delegatedBy: kp.publicKey,
    scope: ['read'],
    expiresAt: '2999-01-01T00:00:00.000Z',
    notBefore: '2020-01-01T00:00:00.000Z',
    maxDepth: 3,
    currentDepth: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  }
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete body[k]
  }
  const signature = sign(canonicalize(body), kp.privateKey)
  return { ...body, signature }
}

function probeVerifyDelegation(id: string, overrides: Record<string, unknown>) {
  try {
    const status = verifyDelegation(signedDelegation(overrides))
    row(
      id,
      'verifier',
      status.valid ? 'ACCEPT' : 'REJECT',
      `valid=${status.valid} depthExceeded=${status.depthExceeded} errors=${JSON.stringify(status.errors)}`,
    )
  } catch (err) {
    row(id, 'verifier', 'THROW', String(err))
  }
}

// ---- scope input classes through verifyDelegation ----
probeVerifyDelegation('scope-control', { scope: ['read'] })
probeVerifyDelegation('scope-absent', { scope: undefined })
probeVerifyDelegation('scope-null', { scope: null })
probeVerifyDelegation('scope-empty-array', { scope: [] })
probeVerifyDelegation('scope-mixed-type', { scope: ['read', 42] })
probeVerifyDelegation('scope-string', { scope: 'read' })
probeVerifyDelegation('scope-object', { scope: {} })
probeVerifyDelegation('scope-bool', { scope: true })

probeVerifyDelegation('scope-null-element', { scope: ['read', null] })

// ---- scopeAuthorizes primitive on the mixed-type class ----
try {
  const first = scopeAuthorizes(['read', 42] as unknown as string[], 'read')
  row('scopeAuthorizes-mixed-match-first', 'primitive', 'ACCEPT', `returned ${first} without touching the non-string element (some() short-circuits)`)
} catch (err) {
  row('scopeAuthorizes-mixed-match-first', 'primitive', 'THROW', String(err))
}
try {
  const second = scopeAuthorizes(['x', 42] as unknown as string[], 'read')
  row('scopeAuthorizes-mixed-reach-nonstring', 'primitive', 'ACCEPT', `returned ${second}`)
} catch (err) {
  row('scopeAuthorizes-mixed-reach-nonstring', 'primitive', 'THROW', String(err))
}

try {
  const nullFirstMatch = scopeAuthorizes(['read', null] as unknown as string[], 'read')
  row('scopeAuthorizes-null-element-match-first', 'primitive', 'ACCEPT', `returned ${nullFirstMatch}`)
} catch (err) {
  row('scopeAuthorizes-null-element-match-first', 'primitive', 'THROW', String(err))
}
try {
  const nullReached = scopeAuthorizes(['x', null] as unknown as string[], 'read')
  row('scopeAuthorizes-null-element-reached', 'primitive', 'ACCEPT', `returned ${nullReached}`)
} catch (err) {
  row('scopeAuthorizes-null-element-reached', 'primitive', 'THROW', String(err))
}

// ---- depth input classes through verifyDelegation (currentDepth) ----
probeVerifyDelegation('depth-current-absent', { currentDepth: undefined })
probeVerifyDelegation('depth-current-null', { currentDepth: null })
probeVerifyDelegation('depth-current-0', { currentDepth: 0 })
probeVerifyDelegation('depth-current-positive', { currentDepth: 2 })
probeVerifyDelegation('depth-current-negative', { currentDepth: -1 })
probeVerifyDelegation('depth-current-fractional', { currentDepth: 1.5 })
probeVerifyDelegation('depth-current-exponent', { currentDepth: 1e0 })
probeVerifyDelegation('depth-current-string', { currentDepth: '1' })
probeVerifyDelegation('depth-current-bool', { currentDepth: true })
probeVerifyDelegation('depth-current-beyond-i64', { currentDepth: 9223372036854775808 })

// ---- depth input classes through verifyDelegation (maxDepth) ----
probeVerifyDelegation('depth-max-absent', { maxDepth: undefined })
probeVerifyDelegation('depth-max-null', { maxDepth: null })
probeVerifyDelegation('depth-max-0', { maxDepth: 0 })
probeVerifyDelegation('depth-max-negative', { maxDepth: -1 })
probeVerifyDelegation('depth-max-fractional', { maxDepth: 1.5 })
probeVerifyDelegation('depth-max-string', { maxDepth: '1' })
probeVerifyDelegation('depth-max-bool', { maxDepth: true })
probeVerifyDelegation('depth-max-beyond-i64', { maxDepth: 9223372036854775808 })

// ---- chain path ----
try {
  validateChain(['del_probe0001'])
  row('chain-validateChain', 'chain', 'ACCEPT', 'unexpectedly returned')
} catch (err) {
  row('chain-validateChain', 'chain', 'NO-PATH', String(err).slice(0, 160))
}

// ---- item 5: small order boundary vector ----
// Public key: canonical encoding of the Edwards identity point (y = 1,
// sign bit 0), order 1. Signature: R = the same encoding, S = 0. The
// RFC 8032 equation [S]B = R + [k]A holds for EVERY message.
const smallOrderPub = '01' + '00'.repeat(31)
const smallOrderSig = '01' + '00'.repeat(31) + '00'.repeat(32)
const msg = 'APS wave1.1 small order probe'
row(
  'smallorder-verify',
  'verifier',
  verify(msg, smallOrderSig, smallOrderPub) ? 'ACCEPT' : 'REJECT',
  'SDK verify() on the degenerate identity-point vector',
)
row(
  'smallorder-message-independent',
  'verifier',
  verify('a completely different message', smallOrderSig, smallOrderPub) ? 'ACCEPT' : 'REJECT',
  'same vector, different message',
)
try {
  const degenerate = {
    delegationId: 'del_probe0002',
    delegatedTo: 'agent-b',
    delegatedBy: smallOrderPub,
    scope: ['read'],
    expiresAt: '2999-01-01T00:00:00.000Z',
    notBefore: '2020-01-01T00:00:00.000Z',
    maxDepth: 3,
    currentDepth: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    signature: smallOrderSig,
  }
  const status = verifyDelegation(degenerate as any)
  row(
    'smallorder-verifyDelegation',
    'verifier',
    status.valid ? 'ACCEPT' : 'REJECT',
    `full delegation path: valid=${status.valid} errors=${JSON.stringify(status.errors)}`,
  )
} catch (err) {
  row('smallorder-verifyDelegation', 'verifier', 'THROW', String(err))
}
