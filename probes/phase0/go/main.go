// Wave 1.1 Phase 0 probe: OBSERVED behavior of the complete Go chain
// verification path (json.Unmarshal into types.Delegation, then
// verify.VerifyDelegationChain) for every scope and depth input class, plus
// the item 5 small order boundary vector through verify.VerifyEd25519 and
// verify.VerifyCanonicalSignature. Reference repo is read only; this probe
// links it via a replace directive. Every ROW line is an executed result,
// not an inference.
package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/aeoess/agent-passport-go/types"
	"github.com/aeoess/agent-passport-go/verify"
)

func row(id, layer, outcome, detail string) {
	fmt.Printf("ROW|%s|%s|%s|%s\n", id, layer, outcome, detail)
}

// runChain unmarshals a raw JSON chain document and, when unmarshalling
// succeeds, runs the typed chain verifier. The layer column records where the
// outcome was decided.
func runChain(id, doc string) {
	var chain []types.Delegation
	if err := json.Unmarshal([]byte(doc), &chain); err != nil {
		row(id, "deserialization", "REJECT", err.Error())
		return
	}
	if err := verify.VerifyDelegationChain(chain); err != nil {
		row(id, "verifier", "REJECT", err.Error())
		return
	}
	row(id, "verifier", "ACCEPT", "chain valid")
}

func chainWithChild(childFields string) string {
	return `[
	 {"delegationId":"root","delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read","x"],"currentDepth":0,"maxDepth":5},
	 {"delegationId":"child","delegatedBy":"agent-a","delegatedTo":"agent-b",` + childFields + `}
	]`
}

func chainWithParent(parentFields, childFields string) string {
	return `[
	 {"delegationId":"root","delegatedBy":"root-key","delegatedTo":"agent-a",` + parentFields + `},
	 {"delegationId":"child","delegatedBy":"agent-a","delegatedTo":"agent-b",` + childFields + `}
	]`
}

func main() {
	fmt.Printf("RUNTIME|%s\n", runtime.Version())

	// ---- scope input classes, child side ----
	runChain("scope-child-control", chainWithChild(`"scope":["read"],"currentDepth":1`))
	runChain("scope-child-absent", chainWithChild(`"currentDepth":1`))
	runChain("scope-child-null", chainWithChild(`"scope":null,"currentDepth":1`))
	runChain("scope-child-empty-array", chainWithChild(`"scope":[],"currentDepth":1`))
	runChain("scope-child-mixed-type", chainWithChild(`"scope":["read",42],"currentDepth":1`))
	runChain("scope-child-string", chainWithChild(`"scope":"read","currentDepth":1`))
	runChain("scope-child-object", chainWithChild(`"scope":{},"currentDepth":1`))
	runChain("scope-child-bool", chainWithChild(`"scope":true,"currentDepth":1`))

	// ---- scope input classes, parent side (child carries ["read"]) ----
	runChain("scope-parent-absent", chainWithParent(`"currentDepth":0`, `"scope":["read"],"currentDepth":1`))
	runChain("scope-parent-null", chainWithParent(`"scope":null,"currentDepth":0`, `"scope":["read"],"currentDepth":1`))
	runChain("scope-parent-empty-array", chainWithParent(`"scope":[],"currentDepth":0`, `"scope":["read"],"currentDepth":1`))
	runChain("scope-parent-mixed-type", chainWithParent(`"scope":["read",42],"currentDepth":0`, `"scope":["read"],"currentDepth":1`))

	// ---- scope ELEMENT subclasses: null and empty-string elements ----
	// encoding/json leaves a JSON null element of a []string unchanged (the
	// zero value ""), so these rows observe whether Go treats a null element
	// as a deserialization rejection or as an inert empty-string member.
	runChain("scope-child-null-element", chainWithChild(`"scope":["read",null],"currentDepth":1`))
	runChain("scope-child-null-element-star-parent", chainWithParent(`"scope":["*"],"currentDepth":0`, `"scope":["read",null],"currentDepth":1`))
	runChain("scope-child-empty-string-element", chainWithChild(`"scope":["read",""],"currentDepth":1`))
	runChain("scope-child-empty-string-element-star-parent", chainWithParent(`"scope":["*"],"currentDepth":0`, `"scope":["read",""],"currentDepth":1`))
	runChain("scope-child-array-element", chainWithChild(`"scope":["read",["x"]],"currentDepth":1`))

	// ---- whole-chain gate: a mixed scope in a single-link chain ----
	runChain("scope-single-link-mixed", `[
	 {"delegationId":"only","delegatedBy":"root-key","delegatedTo":"agent-a","scope":["read",42],"currentDepth":0}
	]`)

	// ---- currentDepth input classes ----
	runChain("depth-control", chainWithChild(`"scope":["read"],"currentDepth":1`))
	runChain("depth-child-absent-parent-0", chainWithChild(`"scope":["read"]`))
	runChain("depth-child-absent-parent-minus1", chainWithParent(`"scope":["read","x"],"currentDepth":-1`, `"scope":["read"]`))
	runChain("depth-child-null-parent-minus1", chainWithParent(`"scope":["read","x"],"currentDepth":-1`, `"scope":["read"],"currentDepth":null`))
	runChain("depth-negative-chain", chainWithParent(`"scope":["read","x"],"currentDepth":-2`, `"scope":["read"],"currentDepth":-1`))
	runChain("depth-child-fractional", chainWithChild(`"scope":["read"],"currentDepth":1.5`))
	runChain("depth-fractional-negative-chain", chainWithParent(`"scope":["read","x"],"currentDepth":-1.5`, `"scope":["read"],"currentDepth":-0.5`))
	runChain("depth-child-exponent", chainWithChild(`"scope":["read"],"currentDepth":1e0`))
	runChain("depth-child-string", chainWithChild(`"scope":["read"],"currentDepth":"1"`))
	runChain("depth-child-bool", chainWithChild(`"scope":["read"],"currentDepth":true`))
	runChain("depth-child-beyond-i64", chainWithChild(`"scope":["read"],"currentDepth":9223372036854775808`))
	runChain("depth-child-minus-zero", chainWithParent(`"scope":["read","x"],"currentDepth":-1`, `"scope":["read"],"currentDepth":-0`))
	runChain("depth-child-minus-zero-fractional", chainWithParent(`"scope":["read","x"],"currentDepth":-1`, `"scope":["read"],"currentDepth":-0.0`))

	// ---- maxDepth input classes (on the parent; depths 0 then 1) ----
	runChain("maxdepth-absent", chainWithParent(`"scope":["read","x"],"currentDepth":0`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-null", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":null`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-1", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":1`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-0", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":0`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-negative", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":-1`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-fractional", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":1.5`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-exponent", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":1e0`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-string", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":"1"`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-bool", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":true`, `"scope":["read"],"currentDepth":1`))
	runChain("maxdepth-beyond-i64", chainWithParent(`"scope":["read","x"],"currentDepth":0,"maxDepth":9223372036854775808`, `"scope":["read"],"currentDepth":1`))

	// ---- item 5: small order boundary vector ----
	// Public key: the canonical encoding of the Edwards identity point
	// (y = 1, sign bit 0), which has order 1 (a small order point).
	// Signature: R = the same identity encoding, S = 0. The RFC 8032
	// equation [S]B = R + [k]A holds for EVERY message.
	smallOrderPub := "01" + strings.Repeat("00", 31)
	smallOrderSig := "01" + strings.Repeat("00", 31) + strings.Repeat("00", 32)
	msg := "APS wave1.1 small order probe"
	if verify.VerifyEd25519([]byte(msg), smallOrderSig, smallOrderPub) {
		row("smallorder-VerifyEd25519", "verifier", "ACCEPT", "degenerate identity-point vector verifies")
	} else {
		row("smallorder-VerifyEd25519", "verifier", "REJECT", "degenerate identity-point vector rejected")
	}
	obj := map[string]interface{}{
		"delegationId": "del_probe",
		"delegatedBy":  smallOrderPub,
		"delegatedTo":  "agent-b",
		"scope":        []interface{}{"read"},
		"signature":    smallOrderSig,
	}
	if verify.VerifyCanonicalSignature(obj, "signature", smallOrderSig, smallOrderPub) {
		row("smallorder-VerifyCanonicalSignature", "verifier", "ACCEPT", "full canonical-signature path verifies")
	} else {
		row("smallorder-VerifyCanonicalSignature", "verifier", "REJECT", "full canonical-signature path rejected")
	}
	// Control: a different message under the same degenerate vector still
	// verifies, demonstrating the vector is message independent.
	if verify.VerifyEd25519([]byte("a completely different message"), smallOrderSig, smallOrderPub) {
		row("smallorder-message-independent", "verifier", "ACCEPT", "verifies for any message")
	} else {
		row("smallorder-message-independent", "verifier", "REJECT", "message dependence observed")
	}
}
