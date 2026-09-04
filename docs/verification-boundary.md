# Verification boundary

Verification APIs fall into two categories: authority-aware verification, where caller-supplied trust or expected context is part of the decision, and integrity verification, where an artifact is checked against information carried by that artifact. An integrity result does not authenticate the signer as authorized for a relying party. Applications making authorization decisions should use APIs that accept the required trust anchors or expected context.

verify_passport / VerifyPassport establish issuer authority only when caller-supplied trusted issuers are verified; explicit self-signed opt-in is integrity-only acceptance. Other exported Rust and Go verification surfaces were not individually classified for authority semantics in this release.
