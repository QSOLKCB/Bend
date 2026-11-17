# Bendovr™ — adversarial research track

*Because even mathematically proven software deserves an adversary.*

A humorous **test-suite nickname**, not an upstream Bend name or a claim of affiliation. No changes to the language or compiler are implied.

## Initial adversarial cases

- BOVR-001: clean pinned source produces a PASS provenance receipt.
- BOVR-002: an uncommitted edit fails verification.
- BOVR-003: a new commit cannot silently replace pinned upstream code.
- BOVR-004: missing source or symlink substitution fails closed.
- BOVR-005: path traversal in pin metadata is rejected.
- BOVR-006: failed verification emits a failure receipt and cannot overwrite an earlier file.
- BOVR-007: integrity checksum is independently recomputable.

These establish **evidence hygiene**, not semantic correctness. Future tests should target proof translation, backend equivalence, overflow/precision behaviour, effect boundaries and compiler miscompilations, with minimal counterexamples and exact source SHA. Never report a test as executed unless it actually ran.

Motto: **Proofs are welcome. Receipts are mandatory.**


## BEND-QSOL-002 — Source / elaborator / kernel boundary

- BOVR-008: source-check and independently check emitted BendTT for reflexivity.
- BOVR-009: check an inductive, recursive, explicit-motive equality proof.
- BOVR-010: reject a false equality at the source checker.
- BOVR-011: refuse unsafe-promise dependencies under `--verdict`.
- BOVR-012: reject a syntactically well-formed but ill-typed BendTT canary.
- BOVR-013: hash and compare repeated elaboration byte-for-byte.
- BOVR-014: test that fake accept-everything kernels fail the canary; fail closed on missing toolchains and timeouts.

The BOVR-014 fake-kernel unit test is **synthetic**, not evidence of a Lean proof. Full semantic evidence requires an actual Bun + BendTT run, with its own immutable receipt. See `docs/PROOF_TRUST.md`.
