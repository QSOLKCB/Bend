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
