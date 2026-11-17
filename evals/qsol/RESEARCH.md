# BEND-QSOL-001 — Independent Bend Research

**Status:** initial preservation and provenance study; *not* a compiler certification.

- **Upstream:** https://github.com/bendlang/bend
- **Research fork:** https://github.com/QSOLKCB/Bend
- **Snapshot commit:** `9c586f094f4fc88bef440dc8b4d77a2f92c257cc`
- **Licence:** upstream Apache-2.0; retain upstream notices and attribution.
- **Scope:** isolate evaluation under `evals/qsol/`; do not change Bend language, compiler, Lean kernel, prelude or upstream performance gates in this phase.

## Trust boundaries

The upstream README's speed and proof claims are **claims under evaluation**, not QSOL-IMC conclusions. A successful Bend check is not, by itself, a demonstration of correctness of all compilation targets. The trusted computing base and translation from Bend source to the Lean kernel require an independent audit. The kernel, elaborator, backends, toolchains and generated code must be distinguished in evidence.

The immutable **reference commit** is pinned in `pins.json` with original Git blob IDs for ten source/policy files. The pin file is reviewable repository metadata, not an external trusted anchor. Pin updates require an explicit explanation and review. SHA-256 receipts detect accidental evidence changes but are **not signatures** or attestations.

## Acceptance for BEND-QSOL-001

1. Record baseline source commit, tree, pin comparisons, Git index digest, runtime platform and integrity checksum.
2. Detect changes in committed pinned files *and* uncommitted working-tree changes; reject missing files, symlinks and traversal pins.
3. Use Python standard library and Git only. No new compiler or runtime dependencies, network requests or shell commands.
4. Add isolated, adversarial Python tests without changing existing Bend tests.
5. Preserve upstream `gates/repo.ts` and existing `repo-gate` job, and run an independent PR check.
6. Do not claim upstream benchmarks, compiler or proof verification were executed by the new audit.

Future work (separate PRs): run genuine compiler/proof suites with pinned toolchains, identify kernel/elaboration trust boundaries, compare CPU/CUDA results and measure performance against C99/QEC workloads. No merges without review of evidence.
