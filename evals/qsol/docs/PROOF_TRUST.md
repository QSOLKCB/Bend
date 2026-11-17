# BEND-QSOL-002 — Proof-System Trust Boundary Audit

**Status:** runnable experiment, *not* a claim that the Bend compiler or the Lean proof system has been independently certified.

This study keeps the upstream TypeScript checker, translation code, Lean kernel, compiler and runtime **unchanged**. All executable additions live under `evals/qsol/`. No new language/runtime dependencies, downloads, or network operations are introduced.

## Inspected trust path (at initial upstream snapshot)

1. **Source acceptance:** `bend2/main.ts` calls `book_read` (`Bend.book_load`, `Bend.book_valid` from `bend2/bend.ts`), then `cli_verdict(book, false)` for `--check-only`. This is the source checker, not an independent kernel proof.
2. **Admissibility:** `cli_verdict` refuses `@unsafe` and foreign dependencies via `book_promises`. The kernel path is taken only with `--verdict` and no such unresolved promises.
3. **Elaboration:** `bend2/safe.ts` implements `safe_book` / `safe_emit`, translating an accepted Bend book to BendTT. `safe_check` **fails** on out-of-scope definitions; `-o file.bendtt` exposes the translation but may omit out-of-scope definitions. The harness rejects an emitted file if the CLI reports diagnostics.
4. **Kernel:** `safe_check` calls `kernel_check`, which invokes a separately built executable from `bend2/bendtt.lean` (or `BENDTT`). In Lean, `Book.parse` and `Book.check` return `ALL PROOFS CHECK` / `SOME PROOFS FAIL`. Upstream pins Lean **4.34.0** via `bend2/safe.ts`.
5. **Independent invocation:** this harness asks Bend to emit BendTT twice, hashes both outputs, runs the supplied kernel on the exact emitted bytes, and appends an ill-typed BendTT canary to establish that the kernel rejects an altered intermediate input. It also substitutes a denial-only kernel for one `--verdict` call to check that the CLI actually fails when its kernel rejects a valid source. These exercises compare direct kernel behavior with Bend's `--verdict` route.

**Crucial distinction:** independently invoking the **same BendTT kernel** on emitted text does **not** independently prove that `safe.ts` elaboration preserves the meaning of the Bend source. That semantic correspondence remains an explicit trusted boundary. Similarly, a compiled Lean kernel and the host toolchain remain trusted; source checks do not establish native/CUDA backend correctness.

## Cases and expected verdicts

| Case | Purpose | Expected |
| --- | --- | --- |
| `tests/proof/reflexivity_basic.bend` | Primitive equality witness through source, emitted BendTT and kernel | PASS on all three |
| `tests/proof/add_comm.bend` | Induction, recursive definitions and explicit-motive rewriting | PASS on all three |
| `evals/qsol/fixtures/false_reflexivity.bend` | False equality witness | Rejected by source `--check-only` and `--verdict` |
| `tests/check/unsafe_loop.bend` | Unsafe promise boundary | `--verdict` refused for unsafe dependency |
| Appended `QSOL_unsound: *1 = {==}` to each emitted book | Ill-typed, **parseable** BendTT added after elaboration | Direct kernel returns `SOME PROOFS FAIL` |
| Repeat emission of each positive | Check deterministic elaboration | Byte-identical SHA-256 |
| Denial-only kernel substituted through `BENDTT` | Check `--verdict` cannot ignore a rejecting kernel | CLI rejects valid source with injected diagnostic |

The canary demonstrates a fail-closed negative input; it is not an exhaustive proof of kernel soundness or evidence that the original Bend source is false. The proof content is intentionally small, which makes failures attributable.

## Reproducible, offline execution

Prerequisites: Git, Python 3, **Bun 1.4.0**, **Lean 4.34.0** and matching `leanc` already installed locally. These are existing upstream compiler/proof toolchains, not Python packages added by this PR. No `npm install`, `uv add` or download is performed by the scripts. Lean compilation may require the usual local C compiler and development libraries.

From a **clean** checkout of the PR branch (or the eventual merge commit):

```sh
python3 -m unittest discover -s evals/qsol -p 'test_*.py' -v
python3 evals/qsol/baseline.py verify
python3 evals/qsol/proof_audit.py --build-kernel --out .tmp/qsol-proof-002-first
```

The `--build-kernel` option builds `bend2/bendtt.lean` using the exact upstream Lean commands (`lean -c`, then `leanc -O3 -DNDEBUG`) and retains the kernel and translation artifacts in the evidence directory. To use an **existing** kernel binary rather than rebuild it:

```sh
python3 evals/qsol/proof_audit.py --kernel /absolute/path/to/bendtt \
  --out .tmp/qsol-proof-002-prebuilt
```

When `--kernel` is supplied, its SHA-256 is recorded but its compilation lineage is **not** established. Pass `--lean lean` to additionally check the installed Lean version, without pretending that this identifies the binary's build chain. Use a **new output path for each run**: the harness refuses to overwrite an existing directory, avoiding stale PASS evidence. The harness sets `BEND_NO_TELEMETRY=1` and executes only checks/elaboration/kernel invocations (not an arbitrary Bend `main`).

## Evidence and limitations

`receipt.json` records:
- Exact source HEAD and BEND-QSOL-001 pinned reference commit, plus source-baseline result;
- SHA-256 of each input fixture, emitted BendTT, repeated translation, and poisoned BendTT;
- Bun version, kernel executable SHA-256, and optionally Lean toolchain and source hashes;
- Actual subprocess argv, exit code, wall-clock duration, timeouts and bounded stdout/stderr excerpts, plus SHA-256 digests of captured output bytes (partial if a process is killed at the cap);
- Per-step expectations/results and a receipt-wide PASS/FAIL with a canonical JSON SHA-256.

A timeout, missing tool, incompatible version, source drift, unexpected stderr, missing translation, unexpected kernel acceptance, **non-specific error on the false-equality case**, **output exceeding 1 MiB**, or mismatched translation fails the experiment. Failure receipts are written to the new output directory. SHA-256 records are **integrity hashes, not cryptographic signatures**.

The original `qsol-baseline` GitHub job discovers the new `test_proof_audit.py` unit tests with stdlib Python. Those unit tests include **simulated fake toolchains** and never substitute for running the real Bend and Lean commands. The actual integration requires an installed toolchain; if the fork has no Actions runs, do not label the semantic tests as CI-proven.

### Follow-up research (separate PR)

- Inspect `safe_book`/BendTT elaboration by syntax category (dependent substitution, erased quantities, higher-order equality and template instantiation).
- Compare proof acceptance across exact revisions and directly analyze the Lean statement/proof coverage, admitted axioms and kernel assumptions.
- Audit unsafe/foreign influence and counterexamples that could survive source validation but be lost in elaboration.
- Evaluate the backend correctness and performance separately; neither is proved here.
