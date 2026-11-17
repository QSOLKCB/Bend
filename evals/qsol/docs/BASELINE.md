# Baseline procedure (BEND-QSOL-001)

Reference: `bendlang/bend` as forked at `9c586f094f4fc88bef440dc8b4d77a2f92c257cc`. Source identities are stored in `../pins.json`. The audit is **read-only**: it performs no build, install, network operation, compiler execution or source edit.

From the checkout root:

```sh
python3 -m unittest discover -s evals/qsol -p 'test_*.py' -v
python3 evals/qsol/baseline.py verify
mkdir -p .tmp/qsol-evidence
python3 evals/qsol/baseline.py capture --output .tmp/qsol-evidence/before.json
# Run separately approved experiments here.
python3 evals/qsol/baseline.py capture --output .tmp/qsol-evidence/after.json
```

The `capture` command records a `PASS` or `FAIL` verdict but exits successfully on detected drift; `verify` exits 1 for drift. Missing or malformed inputs and receipt output errors exit 2. Existing output files cannot be overwritten. The `.tmp/` directory is already excluded by upstream's `.gitignore`.

Evidence fields:
- `source_commit` is the initial upstream pin, not necessarily the current checkout's HEAD.
- `head_commit` / `head_tree` identify the inspected committed revision.
- `tracked_index_sha256` hashes the exact NUL-delimited `git ls-files --stage -z` byte stream.
- Each pinned file is compared against its source Git blob in both HEAD and worktree; its worktree SHA-256 is also recorded.
- `dirty_tracked` exposes modifications to any tracked file; untracked files are intentionally not a failure.
- `receipt_sha256` hashes canonical JSON without itself; **this is not a cryptographic signature**.
- Python, OS and architecture are descriptive, not proof of toolchain validity.

Capture receipts before and after separately; their data should be retained outside an untrusted repository or archived with reviewable provenance. The record includes no user name or machine hostname. This check does **not** exercise Bend, Lean, CUDA, performance, compiler semantics, or upstream claims. The source gate excludes `evals/`; the separate QSOL CI job handles these records.

Any deliberate compiler or pinned-policy modification must be carried by a separately reviewed change, with an explicitly updated baseline and independent execution evidence.
