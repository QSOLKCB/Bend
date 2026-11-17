#!/usr/bin/env python3
"""BEND-QSOL-002: source -> elaboration -> separately invoked BendTT audit.

No downloads, toolchain installation, or execution of compiled Bend programs.
Requires the existing Bun and BendTT/Lean toolchains to be supplied locally.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time

import baseline

SCHEMA = "qsol.bend.proof_audit.v1"
BUN_VERSION = "1.4.0"  # The version pinned by upstream's repo gate.
LEAN_VERSION = "4.34.0"  # bend2/safe.ts: LEAN_VERSION.
PASS = "ALL PROOFS CHECK"
FAIL = "SOME PROOFS FAIL"
MAX_OUTPUT = 1024 * 1024
CASES = (
    ("reflexivity", "tests/proof/reflexivity_basic.bend"),
    ("inductive-add-comm", "tests/proof/add_comm.bend"),
)
NEGATIVE = "evals/qsol/fixtures/false_reflexivity.bend"
UNSAFE = "tests/check/unsafe_loop.bend"
# Deliberate, well-formed BendTT definition with an ill-typed body.
# {==} is an equality witness, not a term of *1 (Type).
KERNEL_CANARY = b"\nQSOL_unsound: *1 = {==}\n"


class AuditError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular(root, rel):
    """Do not traverse symlinks or checkout-relative '..' components."""
    p = Path(rel)
    if p.is_absolute() or not p.parts or any(part in (".", "..") for part in p.parts):
        raise AuditError("Unsafe source path: " + str(rel))
    at = root
    for part in p.parts:
        at = at / part
        if at.is_symlink():
            raise AuditError("Symlink source path: " + str(rel))
    if not at.is_file():
        raise AuditError("Missing source: " + str(rel))
    return at


def run(command, *, cwd, env, timeout=60):
    """Drain stdout/stderr with a hard combined byte cap and a group deadline."""
    start = time.monotonic()
    proc = subprocess.Popen(
        [str(arg) for arg in command], cwd=cwd, env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=(os.name == "posix"),
    )
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    totals = {"stdout": 0, "stderr": 0}
    timed_out = False
    output_over_limit = False
    killed = False
    killed_at = None

    def terminate():
        nonlocal killed, killed_at
        if killed:
            return
        killed = True
        killed_at = time.monotonic()
        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()

    try:
        with selectors.DefaultSelector() as sel:
            for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
                sel.register(pipe, selectors.EVENT_READ, data=name)
            while sel.get_map():
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0 and not killed:
                    timed_out = True
                    terminate()
                ready = sel.select(timeout=0.1 if killed else max(0.0, min(remaining, 0.1)))
                for key, _ in ready:
                    name = key.data
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        sel.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    totals[name] += len(data)
                    digests[name].update(data)
                    if len(chunks[name]) < 3000:
                        chunks[name].extend(data[:3000 - len(chunks[name])])
                    if totals["stdout"] + totals["stderr"] > MAX_OUTPUT:
                        output_over_limit = True
                        terminate()
                if killed and time.monotonic() - killed_at > 3:
                    # A subprocess could deliberately retain a pipe outside its
                    # process group. Never wait forever for that pipe's EOF.
                    break
        if killed:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        else:
            try:
                proc.wait(timeout=max(0.01, timeout - (time.monotonic() - start)))
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate()
                proc.wait(timeout=3)
    finally:
        for pipe in (proc.stdout, proc.stderr):
            if not pipe.closed:
                pipe.close()
        if proc.poll() is None:
            terminate()
            proc.wait()
    return {
        "argv": [str(x) for x in command],
        "exit_code": proc.returncode,
        "timeout": timed_out,
        "duration_ms": round((time.monotonic() - start) * 1000),
        "stdout_sha256": digests["stdout"].hexdigest(),
        "stderr_sha256": digests["stderr"].hexdigest(),
        "stdout": chunks["stdout"].decode("utf-8", errors="replace"),
        "stderr": chunks["stderr"].decode("utf-8", errors="replace"),
        "truncated": any(totals[name] > 3000 for name in totals),
        "output_over_limit": output_over_limit,
    }


def accepted(result, mode):
    if result["timeout"] or result["output_over_limit"]:
        return False
    output = "\n".join(part.strip() for part in (result["stdout"], result["stderr"]) if part.strip())
    if mode == "pass":
        return result["exit_code"] == 0 and result["stdout"].strip() == PASS and not result["stderr"].strip()
    if mode == "source-pass":
        return result["exit_code"] == 0 and result["stdout"].startswith(PASS + "\n") and not result["stderr"].strip()
    if mode == "source-reject":
        return (result["exit_code"] == 1 and output.startswith(FAIL)
                and "- expected :" in output and "- observed :" in output
                and "{0 == 1 : U32}" in output and "Location: main" in output
                and "stack overflow" not in output.lower())
    if mode == "unsafe-reject":
        return result["exit_code"] == 1 and FAIL in output and "unsafe or foreign code" in output
    if mode == "kernel-reject":
        return result["exit_code"] == 1 and result["stdout"].startswith(FAIL + "\n") and not result["stderr"].strip()
    if mode == "forced-deny":
        return (result["exit_code"] == 1 and FAIL in output
                and "QSOL forced kernel denial" in output
                and "BendTT infrastructure" not in output)
    if mode == "exit-zero":
        return result["exit_code"] == 0
    if mode == "emit":
        return result["exit_code"] == 0 and not result["stdout"].strip() and not result["stderr"].strip()
    raise AuditError("Unknown expectation: " + mode)


def seal(record):
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(canonical.encode("utf-8"))


def execute(root, out, bun, kernel, lean, leanc, *, build_kernel=False, timeout):
    """Run all checks, even when an earlier semantic check fails."""
    env = os.environ.copy()
    env["BEND_NO_TELEMETRY"] = "1"
    rec = {"schema": SCHEMA, "status": "FAIL", "baseline": None,
           "source_commit": None, "head_commit": None, "steps": [],
           "toolchains": {}, "artifacts": {}, "errors": [],
           "host": {"os": platform.system(), "arch": platform.machine(),
                    "python": platform.python_version()}}
    def step(label, command, expectation, *, cwd=root, run_env=None):
        try:
            entry = run(command, cwd=cwd, env=env if run_env is None else run_env, timeout=timeout)
            entry["name"] = label
            entry["expectation"] = expectation
            entry["passed"] = accepted(entry, expectation)
            rec["steps"].append(entry)
            if not entry["passed"]:
                rec["errors"].append(label + ": expected " + expectation)
            return entry["passed"]
        except (OSError, ValueError) as exc:
            rec["errors"].append(label + ": infrastructure: " + str(exc))
            return False

    try:
        pins = baseline.read_pins(root / "evals/qsol/pins.json")
        b = baseline.collect(root, pins)
        rec["baseline"] = b["verdict"]
        rec["source_commit"] = b["source_commit"]
        rec["head_commit"] = b["head_commit"]
        rec["baseline_receipt_sha256"] = b["receipt_sha256"]
        if b["verdict"] != "PASS":
            raise AuditError("BEND-QSOL-001 source pins or tracked worktree differ")
        for rel in (NEGATIVE, UNSAFE, *(path for _, path in CASES)):
            rec["artifacts"][rel] = file_hash(regular(root, rel))
        exe = shutil.which(bun)
        if exe is None:
            raise AuditError("Bun executable not found: " + bun)
        v = run([exe, "--version"], cwd=root, env=env, timeout=timeout)
        rec["toolchains"]["bun_version"] = v["stdout"].strip()
        rec["toolchains"]["bun_executable_sha256"] = file_hash(exe)
        if v["timeout"] or v["exit_code"] != 0 or v["stdout"].strip() != BUN_VERSION:
            raise AuditError("Bun version must equal " + BUN_VERSION)
        if build_kernel or lean:
            ln = shutil.which(lean or "lean")
            lc = shutil.which(leanc)
            if not ln or not lc:
                raise AuditError("Lean and leanc are required for a local kernel build or --lean verification")
            v = run([ln, "--version"], cwd=root, env=env, timeout=timeout)
            rec["toolchains"]["lean_version"] = v["stdout"].strip()
            match = re.search(r"^Lean \(version ([^,\s)]+)", v["stdout"])
            if v["timeout"] or v["exit_code"] != 0 or match is None or match.group(1) != LEAN_VERSION:
                raise AuditError("Lean version must equal " + LEAN_VERSION)
            rec["toolchains"]["lean_executable_sha256"] = file_hash(ln)
            rec["toolchains"]["leanc_executable_sha256"] = file_hash(lc)
        if build_kernel:
            kp = out / "bendtt"
            source = regular(root, "bend2/bendtt.lean")
            rec["toolchains"]["lean_source_sha256"] = file_hash(source)
            build = out / "kernel-build"
            build.mkdir()
            shutil.copyfile(source, build / "bendtt.lean")
            if not step("kernel:lean-to-c", [ln, "-c", "bendtt.c", "bendtt.lean"],
                        "exit-zero", cwd=build):
                raise AuditError("Lean kernel C-generation failed")
            if not step("kernel:c-to-native", [lc, "-O3", "-DNDEBUG", "bendtt.c", "-o", str(kp)],
                        "exit-zero", cwd=build):
                raise AuditError("BendTT native build failed")
        else:
            kp = Path(kernel).absolute()
        if kp.is_symlink() or not kp.is_file() or not os.access(kp, os.X_OK):
            raise AuditError("--kernel must name an existing executable regular file")
        rec["toolchains"]["bendtt_sha256"] = file_hash(kp)
        rec["toolchains"]["kernel_provenance"] = "built-from-pinned-source" if build_kernel else "externally-supplied"
        env["BENDTT"] = str(kp)

        for name, source in CASES:
            arg = [exe, "bend2/main.ts", source]
            if not step(name + ":source", arg + ["--check-only"], "source-pass"):
                continue
            if not step(name + ":verdict", arg + ["--verdict"], "pass"):
                continue
            emit1 = out / (name + ".bendtt")
            emit2 = out / (name + ".repeat.bendtt")
            if not step(name + ":elaborate", arg + ["-o", str(emit1)], "emit"):
                continue
            if not emit1.is_file() or emit1.stat().st_size == 0:
                rec["errors"].append(name + ": no BendTT output")
                continue
            rec["artifacts"][emit1.name] = file_hash(emit1)
            if not step(name + ":kernel", [kp, emit1], "pass"):
                continue
            if not step(name + ":elaborate-repeat", arg + ["-o", str(emit2)], "emit"):
                continue
            rec["artifacts"][emit2.name] = file_hash(emit2)
            if rec["artifacts"][emit1.name] != rec["artifacts"][emit2.name]:
                rec["errors"].append(name + ": translation differs across two runs")
            poisoned = out / (name + ".canary.bendtt")
            poisoned.write_bytes(emit1.read_bytes() + KERNEL_CANARY)
            rec["artifacts"][poisoned.name] = file_hash(poisoned)
            step(name + ":kernel-canary", [kp, poisoned], "kernel-reject")
        # Force Bend's CLI to run a denial-only kernel. A success here would
        # indicate it bypassed the kernel or ignored its negative verdict.
        denial = out / "deny_kernel"
        denial.write_text("#!" + sys.executable + "\nimport sys\n"
                          "print('SOME PROOFS FAIL\\nQSOL forced kernel denial')\n"
                          "sys.exit(1)\n", encoding="utf-8")
        denial.chmod(0o700)
        rec["artifacts"][denial.name] = file_hash(denial)
        step("verdict:forced-kernel-denial",
             [exe, "bend2/main.ts", CASES[0][1], "--verdict"],
             "forced-deny", run_env={**env, "BENDTT": str(denial)})
        step("false-reflexivity:source", [exe, "bend2/main.ts", NEGATIVE, "--check-only"], "source-reject")
        step("false-reflexivity:verdict", [exe, "bend2/main.ts", NEGATIVE, "--verdict"], "source-reject")
        step("unsafe-promise:verdict", [exe, "bend2/main.ts", UNSAFE, "--verdict"], "unsafe-reject")
    except (AuditError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        rec["errors"].append(str(exc))
    rec["status"] = "PASS" if not rec["errors"] else "FAIL"
    rec["receipt_sha256"] = seal(rec)
    return rec


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument("--out", type=Path, required=True, help="New evidence directory; existing paths fail closed")
    p.add_argument("--bun", default="bun", help="Bun 1.4.0 executable")
    kernel_group = p.add_mutually_exclusive_group(required=True)
    kernel_group.add_argument("--kernel", type=Path, help="Existing BendTT executable (hash recorded)")
    kernel_group.add_argument("--build-kernel", action="store_true", help="Build from pinned BendTT source using installed Lean 4.34.0")
    p.add_argument("--lean", help="Optional Lean executable, must be v4.34.0")
    p.add_argument("--leanc", default="leanc", help="Optional Lean C compiler for version inventory")
    p.add_argument("--timeout", type=int, default=90)
    a = p.parse_args(argv)
    if not 1 <= a.timeout <= 600:
        p.error("--timeout must be between 1 and 600 seconds")
    root = a.repo.resolve()
    output = a.out.absolute()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        print("Cannot create exclusive output directory: " + str(exc), file=sys.stderr)
        return 2
    rec = execute(root, output, a.bun, a.kernel, a.lean, a.leanc,
                  build_kernel=a.build_kernel, timeout=a.timeout)
    (output / "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("BEND-QSOL-002 " + rec["status"] + ": " + str(output / "receipt.json"))
    return 0 if rec["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
