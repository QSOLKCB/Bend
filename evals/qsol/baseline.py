#!/usr/bin/env python3
"""BEND-QSOL-001: read-only upstream provenance audit (Python stdlib + git)."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


SCHEMA = "qsol.bend.baseline.v1"
RECEIPT_SCHEMA = "qsol.bend.receipt.v1"
DEFAULT_PINS = Path(__file__).with_name("pins.json")


def git(root, *args):
    """Run only fixed git subcommands, without shell interpretation."""
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc.stdout


def git_text(root, *args):
    return git(root, *args).decode("ascii").strip()


def read_pins(filename):
    pins = json.loads(Path(filename).read_text(encoding="utf-8"))
    if pins.get("schema") != SCHEMA or not isinstance(pins.get("files"), dict) or not pins["files"]:
        raise ValueError("Invalid baseline schema or empty pin set")
    if not re.fullmatch(r"[0-9a-f]{40}", pins.get("source_commit", "")):
        raise ValueError("Invalid baseline commit")
    for rel, blob in pins["files"].items():
        path = Path(rel)
        if (not rel or path.is_absolute() or not path.parts
                or any(p in ("..", ".") for p in path.parts)
                or not re.fullmatch(r"[0-9a-f]{40}", blob)):
            raise ValueError("Invalid pinned path or Git blob: " + repr(rel))
    return pins


def safe_file(root, rel):
    path = root
    for part in Path(rel).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Symlink in pinned path: " + rel)
    if not path.is_file():
        raise FileNotFoundError("Pinned file missing or not regular: " + rel)
    return path


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def collect(root, pins):
    # Resolve only the actual Git root: never trust a caller's relative CWD.
    root = Path(git_text(root, "rev-parse", "--show-toplevel")).resolve()
    head = git_text(root, "rev-parse", "--verify", "HEAD")
    tree = git_text(root, "rev-parse", "HEAD^{tree}")
    staged = git(root, "ls-files", "--stage", "-z")
    changed = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=no")
    records = {}
    all_match = True
    for rel, expected in sorted(pins["files"].items()):
        entry = {"expected_blob": expected}
        try:
            path = safe_file(root, rel)
            entry["head_blob"] = git_text(root, "rev-parse", "HEAD:" + rel)
            entry["worktree_blob"] = git_text(root, "hash-object", "--no-filters", "--", str(path))
            entry["worktree_sha256"] = file_sha256(path)
            entry["match"] = entry["head_blob"] == expected and entry["worktree_blob"] == expected
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            entry["match"] = False
            entry["error"] = type(exc).__name__
        records[rel] = entry
        all_match = all_match and entry["match"]
    record = {
        "schema": RECEIPT_SCHEMA,
        "source_commit": pins["source_commit"],
        "head_commit": head,
        "head_tree": tree,
        "tracked_files": len(staged.split(b"\0")) - 1,
        "tracked_index_sha256": hashlib.sha256(staged).hexdigest(),
        "dirty_tracked": bool(changed),
        "dirty_tracked_sha256": hashlib.sha256(changed).hexdigest(),
        "environment": {
            "python": platform.python_version(),
            "os": platform.system(),
            "architecture": platform.machine(),
        },
        "files": records,
        "verdict": "PASS" if all_match and not changed else "FAIL",
    }
    # This checksum detects accidental receipt corruption; it is NOT a signature.
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    record["receipt_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture", "verify"), help="Capture always records; verify also fails on drift")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Git checkout to inspect")
    parser.add_argument("--pins", type=Path, default=DEFAULT_PINS, help="Baseline pin file")
    parser.add_argument("--output", type=Path, help="Write new receipt exclusively; never overwrite")
    args = parser.parse_args(argv)
    try:
        receipt = collect(args.repo, read_pins(args.pins))
        rendered = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
        if args.output:
            # A prior PASS receipt cannot be silently replaced by a failed run.
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(args.output, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(rendered)
            print(str(args.output) + ": " + receipt["verdict"])
        else:
            sys.stdout.write(rendered)
        return 1 if args.mode == "verify" and receipt["verdict"] != "PASS" else 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("BEND-QSOL-001 ERROR: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
