"""Adversarial tests for BEND-QSOL-001; no Bend runtime needed."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


MODULE = Path(__file__).with_name("baseline.py")
SPEC = importlib.util.spec_from_file_location("qsol_bend_baseline", MODULE)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], stderr=subprocess.PIPE
    ).decode("ascii").strip()


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        self.code = self.root / "bend2" / "bend.ts"
        self.code.parent.mkdir()
        self.code.write_text("original\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "fixture")
        self.initial_head = git(self.root, "rev-parse", "HEAD")
        self.original_blob = git(self.root, "rev-parse", "HEAD:bend2/bend.ts")
        self.pins = {
            "schema": audit.SCHEMA, "source_commit": self.initial_head,
            "files": {"bend2/bend.ts": self.original_blob},
        }

    def test_clean_checkout_passes_and_receipt_is_sealed(self):
        result = audit.collect(self.root, self.pins)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["tracked_files"], 1)
        self.assertEqual(result["files"]["bend2/bend.ts"]["worktree_sha256"],
                         hashlib.sha256(b"original\n").hexdigest())
        seal = result.pop("receipt_sha256")
        canonical = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(seal, hashlib.sha256(canonical.encode()).hexdigest())

    def test_unicode_checkout_path_works_in_both_cli_modes(self):
        unicode_root = self.root.parent / "bend-é-測試"
        self.root.rename(unicode_root)
        self.root = unicode_root
        pins = self.root.parent / "unicode-pins.json"
        pins.write_text(json.dumps(self.pins), encoding="utf-8")
        # Git object IDs remain ASCII even when the working directory is not.
        self.assertEqual(audit.git_text(self.root, "rev-parse", "HEAD"), self.initial_head)
        for mode in ("verify", "capture"):
            with self.subTest(mode=mode):
                receipt_path = self.root.parent / (mode + "-unicode.json")
                self.assertEqual(
                    audit.main([mode, "--repo", str(self.root), "--pins", str(pins),
                                "--output", str(receipt_path)]), 0,
                )
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                self.assertEqual(receipt["verdict"], "PASS")
                self.assertEqual(receipt["head_commit"], self.initial_head)

    def test_dirty_worktree_detected_without_commit(self):
        self.code.write_text("tampered\n", encoding="utf-8")
        result = audit.collect(self.root, self.pins)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(result["dirty_tracked"])
        self.assertFalse(result["files"]["bend2/bend.ts"]["match"])

    def test_clean_commit_cannot_repin_source_silently(self):
        self.code.write_text("new committed code\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "change source")
        result = audit.collect(self.root, self.pins)
        self.assertFalse(result["dirty_tracked"])
        self.assertEqual(result["verdict"], "FAIL")
        self.assertNotEqual(result["files"]["bend2/bend.ts"]["head_blob"], self.original_blob)

    def test_missing_pinned_file_fails(self):
        self.code.unlink()
        result = audit.collect(self.root, self.pins)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["files"]["bend2/bend.ts"]["error"], "FileNotFoundError")

    def test_symlink_escape_is_rejected(self):
        outside = Path(self.tmp.name) / "secret.txt"
        outside.write_text("not your source\n", encoding="utf-8")
        self.code.unlink()
        self.code.symlink_to(outside)
        result = audit.collect(self.root, self.pins)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["files"]["bend2/bend.ts"]["error"], "ValueError")

    def test_traversal_pin_rejected(self):
        pins = self.root / "bad-pins.json"
        pins.write_text(json.dumps({
            "schema": audit.SCHEMA, "source_commit": self.initial_head,
            "files": {"../secret": self.original_blob},
        }), encoding="utf-8")
        with self.assertRaises(ValueError):
            audit.read_pins(pins)

    def test_failed_verification_persists_receipt_without_overwrite(self):
        pins = Path(self.tmp.name) / "pins.json"
        pins.write_text(json.dumps(self.pins), encoding="utf-8")
        receipt = Path(self.tmp.name) / "receipt.json"
        self.code.write_text("damaged\n", encoding="utf-8")
        self.assertEqual(audit.main(["verify", "--repo", str(self.root),
                                     "--pins", str(pins), "--output", str(receipt)]), 1)
        self.assertEqual(json.loads(receipt.read_text())["verdict"], "FAIL")
        self.assertEqual(audit.main(["verify", "--repo", str(self.root),
                                     "--pins", str(pins), "--output", str(receipt)]), 2)
        self.assertEqual(json.loads(receipt.read_text())["verdict"], "FAIL")

    def test_capture_records_drift_but_does_not_claim_pass(self):
        pins = Path(self.tmp.name) / "pins.json"
        pins.write_text(json.dumps(self.pins), encoding="utf-8")
        receipt = Path(self.tmp.name) / "capture.json"
        self.code.write_text("changed\n", encoding="utf-8")
        self.assertEqual(audit.main(["capture", "--repo", str(self.root),
                                     "--pins", str(pins), "--output", str(receipt)]), 0)
        result = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["source_commit"], self.initial_head)


if __name__ == "__main__":
    unittest.main()
