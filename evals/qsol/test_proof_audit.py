"""BEND-QSOL-002 harness tests; simulated toolchains are never proof evidence."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import proof_audit as audit


class ProofAuditUnitTests(unittest.TestCase):
    def test_strict_acceptance_does_not_confuse_infrastructure_with_rejection(self):
        r = {"exit_code": 1, "stdout": "SOME PROOFS FAIL\nIn bad:\nwrong type\n",
             "stderr": "", "timeout": False, "output_over_limit": False}
        self.assertTrue(audit.accepted(r, "kernel-reject"))
        self.assertFalse(audit.accepted(r, "pass"))
        self.assertFalse(audit.accepted(r | {"exit_code": 0}, "kernel-reject"))
        self.assertFalse(audit.accepted(r | {"timeout": True}, "kernel-reject"))
        self.assertFalse(audit.accepted(r | {"stderr": "panic"}, "kernel-reject"))
        self.assertFalse(audit.accepted(r | {"stdout": "Error: kernel missing"}, "kernel-reject"))
        self.assertFalse(audit.accepted(r | {"output_over_limit": True}, "kernel-reject"))
        self.assertTrue(audit.accepted(r, "source-reject"))
        self.assertFalse(audit.accepted(r | {"stdout": "SOME PROOFS FAIL\nBendTT infrastructure"}, "source-reject"))

    def test_receipt_seal_detects_mutation(self):
        record = {"schema": audit.SCHEMA, "verdict": "PASS", "source": "example"}
        original = audit.seal(record)
        record["verdict"] = "FAIL"
        self.assertNotEqual(original, audit.seal(record))

    def test_checked_source_paths_reject_links_and_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "valid.bend").write_text("type X\n", encoding="utf-8")
            self.assertEqual(audit.regular(root, "valid.bend"), root / "valid.bend")
            for bad in ("../valid.bend", "/tmp/x.bend", "missing.bend"):
                with self.assertRaises(audit.AuditError):
                    audit.regular(root, bad)
            (root / "link.bend").symlink_to(root / "valid.bend")
            with self.assertRaises(audit.AuditError):
                audit.regular(root, "link.bend")

    def test_process_timeout_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = audit.run([sys.executable, "-c", "import time; time.sleep(2)"],
                               cwd=tmp, env=os.environ.copy(), timeout=0.1)
            self.assertTrue(result["timeout"])
            self.assertFalse(audit.accepted(result, "pass"))

    def test_nonexistent_kernel_emits_failure_receipt_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_sources(root)
            with patch.object(audit.baseline, "read_pins", return_value={}), \
                 patch.object(audit.baseline, "collect", return_value=self.good_baseline()):
                got = audit.execute(root, root, sys.executable, root / "missing-kernel", None,
                                    "leanc", timeout=2)
            self.assertEqual(got["status"], "FAIL")
            self.assertTrue(got["receipt_sha256"])
            self.assertTrue(got["errors"])

    @staticmethod
    def good_baseline():
        return {"verdict": "PASS", "head_commit": "a" * 40,
                "source_commit": "b" * 40, "receipt_sha256": "c" * 64}

    @staticmethod
    def make_sources(root):
        for rel in (audit.NEGATIVE, audit.UNSAFE, *(p for _, p in audit.CASES)):
            at = root / rel
            at.parent.mkdir(parents=True, exist_ok=True)
            at.write_text(rel + "\n", encoding="utf-8")

    @staticmethod
    def fake_tool(root, name, code):
        at = root / name
        at.write_text("#!" + sys.executable + "\n" + code, encoding="utf-8")
        at.chmod(0o755)
        return at

    def simulate_pipeline(self, kernel_accepts_everything=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_sources(root)
            fake_bun = self.fake_tool(root, "bun-fake", '''
import pathlib, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("1.4.0")
elif any("false_reflexivity" in x for x in args):
    print("SOME PROOFS FAIL\\nError: false equality", file=sys.stderr)
    sys.exit(1)
elif any("unsafe_loop" in x for x in args):
    print("SOME PROOFS FAIL\\nError: 1 def relies on unsafe or foreign code", file=sys.stderr)
    sys.exit(1)
elif "--check-only" in args:
    print("ALL PROOFS CHECK\\nUse --verdict for mathematical validity.")
elif "--verdict" in args:
    print("ALL PROOFS CHECK")
elif "-o" in args:
    pathlib.Path(args[-1]).write_text("hello: *1 = *1\\n", encoding="utf-8")
else:
    sys.exit(2)
''')
            fake_kernel = self.fake_tool(root, "kernel-fake", '''
import pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
if b"QSOL_unsound" in raw and not ''' + str(kernel_accepts_everything) + ''':
    print("SOME PROOFS FAIL\\nIn QSOL_unsound: bad type")
    sys.exit(1)
print("ALL PROOFS CHECK")
''')
            out = root / "evidence"
            out.mkdir()
            with patch.object(audit.baseline, "read_pins", return_value={}), \
                 patch.object(audit.baseline, "collect", return_value=self.good_baseline()):
                rec = audit.execute(root, out, str(fake_bun), fake_kernel, None,
                                    "leanc", timeout=3)
            return rec

    def test_synthetic_pipeline_checks_both_paths(self):
        got = self.simulate_pipeline()
        self.assertEqual(got["status"], "PASS", got["errors"])
        self.assertEqual(len(got["steps"]), 15)
        self.assertTrue(all(x["passed"] for x in got["steps"]))
        self.assertIn("reflexivity.bendtt", got["artifacts"])

    def test_accept_everything_kernel_fails_canary(self):
        got = self.simulate_pipeline(kernel_accepts_everything=True)
        self.assertEqual(got["status"], "FAIL")
        self.assertTrue(any("kernel-canary" in error for error in got["errors"]))


if __name__ == "__main__":
    unittest.main()
