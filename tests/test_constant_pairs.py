"""Validate the limited XOR-pair countertest independently of protection maps."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
from io import StringIO
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "skills/cpp-leakage-audit/scripts/probe_constant_pairs.py"
spec = importlib.util.spec_from_file_location("constant_pairs", TOOL)
pairs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pairs)


class ConstantPairTests(unittest.TestCase):
    def test_unaligned_adjacent_pairs_and_false_positive_boundary(self):
        value, mask = 0x5a827999, 0x93ed83e9
        data = b"x" + struct.pack("<II", mask, value ^ mask) + b"y"
        result = pairs.probe(data, [value], 100)
        self.assertTrue(result["complete"])
        self.assertEqual(result["scanned_windows"], 3)
        self.assertEqual([row["offset"] for row in result["findings"]], [1])
        self.assertEqual(result["findings"][0]["constant"], "u32le:0x5a827999")
        # The raw literal and nonadjacent shares are outside this mechanism.
        self.assertFalse(pairs.probe(struct.pack("<I", value), [value], 100)["findings"])
        split = struct.pack("<I", mask) + bytes(4) + struct.pack("<I", value ^ mask)
        self.assertFalse(pairs.probe(split, [value], 100)["findings"])

    def test_finding_limit_marks_coverage_incomplete(self):
        result = pairs.probe(bytes(20), [0], 2)
        self.assertFalse(result["complete"])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(result["scanned_windows"], 2)
        exact = pairs.probe(bytes(8), [0], 1)
        self.assertTrue(exact["complete"])

    def test_cli_bounds_hashes_exit_codes_and_read_only_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture.bin"
            data = struct.pack("<II", 0x11223344, 0x4ba04add)
            binary.write_bytes(data)
            command = [sys.executable, "-I", "-S", str(TOOL), "--binary", str(binary)]

            def run(*args):
                return subprocess.run([*command, *args], capture_output=True, text=True,
                                      cwd=directory, timeout=15)

            found = run("--constant", "u32le:0x5a827999")
            self.assertEqual(found.returncode, 1, found.stderr)
            report = json.loads(found.stdout)
            self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
            self.assertTrue(report["input_unchanged"])
            clean = run("--constant", "u32le:42")
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertEqual(json.loads(clean.stdout)["status"], "no-candidates")
            for args in [("--constant", "f64le:1"), ("--constant", "u32le:-1"),
                         ("--constant", "u32le:4294967296"),
                         ("--constant", "u32le:1", "--max-bytes", "7"),
                         ("--constant", "u32le:1", "--max-bytes", str(1 << 100)),
                         ("--constant", "u32le:1", "--max-findings", "0")]:
                result = run(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(binary.read_bytes(), data)
            self.assertEqual(list(Path(directory).iterdir()), [binary])
            binary.write_bytes(b"")
            self.assertEqual(run("--constant", "u32le:1").returncode, 2)

    def test_changed_input_is_rejected_without_candidate_report(self):
        stdout, stderr = StringIO(), StringIO()
        with patch.object(pairs, "snapshot", side_effect=[bytes(8), bytes(7) + b"x"]):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = pairs.main(["--binary", "unused.bin", "--constant", "u32le:0"])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(json.loads(stderr.getvalue())["status"], "error")
        self.assertIn("changed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
