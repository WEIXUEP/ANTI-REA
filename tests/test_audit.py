"""Exercise the standalone skill entry point and evidence comparisons."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/cpp-leakage-audit/scripts/audit.py"
spec = importlib.util.spec_from_file_location("standalone_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditAcceptanceTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True, timeout=30)

    def test_byte_matching_short_unicode_and_exact_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.dat"
            path.write_bytes(b"\x01XY\x02" + "内部错误".encode("utf-8") + b"\0" + "秘密".encode("utf-16le"))
            rows, _ = audit.scan_binary(path, deny=["XY", "内部错误", "秘密"])
            hits = {(r["evidence"], r["offset"], r["encoding"]) for r in rows if r["category"] == "denied-text"}
            self.assertIn(("XY", 1, "UTF-8"), hits)
            self.assertIn(("内部错误", 4, "UTF-8"), hits)
            self.assertIn(("秘密", 17, "UTF-16LE"), hits)

    def test_original_baseline_and_protected_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, protected = root / "original", root / "protected"
            original.mkdir()
            protected.mkdir()
            (original / "data.dat").write_bytes(b"\0SensitiveKernel\0")
            (protected / "data.dat").write_bytes(b"\0R_opaque\0")
            baseline, result = root / "baseline", root / "after"
            self.assertEqual(self.run_cli("--package", original, "--deny", "SensitiveKernel", "--out", baseline).returncode, 0)
            control = self.run_cli("--package", original, "--deny", "SensitiveKernel", "--fail-on-deny")
            self.assertEqual(control.returncode, 1)
            run = self.run_cli("--package", protected, "--deny", "SensitiveKernel", "--baseline", baseline.with_suffix(".json"),
                               "--require-metadata", "--fail-on-deny", "--out", result)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(result.with_suffix(".json").read_text())
            self.assertTrue(any(r["category"] == "denied-text" for r in report["comparison"]["resolved"]))
            self.assertEqual(len(report["artifacts"][0]["sha256"]), 64)
            self.assertEqual(report["artifacts"][0]["artifact"], "package/data.dat")
            mismatch = self.run_cli("--package", protected, "--baseline", baseline.with_suffix(".json"))
            self.assertEqual(mismatch.returncode, 2)
            self.assertIn("corpus", mismatch.stderr)
            previous = json.loads(baseline.with_suffix(".json").read_text())
            previous["scanner_sha256"] = "old scanner"
            (root / "old-scanner.json").write_text(json.dumps(previous))
            version = self.run_cli("--package", protected, "--deny", "SensitiveKernel", "--baseline", root / "old-scanner.json")
            self.assertEqual(version.returncode, 2)
            self.assertIn("scanner version differs", version.stderr)
            overwrite = self.run_cli("--package", protected, "--deny", "SensitiveKernel", "--baseline", baseline.with_suffix(".json"), "--out", baseline)
            self.assertEqual(overwrite.returncode, 2)
            (protected / "extra.dat").write_bytes(b"extra")
            changed = self.run_cli("--package", protected, "--deny", "SensitiveKernel", "--baseline", baseline.with_suffix(".json"))
            self.assertEqual(changed.returncode, 2)
            self.assertIn("inventory differs", changed.stderr)

    def test_package_private_artifacts_and_duplicate_basenames(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ("a/debug.pdb", "b/debug.pdb", "private/keys.json", "maps/rtti.json"):
                path = root / "release" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"private")
            report = root / "report"
            result = self.run_cli("--package", root / "release", "--fail-on-deny", "--out", report)
            self.assertEqual(result.returncode, 1)
            data = json.loads(report.with_suffix(".json").read_text())
            self.assertEqual(len(data["artifacts"]), 4)
            self.assertEqual(len({r["artifact"] for r in data["findings"] if r["category"] == "private-artifact"}), 4)

    def test_malformed_pe_is_an_unperformed_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.exe"
            path.write_bytes(b"MZ" + bytes(64))
            result = self.run_cli("--binary", path, "--require-metadata")
            self.assertEqual(result.returncode, 2)
            self.assertIn("parse failed", result.stdout)

    def test_packaged_executable_without_pe_header_is_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.exe"
            path.write_bytes(b"not a PE")
            result = self.run_cli("--package", directory, "--require-metadata")
            self.assertEqual(result.returncode, 2)
            self.assertIn("not an ELF or PE", result.stdout)

    @unittest.skipUnless(os.name == "nt", "Native PE fixture from the Python interpreter")
    def test_recovered_pe_import_parse_error_is_not_clean(self):
        import pefile
        with tempfile.TemporaryDirectory() as directory:
            # Mutate a private in-memory fixture, never the installed interpreter.
            pe = pefile.PE(data=Path(sys.executable).read_bytes(), fast_load=True)
            imports = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            imports.VirtualAddress = 0xffffffff
            imports.Size = 64
            path = Path(directory) / "bad-imports.exe"
            path.write_bytes(pe.write())
            rows, unchecked = audit.scan_binary(path)
            self.assertTrue(any(r["category"] == "pe-machine" for r in rows))
            self.assertTrue(any("parser warning" in item for item in unchecked), unchecked)
            self.assertEqual(self.run_cli("--binary", path, "--require-metadata").returncode, 2)

    def test_empty_package_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.run_cli("--package", directory).returncode, 2)

    def test_reports_cannot_modify_inputs_or_enter_release_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.json"
            original.write_bytes(b"original artifact")
            result = self.run_cli("--binary", original, "--out", root / "original")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(original.read_bytes(), b"original artifact")
            result = self.run_cli("--package", root, "--out", root / "audit")
            self.assertEqual(result.returncode, 2)
            self.assertIn("outside the release package", result.stderr)
            self.assertFalse((root / "audit.json").exists())

    def test_msvc_rtti_pointer_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.dat"
            path.write_bytes(b"\0.?AUExample@@\0.PEAVExample@@\0.?PEAUExample@@\0")
            rows, _ = audit.scan_binary(path)
            self.assertTrue(any(".?PEAUExample" in r["evidence"] for r in rows if r["category"] == "rtti"))


if __name__ == "__main__":
    unittest.main()
