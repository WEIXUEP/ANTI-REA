"""Behavior and input-boundary checks for the Python case/audit helpers."""
from io import BytesIO
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/python-leakage-audit/scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("pycase_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PythonCaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_script(self, name, *args):
        return subprocess.run([sys.executable, "-I", "-S", str(SCRIPTS / name), *map(str, args)],
                              capture_output=True, text=True, timeout=20, cwd=self.root)

    def test_static_pyc_inspection_does_not_execute(self):
        source = self.root / "input.py"
        sentinel = self.root / "executed.txt"
        source.write_text("from pathlib import Path\nPath(" + repr(str(sentinel)) + ").write_text('bad')\n"
                          "class SecretMixer:\n def apply(self, x): return x * 1664525\n")
        compiled = self.root / "input.pyc"
        py_compile.compile(str(source), cfile=str(compiled), doraise=True, dfile="private/build/root.py")
        result = self.run_script("audit.py", "--package", compiled, "--deny", "SecretMixer", "--out", self.root / "report", "--fail-on-deny")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(sentinel.exists())
        report = json.loads((self.root / "report.json").read_text())
        self.assertTrue(any("1664525" in code["disassembly"] for code in report["code"]))
        self.assertTrue(any(code["filename"] == "private/build/root.py" for code in report["code"]))

    def test_wrong_magic_is_an_explicit_gap(self):
        target = self.root / "bad.pyc"
        target.write_bytes(b"WRNG" + bytes(20))
        result = self.run_script("audit.py", "--package", target, "--out", self.root / "report")
        self.assertEqual(result.returncode, 2)
        self.assertTrue(json.loads((self.root / "report.json").read_text())["gaps"])

    def test_archive_traversal_duplicates_and_symlinks_rejected_before_write(self):
        extractor = load("extract")
        import stat
        for index, names in enumerate((["good.txt", "../outside.txt"], ["x.txt", "X.txt"], ["C:/bad.txt"], ["NUL.txt"],
                                       ["safe.txt", "a?b.txt"], ["a", "a/b"], [".EXTRACTION-MANIFEST.JSON"])):
            archive = self.root / (str(index) + ".zip")
            with zipfile.ZipFile(archive, "w") as stream:
                for name in names:
                    stream.writestr(name, b"data")
            output = self.root / ("out" + str(index))
            with self.assertRaises(ValueError):
                extractor.extract(archive, output)
            self.assertFalse(output.exists())
        archive = self.root / "symlink.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            stream.writestr(info, "target")
        with self.assertRaises(ValueError):
            extractor.extract(archive, self.root / "symlink-out")

    def test_extraction_limits_and_preserves_source(self):
        extractor = load("extract")
        with self.assertRaises(ValueError):
            extractor.inflate(zlib.compress(b"x" * 4096), limit=128)
        archive = self.root / "valid.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr("nested/a.txt", "hello")
        before = archive.read_bytes()
        output = self.root / "out"
        result = self.run_script("extract.py", "--input", archive, "--out", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / "nested/a.txt").read_text(), "hello")
        self.assertEqual(archive.read_bytes(), before)
        self.assertEqual(self.run_script("extract.py", "--input", archive, "--out", output).returncode, 2)

    def test_html_escaping_and_report_isolation(self):
        target = self.root / "input.py"
        target.write_text('value = "</script><script>alert(7)</script>"\n')
        bad = self.run_script("audit.py", "--package", self.root, "--out", self.root / "bad")
        self.assertEqual(bad.returncode, 2)
        result = self.run_script("audit.py", "--package", target, "--deny", "</script><script>alert(7)</script>", "--out", self.root / "report")
        self.assertEqual(result.returncode, 0, result.stderr)
        html = (self.root / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(7)</script>", html)
        self.assertIn("&lt;script&gt;alert(7)&lt;/script&gt;", html)
        self.assertEqual(self.run_script("audit.py", "--package", target, "--out", self.root / "report").returncode, 2)

    def test_capture_requires_explicit_execution(self):
        target = self.root / "input.py"
        target.write_text("raise RuntimeError('must not run')")
        result = self.run_script("capture.py", "--entry", target, "--module-prefix", "input", "--out", self.root / "capture")
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --execute", result.stderr)

    def test_baseline_corpus_mismatch_rejected(self):
        target = self.root / "input.txt"
        target.write_text("secret")
        self.assertEqual(self.run_script("audit.py", "--package", target, "--deny", "secret", "--out", self.root / "before").returncode, 0)
        result = self.run_script("audit.py", "--package", target, "--deny", "other", "--baseline", self.root / "before.json", "--out", self.root / "after")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "after.json").exists())

    def test_both_downloaded_skills_run_independently(self):
        spec = importlib.util.spec_from_file_location("python_site_hook", ROOT / "src/anti_rea/site_hook.py")
        hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hook)
        for skill in ("python-code-protection", "python-leakage-audit"):
            folder = self.root / skill
            with zipfile.ZipFile(BytesIO(hook.skill_archive(hook.skill_contents(ROOT, skill), skill))) as archive:
                archive.extractall(folder)
            scripts = folder / skill / "scripts"
            names = ("doctor.py",) if skill == "python-code-protection" else ("audit.py", "extract.py", "capture.py")
            for name in names:
                result = subprocess.run([sys.executable, "-I", "-S", str(scripts / name), "--help"],
                                        cwd=self.root, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
            if skill == "python-code-protection":
                result = subprocess.run([sys.executable, "-I", "-S", str(scripts / "doctor.py"), "--require", "cryptography"],
                                        cwd=self.root, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 1)
            else:
                target = self.root / "fixture.py"
                target.write_text("class HiddenClass: pass\n")
                result = subprocess.run([sys.executable, "-I", "-S", str(scripts / "audit.py"),
                    "--package", str(target), "--deny", "HiddenClass", "--fail-on-deny", "--out", str(self.root / "standalone")],
                    cwd=self.root, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertTrue((self.root / "standalone.html").is_file())

    @unittest.skipUnless(os.name == "nt", "Windows process-tree timeout check")
    def test_validator_timeout_records_failure(self):
        import argparse
        spec = importlib.util.spec_from_file_location("python_validator", ROOT / "tools/validate_python_windows.py")
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        trial = validator.Trial(argparse.Namespace(out=self.root / "trial"))
        with self.assertRaises(subprocess.TimeoutExpired):
            trial.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1)
        self.assertEqual(trial.state["commands"][-1]["timeout"], 0.1)

    def test_scanner_fingerprint_mismatch_rejected(self):
        target = self.root / "input.txt"
        target.write_text("secret")
        self.run_script("audit.py", "--package", target, "--out", self.root / "original")
        path = self.root / "original.json"
        baseline = json.loads(path.read_text())
        baseline["scanner_sha256"] = "0" * 64
        path.write_text(json.dumps(baseline))
        result = self.run_script("audit.py", "--package", target, "--baseline", path, "--out", self.root / "next")
        self.assertEqual(result.returncode, 2)

    def test_binary_path_candidate_is_located_without_execution(self):
        target = self.root / "app.bin"
        target.write_bytes(b"\0\0F:\\private\\build\\core.py\0")
        result = self.run_script("audit.py", "--package", target, "--out", self.root / "paths")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "paths.json").read_text())
        row = next(r for r in report["findings"] if r["category"] == "path-candidate")
        self.assertEqual(row["offset"], 2)
        self.assertEqual(row["value"], "F:\\private\\build\\core.py")


if __name__ == "__main__":
    unittest.main()
