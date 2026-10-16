"""Validate the public skill download without requiring runtime crypto packages."""
from io import BytesIO
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("site_hook", ROOT / "src/anti_rea/site_hook.py")
site_hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site_hook)


class PublicationTests(unittest.TestCase):
    def test_downloaded_scanner_runs_without_repository_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with ZipFile(BytesIO(site_hook.skill_archive(site_hook.skill_contents(ROOT)))) as archive:
                archive.extractall(root)
            package = root / "package"
            package.mkdir()
            (package / "asset.dat").write_bytes(b"\x01ConfidentialKernel\x02")
            report = root / "baseline"
            result = subprocess.run([sys.executable, "-I", str(root / "cpp-leakage-audit/scripts/audit.py"),
                "--package", str(package), "--deny", "ConfidentialKernel", "--fail-on-deny", "--out", str(report)],
                cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(report.with_suffix(".json").is_file())
            self.assertTrue((root / "cpp-leakage-audit/references/windows.md").is_file())

    def test_archive_matches_canonical_files(self):
        contents = site_hook.skill_contents(ROOT)
        with ZipFile(BytesIO(site_hook.skill_archive(contents))) as archive:
            self.assertEqual(set(archive.namelist()), {"cpp-leakage-audit/" + name for name in (*site_hook.SKILL_FILES, "LICENSE")})
            for name, expected in contents.items():
                self.assertEqual(archive.read("cpp-leakage-audit/" + name), expected)

    def test_unlisted_private_file_is_not_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "LICENSE").write_text("Public fixture license")
            directory = root / "skills/cpp-leakage-audit"
            for name in site_hook.SKILL_FILES:
                destination = directory / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("public fixture " + name)
            (directory / "private-key.json").write_text("PRIVATE_TEST_SENTINEL")
            contents = site_hook.skill_contents(root)
            with ZipFile(BytesIO(site_hook.skill_archive(contents))) as archive:
                self.assertNotIn("cpp-leakage-audit/private-key.json", archive.namelist())
                self.assertNotIn(b"PRIVATE_TEST_SENTINEL", b"".join(archive.read(name) for name in archive.namelist()))

    def test_missing_required_source_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(FileNotFoundError):
                site_hook.skill_contents(temporary)

    def test_download_is_reproducible(self):
        contents = site_hook.skill_contents(ROOT)
        self.assertEqual(site_hook.skill_archive(contents), site_hook.skill_archive(contents))

    def test_external_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "skills/cpp-leakage-audit"
            directory.mkdir(parents=True)
            external = root / "private.txt"
            external.write_text("PRIVATE_TEST_SENTINEL")
            try:
                (directory / "SKILL.md").symlink_to(external)
            except OSError:
                self.skipTest("Symlink creation unavailable")
            with self.assertRaises(ValueError):
                site_hook.skill_contents(root)


if __name__ == "__main__":
    unittest.main()
