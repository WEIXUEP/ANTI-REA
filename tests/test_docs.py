"""Validate both public skill downloads and their publication boundaries."""
from io import BytesIO
import importlib.util
from pathlib import Path
import re
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
            self.assertFalse((root / "cpp-code-protection").exists())

    def test_archives_match_canonical_files(self):
        for skill, names in site_hook.SKILL_FILES.items():
            with self.subTest(skill=skill):
                contents = site_hook.skill_contents(ROOT, skill)
                with ZipFile(BytesIO(site_hook.skill_archive(contents, skill))) as archive:
                    self.assertEqual(set(archive.namelist()), {skill + "/" + name for name in (*names, "LICENSE")})
                    for name, expected in contents.items():
                        self.assertEqual(archive.read(skill + "/" + name), expected)

    def test_capabilities_are_separate(self):
        audit = site_hook.skill_contents(ROOT, "cpp-leakage-audit")
        protection = site_hook.skill_contents(ROOT, "cpp-code-protection")
        self.assertIn("scripts/audit.py", audit)
        self.assertNotIn("scripts/audit.py", protection)
        for name in ("generate_keys.py", "decode.py", "_recovery.py", "doctor.py", "measure.py"):
            self.assertNotIn("scripts/" + name, audit)
            self.assertIn("scripts/" + name, protection)

    def test_generated_pages_do_not_overwrite_documentation_routes(self):
        sources = [path.relative_to(ROOT / "docs") for path in (ROOT / "docs").rglob("*.md")]
        for skill, route in site_hook.SKILL_ROUTES.items():
            sources.extend(Path(route) / ("index.md" if name == "SKILL.md" else name)
                           for name in site_hook.SKILL_FILES[skill] if name.endswith(".md"))
        routes = {}
        for source in sources:
            destination = source.parent if source.name == "index.md" else source.with_suffix("")
            self.assertNotIn(destination, routes, (source, routes.get(destination)))
            routes[destination] = source

    def test_markdown_links_stay_within_each_archive(self):
        for skill in site_hook.SKILL_FILES:
            contents = site_hook.skill_contents(ROOT, skill)
            for source, data in contents.items():
                if not source.endswith(".md"):
                    continue
                for link in re.findall(r"\]\(([^)]+)\)", data.decode()):
                    if "://" in link or link.startswith("#"):
                        continue
                    destination = (Path(source).parent / link.split("#")[0]).as_posix()
                    self.assertIn(destination, contents, (skill, source, link))

    def test_unlisted_private_files_are_not_published(self):
        for skill, names in site_hook.SKILL_FILES.items():
            with self.subTest(skill=skill), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "LICENSE").write_text("Public fixture license")
                directory = root / "skills" / skill
                for name in names:
                    destination = directory / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text("public fixture " + name)
                (directory / "private-key.json").write_text("PRIVATE_TEST_SENTINEL")
                contents = site_hook.skill_contents(root, skill)
                with ZipFile(BytesIO(site_hook.skill_archive(contents, skill))) as archive:
                    self.assertNotIn(skill + "/private-key.json", archive.namelist())
                    self.assertNotIn(b"PRIVATE_TEST_SENTINEL", b"".join(archive.read(name) for name in archive.namelist()))

    def test_missing_required_source_fails(self):
        for skill in site_hook.SKILL_FILES:
            with self.subTest(skill=skill), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(FileNotFoundError):
                    site_hook.skill_contents(temporary, skill)

    def test_downloads_are_reproducible(self):
        for skill in site_hook.SKILL_FILES:
            contents = site_hook.skill_contents(ROOT, skill)
            self.assertEqual(site_hook.skill_archive(contents, skill), site_hook.skill_archive(contents, skill))

    def test_external_sources_are_rejected(self):
        for skill in site_hook.SKILL_FILES:
            with self.subTest(skill=skill), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory = root / "skills" / skill
                directory.mkdir(parents=True)
                external = root / "private.txt"
                external.write_text("PRIVATE_TEST_SENTINEL")
                try:
                    (directory / "SKILL.md").symlink_to(external)
                except OSError:
                    self.skipTest("Symlink creation unavailable")
                with self.assertRaises(ValueError):
                    site_hook.skill_contents(root, skill)


if __name__ == "__main__":
    unittest.main()
