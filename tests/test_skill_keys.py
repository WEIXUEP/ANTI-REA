"""Exercise the portable skill key generator against the example crypto format."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/cpp-code-protection/scripts/generate_keys.py"
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.crypto import key_id, load_keys, open_sealed, seal

spec = importlib.util.spec_from_file_location("skill_keys", SCRIPT)
skill_keys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(skill_keys)


class SkillKeyTests(unittest.TestCase):
    def test_compatible_independent_private_bundles(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name / "keys.json" for name in ("one", "two")]
            summaries = [skill_keys.generate_keys(path) for path in paths]
            first, second = [load_keys(path) for path in paths]
            self.assertNotEqual(first["public"], second["public"])
            self.assertNotEqual(first["master"], second["master"])
            self.assertEqual(summaries[0]["key_id"], key_id(first["public"]))
            token = seal(first["public"], "Synthetic recovery event")
            self.assertEqual(open_sealed(first["private"], token), "Synthetic recovery event")
            with self.assertRaises(Exception):
                open_sealed(second["private"], token)
            if os.name == "posix":
                self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)

    def test_cli_does_not_disclose_secrets_or_replace_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "keys.json"
            command = [sys.executable, str(SCRIPT), "--out", str(path)]
            result = subprocess.run(command, capture_output=True, text=True, cwd=temporary)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = load_keys(path)
            self.assertEqual(set(json.loads(result.stdout)), {"key_id", "path"})
            for field in ("master", "private"):
                self.assertNotIn(value[field], result.stdout + result.stderr)
            before = path.read_bytes()
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_bytes(), before)
            self.assertNotIn("Traceback", result.stderr)

    def test_dangling_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "missing.json"
            link = Path(temporary) / "keys.json"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("Symlink creation unavailable")
            with self.assertRaises(FileExistsError):
                skill_keys.generate_keys(link)
            self.assertFalse(target.exists())

    def test_concurrent_generators_only_one_succeeds(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "keys.json"
            command = [sys.executable, str(SCRIPT), "--out", str(path)]
            processes = [subprocess.Popen(command, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True) for _ in range(2)]
            for process in processes:
                process.communicate(timeout=15)
            self.assertEqual(sorted(process.returncode for process in processes), [0, 2])
            load_keys(path)


if __name__ == "__main__":
    unittest.main()
