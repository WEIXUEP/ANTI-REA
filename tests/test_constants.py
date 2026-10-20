"""Constant generation and integration boundaries; compiled behavior is tested natively."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.constants import generate_constants
from anti_rea.generate import generate


class ConstantTests(unittest.TestCase):
    def test_generation_rotation_and_off(self):
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            keys = ROOT / "demo-keys/keys.json"
            generate(ROOT, build, keys, True)
            header = build / "generated/policy_constants.hpp"
            mapping = build / "private/constants.json"
            first = header.read_bytes()
            rows = json.loads(mapping.read_text())["constants"]
            expected = [0xa341316c, 0xc8013ea4, 0xad90777d, 0x7e95761e, 0x5a827999]
            self.assertEqual([row["original"] for row in rows], expected)
            for row in rows:
                self.assertEqual(row["encoded"] ^ row["mask"], row["original"])
                self.assertNotIn(f"0x{row['original']:08x}".encode(), first)
            generate(ROOT, build, keys, True)
            self.assertEqual(first, header.read_bytes())
            header.unlink()
            generate(ROOT, build, keys, True)
            self.assertEqual(first, header.read_bytes())
            generate_constants(ROOT / "examples/policy-constants.json", header.parent,
                               build / "private", "01" * 32, True)
            rotated = json.loads(mapping.read_text())["constants"]
            self.assertTrue(all(a["mask"] != b["mask"] for a, b in zip(rows, rotated)))
            for protected, constants in ((True, False), (False, True)):
                generate(ROOT, build, keys, protected, constants)
                self.assertFalse(json.loads(mapping.read_text())["protected"])
                self.assertNotIn(b"volatile", header.read_bytes())
                for value in expected:
                    self.assertIn(f"0x{value:08x}".encode(), header.read_bytes())

    def test_invalid_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            catalog = folder / "catalog.json"
            for values in ({}, {"bad-name": 1}, {"valid": -1}, {"valid": 2**32},
                           {"valid": True}, {"valid": 1.25}):
                with self.subTest(values=values):
                    catalog.write_text(json.dumps(dict(schema=1, values=values)))
                    with self.assertRaises(ValueError):
                        generate_constants(catalog, folder, folder, "00" * 32, True)
            self.assertFalse((folder / "policy_constants.hpp").exists())


if __name__ == "__main__":
    unittest.main()
