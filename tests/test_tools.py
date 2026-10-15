"""Portable tools and ABI fixture tests; no compiler required."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.crypto import generate_keys, load_keys, opaque, seal, open_sealed, decode
from anti_rea.generate import generate
from anti_rea.ir import transform
from anti_rea.launcher import split_compile, windows_words, expand_response, validate_obfuscation

spec = importlib.util.spec_from_file_location("audit", ROOT / "skills/cpp-leakage-audit/scripts/audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.keys = load_keys(ROOT / "demo-keys/keys.json")

    def test_public_roundtrip(self):
        encrypted = seal(self.keys["public"], "Secret tensor warning")
        self.assertNotIn("Secret tensor", encrypted)
        self.assertEqual(open_sealed(self.keys["private"], encrypted), "Secret tensor warning")

    def test_tamper(self):
        value = seal(self.keys["public"], "message")
        with self.assertRaises(Exception):
            open_sealed(self.keys["private"], "AAAA" + value[4:])

    def test_generation_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            generate_keys(path)
            self.assertNotEqual(load_keys(path)["public"], self.keys["public"])
            with self.assertRaises(ValueError):
                generate_keys(path)
            with self.assertRaises(Exception):
                open_sealed(load_keys(path)["private"], seal(self.keys["public"], "secret"))

    def test_domains(self):
        self.assertNotEqual(opaque(self.keys["master"], "file", "x"), opaque(self.keys["master"], "rtti", "x"))

    def test_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            generate(ROOT, directory, ROOT / "demo-keys/keys.json", True)
            header = (Path(directory) / "generated/diagnostic_catalog.hpp").read_text()
            self.assertNotIn("Invalid mesh topology", header)
            compiler_keys = json.loads((Path(directory) / "private/compiler-keys.json").read_text())
            self.assertNotIn("private", compiler_keys)
            mapping = json.loads((Path(directory) / "private/diagnostics.json").read_text())
            self.assertEqual(len(mapping["sites"]), 5)

    def test_recover_event_and_key_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            generate(ROOT, directory, ROOT / "demo-keys/keys.json", True)
            mapping = json.loads((Path(directory) / "private/diagnostics.json").read_text())
            identity, row = next((identity, row) for identity, row in mapping["sites"].items() if row["site"] == "iteration")
            from anti_rea.crypto import key_id
            body = json.dumps(dict(schema=1, id=identity, template=seal(self.keys["public"], row["message"]), fields=["37"]))
            token = "AR1:" + key_id(self.keys["public"]) + ":" + seal(self.keys["public"], body)
            recovered = decode(token, self.keys, directory)
            self.assertEqual(recovered["message"], "Internal spectral preconditioner stalled after 37 iterations")
            path = Path(directory) / "rotated.json"
            generate_keys(path)
            with self.assertRaises(ValueError):
                decode(token, load_keys(path), directory)
            generate(ROOT, directory, path, True)
            with self.assertRaises(ValueError):
                decode(token, self.keys, directory)


class LauncherTests(unittest.TestCase):
    def test_linux(self):
        source, output, flags = split_compile(["-O2", "-c", "some file.cpp", "-o", "unit.o"], False)
        self.assertEqual((source, output, flags), ("some file.cpp", "unit.o", ["-O2"]))

    def test_jom(self):
        self.assertEqual(split_compile(["--", "-TP", "/c", "unit.cpp", "/Founit.obj", "/MD", "/O2"], True),
                         ("unit.cpp", "unit.obj", ["/MD", "/O2"]))

    def test_windows_response(self):
        self.assertEqual(windows_words(r'/I"C:\Program Files\sdk" "unit file.cpp" /Fo"out file.obj"'),
                         [r'/IC:\Program Files\sdk', 'unit file.cpp', '/Foout file.obj'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "args.rsp"
            path.write_text('"unit file.cpp" /Founit.obj', encoding="utf-16")
            self.assertEqual(expand_response(["@" + str(path)], True), ["unit file.cpp", "/Founit.obj"])

    def test_reject_lto(self):
        with self.assertRaises(ValueError):
            split_compile(["-flto", "-c", "unit.cpp", "-o", "unit.o"], False)

    def test_reject_multiple(self):
        with self.assertRaises(ValueError):
            split_compile(["a.cpp", "b.cpp", "-o", "unit.o"], False)

    def test_applied_pass_contract(self):
        report = dict(schema="llvm_obfuscator.obf_map", functions=[
            dict(name="_Z15policy_dispatchj", passes=[dict(id="flattening", status="ran", changed=True)]),
            dict(name="_Z12policy_tokenj", passes=[dict(id="mba", status="ran", changed=True),
                                                  dict(id="flattening", status="skipped", skip_reason="too few blocks")])])
        self.assertEqual(len(validate_obfuscation(report, "HEAVY")), 2)
        with self.assertRaises(ValueError):
            validate_obfuscation(report, "MIXED_VM")


class RttiTests(unittest.TestCase):
    def test_itanium_fixture(self):
        raw = "N5aegis8internal1XE"
        ir = '@_ZTS' + raw + ' = linkonce_odr constant [' + str(len(raw) + 1) + ' x i8] c"' + raw + '\\00", align 1\n'
        output, rows = transform(ir, "00" * 32, None, decode=lambda raw: "aegis::internal::X")
        self.assertIn("65R", output)
        self.assertTrue(rows[0]["protected"])

    def test_msvc_fixture(self):
        raw = ".?AVX@internal@aegis@@"
        ir = '@"??_R0?AVX@internal@aegis@@@8" = linkonce_odr global { ptr, ptr, [' + str(len(raw)+1) + ' x i8] } { ptr @"??_7type_info@@6B@", ptr null, [' + str(len(raw)+1) + ' x i8] c"' + raw + '\\00" }, comdat\n'
        output, rows = transform(ir, "00" * 32, None, msvc=True, decode=lambda raw: "class aegis::internal::X")
        self.assertIn(".?AVR_", output)
        self.assertNotIn('c"' + raw, output)
        self.assertEqual(rows[0]["abi"], "msvc")

    def test_quoted_lambda(self):
        raw = "Z10print_rttivE3$_0"
        ir = '@"_ZTS' + raw + '" = internal constant [' + str(len(raw) + 1) + ' x i8] c"' + raw + '\\00", align 1\n'
        output, rows = transform(ir, "00" * 32, None, decode=lambda raw: "print_rtti()::$_0")
        self.assertNotIn('c"' + raw, output)
        self.assertTrue(rows[0]["protected"])

    def test_unknown_layout_fails(self):
        with self.assertRaises(ValueError):
            transform('@_ZTS1X = constant i8 0\n', "00" * 32, None)

    def test_external_type_preserved(self):
        ir = '@_ZTS1X = constant [3 x i8] c"1X\\00"\n'
        output, rows = transform(ir, "00" * 32, None, decode=lambda raw: "ExternalType")
        self.assertEqual(ir, output)
        self.assertFalse(rows[0]["protected"])


class AuditTests(unittest.TestCase):
    def test_url_is_not_a_drive(self):
        self.assertFalse(audit.path_matches("clang (https://github.com/llvm/llvm-project)"))
        self.assertTrue(audit.path_matches(r"C:\private\solver.cpp"))

    def test_strings_and_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(b"\0/root/build/solver.cpp\0hidden_solver\0" + "C:\\private\\mesh.cpp".encode("utf-16le"))
            rows, unchecked = audit.scan_binary(path, functions=["hidden_solver"])
            self.assertTrue(any(row["category"] == "path" and row["encoding"] == "UTF-16LE" for row in rows))
            self.assertTrue(any(row["category"] == "specified-function" for row in rows))
            self.assertTrue(unchecked)
            rows, _ = audit.scan_binary(path)
            self.assertFalse(any(row["category"] == "specified-function" for row in rows))

    def test_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.cpp"
            path.write_text('auto p = __FILE__;\nthrow std::runtime_error("secret");\n')
            categories = {row["category"] for row in audit.scan_source(path)}
            self.assertIn("source-location", categories)
            self.assertIn("diagnostic", categories)

    def test_removed_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(b"\0E-opaque\0")
            rows, _ = audit.scan_binary(path, deny=["secret tensor"])
            self.assertFalse(any(row["category"] == "denied-text" for row in rows))


if __name__ == "__main__":
    unittest.main()
