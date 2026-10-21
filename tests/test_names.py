"""Name identity, ABI encodings and reference-preserving LLVM symbol rewrites."""
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.ir import transform
from anti_rea.names import decoy, load_policy, rename_functions, rtti_aliases


class NamingTests(unittest.TestCase):
    def test_identity_stability_rotation_and_unique_types(self):
        labels = [decoy("00" * 32, "rtti-msvc", str(i), "type") for i in range(256)]
        self.assertEqual(len(set(labels)), 256)
        self.assertEqual(labels[0], decoy("00" * 32, "rtti-msvc", "0", "type"))
        self.assertNotEqual(labels[0], decoy("01" * 32, "rtti-msvc", "0", "type"))
        self.assertNotEqual(labels[0], decoy("00" * 32, "function", "0", "function"))

    def test_class_alias_layout_selection_and_lookup_both_abis(self):
        for msvc, raw, decoded in [(True, ".?AVX@internal@aegis@@", "class aegis::internal::X"),
                                   (False, "N5aegis8internal1XE", "aegis::internal::X")]:
            size = len(raw) + 1
            if msvc:
                ir = f'@"??_R0?AVX@internal@aegis@@@8" = linkonce_odr global {{ ptr, ptr, [{size} x i8] }} {{ ptr @"??_7type_info@@6B@", ptr null, [{size} x i8] c"{raw}\\00" }}, comdat\n'
            else:
                ir = f'@_ZTS{raw} = linkonce_odr constant [{size} x i8] c"{raw}\\00", align 1\n'
            output, rows = transform(ir, "00" * 32, None, msvc, lambda _: decoded, "DECOY")
            alias = rows[0]["opaque"]
            self.assertNotIn('c"' + raw, output)
            self.assertIn(f'[{len(alias)+1} x i8] c"{alias}\\00"', output)
            label = alias[4:-2] if msvc else re.sub(r"^\d+", "", alias)
            self.assertIn(label, rtti_aliases(alias))
            untouched, rows = transform(ir, "00" * 32, None, msvc, lambda _: "third_party::Independent", "DECOY")
            self.assertEqual(untouched, ir)
            self.assertFalse(rows[0]["protected"])

    def test_pointer_identity_marker_preserved(self):
        raw = "*N5aegis8internal1XE"
        ir = f'@_ZTSsample = internal constant [{len(raw)+1} x i8] c"{raw}\\00"\n'
        _, rows = transform(ir, "00" * 32, None, decode=lambda _: "aegis::internal::X", name_style="DECOY")
        self.assertTrue(rows[0]["opaque"].startswith("*"))

    def test_exact_calls_address_tables_and_comdat_are_rewritten(self):
        ir = '''; @_Z3foov stays a comment
$"_Z3foov" = comdat any
@address = global ptr @_Z3foov
@literal = constant [4 x i8] c"foo\\00"
define linkonce_odr hidden i32 @_Z3foov() comdat { ret i32 7 }
define i32 @_Z3foov_suffix() { %r = call i32 @_Z3foov()
ret i32 %r }
'''
        output, rows = rename_functions(ir, "00" * 32, {"_Z3foov": "foo()"})
        alias = rows[0]["replacement"]
        self.assertIn("@address = global ptr @" + alias, output)
        self.assertIn("call i32 @" + alias + "()", output)
        self.assertIn("$" + alias + " = comdat any", output)
        self.assertIn("@_Z3foov_suffix", output)
        self.assertIn('; @_Z3foov stays a comment', output)
        self.assertIn('c"foo\\00"', output)
        self.assertEqual(rename_functions('declare hidden i32 @_Z3foov()\n', "00" * 32, {"_Z3foov": "foo()"})[1][0]["replacement"], alias)

    def test_quoted_msvc_reference_and_public_assembly_collision_rejection(self):
        symbol = "?foo@@YAHXZ"
        output, rows = rename_functions(f'declare i32 @"{symbol}"()\n', "00" * 32, {symbol: "foo()"})
        self.assertIn("@" + rows[0]["replacement"], output)
        for qualifier in ("dllexport", "dllimport", "available_externally"):
            with self.assertRaises(ValueError):
                rename_functions(f'declare {qualifier} i32 @"{symbol}"()\n', "00" * 32, {symbol: "foo()"})
        ir = f'declare i32 @"{symbol}"()\n'
        with self.assertRaises(ValueError):
            rename_functions(ir + f'module asm "{symbol}"\n', "00" * 32, {symbol: "foo()"})
        with self.assertRaises(ValueError):
            rename_functions(ir + f'@{rows[0]["replacement"]} = global i32 0\n', "00" * 32, {symbol: "foo()"})
        with self.assertRaises(ValueError):
            rename_functions('define i32 @_Z3foov() { ret i32 7 }\n', "00" * 32, {"_Z3foov": "foo()"})

    def test_retained_exports_are_explicit_and_definition_only(self):
        ir = 'define dso_local noundef i32 @"?foo@@YAHXZ"() { ret i32 7 }\ndeclare i32 @"?bar@@YAHXZ"()\n'
        policy = {"?foo@@YAHXZ": "foo()", "?bar@@YAHXZ": "bar()"}
        plain, _ = rename_functions(ir, "00" * 32, policy)
        retained, _ = rename_functions(ir, "00" * 32, policy, retain_exports=True)
        self.assertNotIn("dllexport", plain)
        self.assertIn("define dso_local dllexport noundef i32", retained)
        self.assertNotIn("declare dllexport", retained)

    def test_explicit_policy_validation(self):
        self.assertEqual(len(load_policy(ROOT / "examples/name-policy.json", True)), 4)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            for data in ({"schema": 1, "functions": [{"name": "main", "itanium": "main"}]},
                         {"schema": 1, "functions": [{"name": "x", "itanium": "_Z1xv"}] * 2}):
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    load_policy(path, False)


if __name__ == "__main__":
    unittest.main()
