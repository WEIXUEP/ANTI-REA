"""Three-release entry point and delta report tests without compiling C++."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.measurement import PROFILES, differences, executable, main, render_differences, toolchain


def fixture():
    return dict(schema=1, configurations=[
        dict(preset=name, status="Passed", bytes=size, build_seconds=1.0,
             startup={"process_wall_seconds": {"median": 0.002}},
             bench={"inner_seconds": {"median": 0.003}}, denied_matches=hits)
        for name, size, hits in (("baseline", 100, 10), ("stripped", 50, 4), ("protected", 60, 0))
    ])


class MeasurementTests(unittest.TestCase):
    def test_comparison_controls_override_protected_defaults(self):
        presets = {row["name"]: row for row in json.loads((ROOT / "CMakePresets.json").read_text())["configurePresets"]}
        for name, protected, stripped in (("baseline", False, False), ("stripped", False, True), ("protected", True, True)):
            settings = presets[name]["cacheVariables"]
            self.assertEqual(settings["ANTI_REA_CODE_PROTECTION"], protected)
            self.assertEqual(settings["ANTI_REA_STRIP_RELEASE"], stripped)
        self.assertEqual(presets["common"]["cacheVariables"]["ANTI_REA_OBFUSCATION"], "NONE")

    def test_delta_direction_and_units(self):
        result = differences(fixture())
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["comparisons"]), 3)
        size = result["comparisons"][0]["metrics"][0]
        self.assertEqual((size["delta"], size["percent"]), (-50, -50))
        self.assertEqual(result["comparisons"][0]["metrics"][2]["reference"], 2)
        self.assertEqual(result["comparisons"][2]["metrics"][0]["percent"], 20)

    def test_zero_reference(self):
        report = fixture()
        report["configurations"][0]["denied_matches"] = 0
        result = differences(report)
        self.assertIsNone(result["comparisons"][0]["metrics"][-1]["percent"])
        self.assertIn("N/A (zero reference)", render_differences(result))

    def test_incomplete_has_no_deltas(self):
        for status in ("Failed", "Not run"):
            report = fixture()
            report["configurations"][2]["status"] = status
            result = differences(report)
            self.assertFalse(result["complete"])
            self.assertEqual(result["comparisons"], [])
        report["configurations"].pop()
        self.assertEqual(differences(report)["statuses"]["protected"], "Missing")

    def test_reject_schema_and_duplicates(self):
        with self.assertRaises(ValueError):
            differences({"schema": 20})
        report = fixture()
        report["configurations"].append(report["configurations"][0])
        with self.assertRaises(ValueError):
            differences(report)

    def test_driver_symlink_not_resolved(self):
        with patch("anti_rea.measurement.shutil.which", return_value="/toolchain/bin/clang++"):
            self.assertEqual(str(executable("clang++")), "/toolchain/bin/clang++")

    def test_explicit_toolchain_checked(self):
        with patch("anti_rea.measurement.executable", side_effect=[Path("/bin/clang++"), Path("/bin/opt")]), \
                patch("anti_rea.measurement.doctor") as check:
            self.assertEqual(toolchain(ROOT, "clang++", "opt"), (Path("/bin/clang++"), Path("/bin/opt")))
            check.assert_called_once_with(Path("/bin/clang++"), Path("/bin/opt"))

    def test_auto_detect_local_toolchain(self):
        with patch("anti_rea.measurement.shutil.which", side_effect=lambda name: str(name)), \
                patch("anti_rea.measurement.doctor"):
            compiler, optimizer = toolchain(ROOT)
            self.assertEqual(compiler, ROOT / "build/toolchains/xollvm23/bin/clang++")
            self.assertEqual(optimizer, compiler.parent / "opt")

    def test_default_three_profile_command(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "result"

            def build(argv):
                self.assertEqual(argv[argv.index("--presets") + 1:argv.index("--jobs")], list(PROFILES))
                self.assertEqual(argv[argv.index("--jobs") + 1], "8")
                self.assertEqual(argv[argv.index("--samples") + 1], "9")
                prefix.with_suffix(".json").write_text(json.dumps(fixture()))
                return 0

            with patch("anti_rea.measurement.toolchain", return_value=(Path("/clang++"), Path("/opt"))), \
                    patch("anti_rea.measurement.compare", side_effect=build), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--out", str(prefix)]), 0)
            self.assertTrue(prefix.with_name("result-differences.md").is_file())

    def test_report_only_no_build(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            source.write_text(json.dumps(fixture()))
            with patch("anti_rea.measurement.compare") as build, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--report-only", str(source), "--out", str(Path(directory) / "review")]), 0)
                build.assert_not_called()

    def test_bad_report_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bad.json"
            source.write_text("{}")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--report-only", str(source)]), 1)


if __name__ == "__main__":
    unittest.main()
