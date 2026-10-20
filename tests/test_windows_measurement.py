"""Keep Windows cost measurements bound to accepted release bytes and timings."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("measure_windows", ROOT / "tools/measure_windows.py")
measurement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measurement)


class AcceptanceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.acceptance = self.root / "result.json"
        self.report = dict(status="passed", platform="win32", configurations={}, commands=[])
        for label in ("release-baseline", "release-protected"):
            binary = self.root / "packages" / label / "bin/app.exe"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"synthetic accepted artifact")
            self.report["configurations"][label] = dict(status="passed", artifacts={
                "app.exe": dict(sha256=measurement.digest(binary))})
            self.report["commands"].append(dict(argv=["cmake", "--build", str(self.root / label)],
                                                 exit_code=0, wall_seconds=2.0))
        self.save()

    def save(self):
        self.acceptance.write_text(json.dumps(self.report), encoding="utf-8")

    def test_changed_release_is_rejected(self):
        measurement.prepare(self.acceptance, self.root / "new-report")
        (self.root / "packages/release-protected/bin/app.exe").write_bytes(b"changed artifact")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            measurement.prepare(self.acceptance, self.root / "new-report")

    def test_failed_acceptance_and_missing_timings_are_rejected(self):
        self.report["status"] = "failed"
        self.save()
        with self.assertRaisesRegex(ValueError, "completed native"):
            measurement.prepare(self.acceptance, self.root / "new-report")
        self.report["status"] = "passed"
        del self.report["commands"][0]["wall_seconds"]
        self.save()
        with self.assertRaisesRegex(ValueError, "clean-build timing"):
            measurement.prepare(self.acceptance, self.root / "new-report")

    def test_report_cannot_enter_accepted_package(self):
        with self.assertRaisesRegex(ValueError, "outside release"):
            measurement.prepare(self.acceptance, self.root / "packages/release-protected/report")

    def test_vm_profile_keeps_original_control_unobfuscated(self):
        self.report["obfuscation"] = "MIXED_VM"
        self.report["configurations"]["release-protected"]["obfuscation"] = "MIXED_VM"
        self.save()
        _, profiles = measurement.prepare(self.acceptance, self.root / "new-report")
        self.assertEqual(profiles["baseline"]["obfuscation"], "NONE")
        self.assertEqual(profiles["protected"]["obfuscation"], "MIXED_VM")

    def test_explicit_cost_budgets_and_relative_speed(self):
        profiles = {}
        for name, multiplier in (("baseline", 1), ("protected", 2)):
            workloads = {mode: {field: dict(median=multiplier)} for mode, field in (
                ("startup", "process_wall_seconds"), ("bench", "inner_seconds"), ("warning", "process_wall_seconds"))}
            profiles[name] = dict(core_bytes=10 * multiplier, package_bytes=20 * multiplier,
                                  build_seconds=multiplier, workloads=workloads)
        differences, checks = measurement.compare_cost(profiles, dict(bench=2, package_bytes=1.5))
        self.assertEqual(differences["bench"]["relative_speed_percent"], 50)
        self.assertEqual([row["status"] for row in checks], ["passed", "failed"])
        profiles["baseline"]["workloads"]["bench"]["inner_seconds"]["median"] = 0
        _, checks = measurement.compare_cost(profiles, dict(bench=2))
        self.assertEqual(checks[0]["status"], "incomplete")
        profiles["baseline"]["workloads"]["bench"]["inner_seconds"]["median"] = 1
        profiles["protected"]["workloads"]["bench"]["inner_seconds"]["median"] = 0
        _, checks = measurement.compare_cost(profiles, dict(bench=2))
        self.assertEqual(checks[0]["status"], "incomplete")
        self.assertEqual(measurement.compare_cost(profiles, {})[1], [])


if __name__ == "__main__":
    unittest.main()
