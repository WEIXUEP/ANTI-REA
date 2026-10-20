"""Budget decisions, sampling order and artifact binding for standalone workloads."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("workload_measurement", ROOT / "skills/cpp-code-protection/scripts/measure.py")
measurement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measurement)


class WorkloadBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name, size in (("baseline", 10), ("protected", 20)):
            (self.root / name).write_bytes(b"x" * size)
        self.config = dict(schema=1, profiles=[dict(name=name, command=[name], artifacts=[name])
                                              for name in ("baseline", "protected")],
                           comparisons=[dict(reference="baseline", target="protected", max_slowdown=2, max_size_ratio=2)])

    def run_measurement(self, mutate=None):
        calls, times = [], []
        elapsed = 0

        def execute(command, **kwargs):
            nonlocal elapsed
            name = command[0]
            calls.append(name)
            times.extend((elapsed, elapsed + (1 if name == "baseline" else 2)))
            elapsed = times[-1] + 1
            kwargs["stdout"].write(b"42\n")
            if mutate:
                mutate(name)
            return subprocess.CompletedProcess(command, 0)

        def timer():
            if times:
                _, end = times
                times.clear()
                return end
            return elapsed

        with patch.object(measurement.platform, "platform", return_value="test-host"), \
                patch.object(measurement.subprocess, "run", side_effect=execute), \
                patch.object(measurement.time, "perf_counter", side_effect=timer):
            result = measurement.measure(self.config, self.root, samples=3, warmups=1)
        return result, calls

    def test_rotation_relative_speed_and_inclusive_budget(self):
        report, calls = self.run_measurement()
        self.assertEqual(calls, ["baseline", "protected", "protected", "baseline"] * 2)
        self.assertEqual(report["status"], "passed")
        comparison = report["comparisons"][0]
        self.assertEqual(comparison["relative_speed_percent"], 50)
        self.assertEqual(comparison["slowdown"], 2)
        self.assertEqual(comparison["size_ratio"], 2)
        self.assertEqual(report["profiles"][0]["wall_samples_seconds"], [1, 1, 1])
        self.assertEqual(report["profiles"][1]["wall_seconds"]["p95"], 2)

    def test_budget_exceeded_and_missing_size_are_not_passes(self):
        self.config["comparisons"][0]["max_slowdown"] = 1.99
        report, _ = self.run_measurement()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["comparisons"][0]["checks"]["max_slowdown"])
        self.config["profiles"][0]["artifacts"] = []
        report, _ = self.run_measurement()
        self.assertEqual(report["comparisons"][0]["status"], "incomplete")
        self.assertEqual(report["comparisons"][0]["reason"], "size_reference_unavailable")

    def test_changed_artifact_invalidates_budget(self):
        def mutate(name):
            if name == "protected":
                (self.root / name).write_bytes(b"changed")
        report, _ = self.run_measurement(mutate)
        self.assertEqual(report["profiles"][1]["reason"], "artifact_changed")
        self.assertEqual(report["comparisons"][0]["status"], "incomplete")

    def test_warmup_output_failure_is_not_a_measurement_pass(self):
        self.config["profiles"][0]["expected_stdout_sha256"] = "0" * 64
        report, calls = self.run_measurement()
        self.assertEqual(report["profiles"][0]["failed_phase"], "warmup")
        self.assertEqual(calls.count("baseline"), 1)
        self.assertEqual(report["comparisons"][0]["status"], "incomplete")

    def test_all_budgets_validated_before_execution(self):
        invalid = [None, {}, [dict(reference="baseline", target="absent")],
                   [dict(reference="baseline", target="baseline")],
                   [dict(reference="baseline", target="protected", max_slowdon=2)]]
        invalid += [[dict(reference="baseline", target="protected", max_slowdown=value)]
                    for value in (True, 0, -1, float("inf"), float("nan"), "2")]
        for comparisons in invalid:
            with self.subTest(comparisons=comparisons), patch.object(measurement.subprocess, "run") as execute:
                self.config["comparisons"] = comparisons
                with self.assertRaises(ValueError):
                    measurement.measure(self.config, self.root)
                execute.assert_not_called()
