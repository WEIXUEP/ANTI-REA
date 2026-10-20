"""Native triage contracts; mocked REA is not real-provider verification."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/cpp-leakage-audit/scripts"
spec = importlib.util.spec_from_file_location("rea_audit", SCRIPTS / "rea_audit.py")
rea = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rea)


class ReaAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "app.exe"
        self.binary.write_bytes(b"MZ" + bytes(64))
        self.baseline_path = self.root / "original.json"
        self.baseline = dict(schema=2, scanner_sha256=rea.sha256((SCRIPTS / "audit.py").read_bytes()),
                             artifacts=[dict(artifact="binary/0/app.exe", size=66,
                                             sha256=rea.sha256(self.binary.read_bytes()))],
                             scan=dict(package_count=0), findings=[], not_checked=["Synthetic malformed PE fixture"])
        self.save()

    def save(self):
        self.baseline_path.write_text(json.dumps(self.baseline), encoding="utf-8")

    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, "-I", str(SCRIPTS / "rea_audit.py"),
                               "--baseline", str(self.baseline_path), "--binary", str(self.binary),
                               *map(str, arguments)], capture_output=True, text=True, timeout=30)

    def test_plan_uses_only_structured_imports_and_preserves_leak_allow_rules(self):
        def row(symbol, category="import-symbol", status="confirmed", artifact="binary/0/app.exe"):
            return dict(artifact=artifact, evidence=symbol, category=category, status=status)
        self.baseline["findings"] = [row("strcpy"), row("__imp__memcpy@12"),
                                     row("system@@GLIBC_2.2.5"), row("_popen"),
                                     row("LoadLibraryW", "delay-import-symbol", "allowed"),
                                     row("strcpy", "readable-string"), row("system", "export-symbol"),
                                     row("safe_strcpy"), row("?strcpy@safe@@"), row("strcpy_s"),
                                     row("gets", artifact="binary/1/other.dll")]
        self.save()
        output = self.root / "plan"
        result = self.run_cli("--out", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(len(report["candidates"]), 5)
        self.assertTrue(all(row["status"] == "candidate" for row in report["candidates"]))
        self.assertEqual(report["baseline_not_checked"], self.baseline["not_checked"])
        self.assertEqual(report["binding"]["baseline_sha256"], rea.sha256(self.baseline_path.read_bytes()))
        self.assertEqual(report["status"], "planned")
        self.assertNotIn("rea", report)

    def test_changed_artifact_and_stale_scanner_are_rejected_before_query(self):
        output = self.root / "bad"
        self.binary.write_bytes(b"MZchanged")
        result = self.run_cli("--action", "function", "--selector", "entry", "--out", output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("SHA-256", result.stderr)
        self.assertFalse(output.exists())
        self.binary.write_bytes(b"MZ" + bytes(64))
        self.baseline["scanner_sha256"] = "old"
        self.save()
        self.assertEqual(self.run_cli("--out", output).returncode, 2)
        self.assertFalse(output.exists())

    def test_duplicate_content_requires_explicit_artifact(self):
        self.baseline["artifacts"].append(dict(self.baseline["artifacts"][0], artifact="binary/1/app.exe"))
        self.save()
        self.assertEqual(self.run_cli("--out", self.root / "ambiguous").returncode, 2)
        result = self.run_cli("--artifact", "binary/1/app.exe", "--out", self.root / "selected")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_package_layout_and_reports_outside_release_are_enforced(self):
        package = self.root / "release"
        package.mkdir()
        self.binary = package / "app.exe"
        self.binary.write_bytes(b"MZ" + bytes(64))
        self.baseline["artifacts"][0]["artifact"] = "package/app.exe"
        self.baseline["scan"]["package_count"] = 1
        self.save()
        self.assertEqual(self.run_cli("--out", self.root / "missing-root").returncode, 2)
        self.assertEqual(self.run_cli("--package-root", package, "--out", package / "reports").returncode, 2)
        self.assertEqual(self.run_cli("--package-root", self.root, "--out", self.root / "wrong-root").returncode, 2)
        result = self.run_cli("--package-root", package, "--out", self.root / "private-report")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(package.iterdir()), [self.binary])

    def test_existing_evidence_and_original_inputs_are_never_overwritten(self):
        original = self.baseline_path.read_bytes()
        result = self.run_cli("--out", self.root)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.baseline_path.read_bytes(), original)
        self.assertFalse((self.root / "report.json").exists())

    def test_cli_selection_is_literal_and_static_only(self):
        selector = '--help; $(whoami) " quoted'
        command = rea.query_arguments("function", self.binary, selector, "ghidra")
        self.assertIn("--procedure=" + selector, command)
        self.assertEqual(command[-3:], ["--format", "json", "--full-output"])
        command = rea.query_arguments("search-procedures", self.binary, selector, "ghidra")
        self.assertIn("--pattern=" + selector, command)
        self.assertIn("--mode=literal", command)
        for action in ("values", "call-targets"):
            with self.assertRaises(ValueError):
                rea.query_arguments(action, self.binary, selector, "ghidra")
            self.assertIn("0x140001000", rea.query_arguments(action, self.binary, "0x140001000", "ghidra"))
        for action in ("setup", "observe-native-calls", "annotate-native-function"):
            self.assertEqual(self.run_cli("--action", action, "--out", self.root / action).returncode, 2)

    def test_unavailable_backend_is_incomplete_with_retained_report(self):
        output = self.root / "missing"
        result = self.run_cli("--action", "function", "--selector", "entry",
                              "--rea-root", self.root / "no-rea", "--out", output)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("REA missing", report["error"])

    def test_backend_envelopes_and_raw_evidence_are_preserved(self):
        backend = self.root / "backend"
        (backend / "scripts").mkdir(parents=True)
        (backend / "scripts/rea.mjs").write_text("// fixture, never executed")
        (backend / "package.json").write_text('{"version":"fixture"}')
        (backend / ".git").write_text("gitdir: fixture")
        binding = dict(sha256=rea.sha256(self.binary.read_bytes()))
        evidence = dict(evidence_id="ev_fixture", subject=dict(digest=binding), operation="analyze_function",
                        provider=dict(id="ghidra"), limitations=["unresolved alias"])
        good = json.dumps(dict(ok=True, data=evidence)).encode()
        wrong_identity = json.dumps(dict(ok=True, data=dict(evidence, subject=dict(digest=dict(sha256="other"))))).encode()
        wrong_operation = json.dumps(dict(ok=True, data=dict(evidence, operation="observe_native_calls"))).encode()
        wrong_provider = json.dumps(dict(ok=True, data=dict(evidence, provider=dict(id="other")))).encode()
        for index, (code, stdout, expected) in enumerate((
                (0, good, "completed"),
                (0, wrong_identity, "incomplete"),
                (0, wrong_operation, "incomplete"),
                (0, wrong_provider, "incomplete"),
                (0, b'{"ok":false,"error":{"code":"unavailable"}}', "incomplete"),
                (1, b'{"ok":true,"data":{}}', "incomplete"),
                (0, b'{"ok":true}', "incomplete"),
                (0, b'not JSON\xff', "incomplete"))):
            output = self.root / str(index)
            output.mkdir()
            stderr = b"retained provider diagnostic\xff"
            replies = [subprocess.CompletedProcess([], 0, b"abc123\n", b""),
                       subprocess.CompletedProcess([], code, stdout, stderr)]
            with patch.object(rea.shutil, "which", return_value="node.exe"), \
                    patch.object(rea.subprocess, "run", side_effect=replies) as run:
                report = rea.run_query(backend, "node", ["function", str(self.binary)], output,
                                       binding, "function", "ghidra")
            self.assertEqual(report["status"], expected)
            self.assertEqual((output / "rea.stdout.txt").read_bytes(), stdout)
            self.assertEqual((output / "rea.stderr.txt").read_bytes(), stderr)
            self.assertEqual(report["stdout_sha256"], hashlib.sha256(stdout).hexdigest())
            self.assertNotIn("shell", run.call_args.kwargs)
            self.assertEqual(run.call_args.args[0][:2], ["node.exe", str(backend / "scripts/rea.mjs")])
            if index == 0:
                self.assertEqual(report["envelope"]["data"]["limitations"], ["unresolved alias"])

    def test_target_changed_during_query_is_not_completed(self):
        def replace_target(*args):
            self.binary.write_bytes(b"MZnew version")
            return dict(status="completed", error=None, envelope=dict(ok=True, data={}))
        output = self.root / "changed-during-query"
        with patch.object(rea, "run_query", side_effect=replace_target):
            code = rea.main(["--baseline", str(self.baseline_path), "--binary", str(self.binary),
                             "--action", "function", "--selector", "entry", "--out", str(output)])
        self.assertEqual(code, 2)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("changed during analysis", report["error"])

    def test_composed_trace_validates_child_provenance_not_parent_engine(self):
        binding = dict(sha256="fixture digest")
        result = dict(target_sha256=binding["sha256"],
                      procedures=[dict(provider="ghidra", evidence_id="ev_child")])
        evidence = dict(evidence_id="ev_parent", subject=dict(digest=binding),
                        operation="trace_native_values", provider=dict(id="rea-workflow"),
                        normalized_result=result)
        self.assertTrue(rea.evidence_matches(evidence, binding, "values", "ghidra"))
        self.assertFalse(rea.evidence_matches(evidence, binding, "values", "ida"))
        result["target_sha256"] = "other artifact"
        self.assertFalse(rea.evidence_matches(evidence, binding, "values", "ghidra"))
        result["target_sha256"] = binding["sha256"]
        result["procedures"] = []
        self.assertFalse(rea.evidence_matches(evidence, binding, "values", "ghidra"))

    def test_invalid_baseline_and_non_native_artifact_are_rejected(self):
        for report in ([], dict(schema=1), dict(self.baseline, findings="bad")):
            self.baseline_path.write_text(json.dumps(report))
            result = self.run_cli("--out", self.root / "invalid")
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Traceback", result.stderr)
        self.binary.write_bytes(b"ordinary asset")
        self.baseline["artifacts"][0].update(size=self.binary.stat().st_size,
                                              sha256=rea.sha256(self.binary.read_bytes()))
        self.save()
        self.assertEqual(self.run_cli("--out", self.root / "asset").returncode, 2)
        self.binary.write_bytes(b"MZ" + bytes(64))
        self.baseline["artifacts"][0].update(size=66, sha256=rea.sha256(self.binary.read_bytes()), artifact="")
        self.save()
        result = self.run_cli("--out", self.root / "invalid-label")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_removed_target_retains_query_evidence_and_incomplete_report(self):
        def remove_target(*args):
            self.binary.unlink()
            return dict(status="completed", error=None, envelope=dict(ok=True, data="retained fixture"))
        output = self.root / "removed-during-query"
        with patch.object(rea, "run_query", side_effect=remove_target):
            code = rea.main(["--baseline", str(self.baseline_path), "--binary", str(self.binary),
                             "--action", "function", "--selector", "entry", "--out", str(output)])
        self.assertEqual(code, 2)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["rea"]["envelope"]["data"], "retained fixture")
        self.assertIn("unavailable after analysis", report["error"])


if __name__ == "__main__":
    unittest.main()
