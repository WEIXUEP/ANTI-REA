"""Run the distributed skill outside the checkout with synthetic private data."""

from io import BytesIO
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.crypto import load_keys, seal, key_id, opaque

spec = importlib.util.spec_from_file_location("standalone_site_hook", ROOT / "src/anti_rea/site_hook.py")
site_hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site_hook)


class StandaloneSkillTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # Keep the archives in separate environments: neither can import its sibling.
        for skill in site_hook.SKILL_FILES:
            with ZipFile(BytesIO(site_hook.skill_archive(site_hook.skill_contents(ROOT, skill), skill))) as archive:
                archive.extractall(self.root / skill)
        self.audit_scripts = self.root / "cpp-leakage-audit/cpp-leakage-audit/scripts"
        self.scripts = self.root / "cpp-code-protection/cpp-code-protection/scripts"
        self.cwd = self.root / "unrelated-cwd"
        self.cwd.mkdir()
        self.environment = dict(os.environ)
        self.environment.pop("PYTHONPATH", None)

    def run_tool(self, name, *arguments, no_site=False, stdin=None):
        command = [sys.executable]
        if no_site:
            command.append("-S")
        scripts = self.audit_scripts if name in {"audit.py", "rea_audit.py"} else self.scripts
        return subprocess.run([*command, str(scripts / name), *map(str, arguments)],
                              cwd=self.cwd, env=self.environment, input=stdin,
                              capture_output=True, text=True, timeout=30)

    def fixture(self, template="Synthetic solver warning after {} iterations"):
        key_file = self.root / "secret/keys.json"
        result = self.run_tool("generate_keys.py", "--out", key_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        keys = load_keys(key_file)
        build = self.root / "release-build"
        private = build / "private"
        private.mkdir(parents=True)
        site = dict(path="engine/kernel.cpp", line=27, site="iterations", message=template)
        mapping = dict(schema=1, key_id=key_id(keys["public"]),
                       master_id=opaque(keys["master"], "master-id", "v1"), sites={"E-synthetic": site})
        (private / "diagnostics.json").write_text(json.dumps(mapping), encoding="utf-8")
        body = json.dumps(dict(schema=1, id="E-synthetic", template=seal(keys["public"], template), fields=["37"]))
        token = "AR1:" + key_id(keys["public"]) + ":" + seal(keys["public"], body)
        return key_file, build, keys, token, mapping

    def test_entrypoint_help_and_inventory_without_site_packages(self):
        for name in ("audit.py", "rea_audit.py", "generate_keys.py", "decode.py", "doctor.py", "measure.py"):
            with self.subTest(name=name):
                result = self.run_tool(name, "--help", no_site=True)
                self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_tool("doctor.py", no_site=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["checks"]["crypto"]["status"], "missing")
        result = self.run_tool("doctor.py", "--require", "crypto", no_site=True)
        self.assertEqual(result.returncode, 1)

    def test_decode_repeated_events_and_private_export(self):
        key_file, build, keys, token, _ = self.fixture()
        result = self.run_tool("decode.py", "--build", build, "--keys", key_file,
                               "--stdin", stdin="Public prefix\nPayload: " + token + "\nPayload: " + token)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual(report["results"][0]["message"], "Synthetic solver warning after 37 iterations")
        self.assertEqual(report["results"][0]["path"], "engine/kernel.cpp")
        self.assertEqual(report["results"][0]["line"], 27)
        for field in ("private", "master"):
            self.assertNotIn(keys[field], result.stdout + result.stderr)
        destination = self.root / "recovered.json"
        args = ("--build", build, "--keys", key_file, "--text", token, "--output", destination)
        self.assertEqual(self.run_tool("decode.py", *args).returncode, 0)
        before = destination.read_bytes()
        self.assertEqual(self.run_tool("decode.py", *args).returncode, 2)
        self.assertEqual(destination.read_bytes(), before)

    def test_decode_partial_tamper_wrong_key_and_empty_input(self):
        key_file, build, _, token, _ = self.fixture()
        damaged = token.rsplit(":", 1)[0] + ":AAAA"
        args = ("--build", build, "--keys", key_file)
        result = self.run_tool("decode.py", *args, "--text", token + "\n" + damaged)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([row["status"] for row in json.loads(result.stdout)["results"]], ["recovered", "failed"])
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        wrong = self.root / "wrong.json"
        self.assertEqual(self.run_tool("generate_keys.py", "--out", wrong).returncode, 0)
        result = self.run_tool("decode.py", "--build", build, "--keys", wrong, "--text", token)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["results"][0]["code"], "payload_key_mismatch")
        self.assertEqual(self.run_tool("decode.py", *args, "--text", "").returncode, 2)
        result = self.run_tool("decode.py", *args, "--text", token.replace("AR1:", "AR2:"))
        self.assertEqual(result.returncode, 1)

    def test_map_inventory_conflicts_and_template_guard(self):
        key_file, build, _, token, mapping = self.fixture("{0.__class__}")
        args = ("--build", build, "--keys", key_file)
        result = self.run_tool("decode.py", *args, "--text", token)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["results"][0]["code"], "unsupported_template_grammar")
        result = self.run_tool("decode.py", "--build", build, "--list-maps", no_site=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["maps"][0]["records"], 1)
        mapping["sites"]["E-synthetic"]["line"] = 28
        conflict = self.root / "conflict.json"
        conflict.write_text(json.dumps(mapping))
        result = self.run_tool("decode.py", *args, "--map", conflict, "--text", token)
        self.assertEqual(result.returncode, 2)
        self.assertIn("conflicting_location_maps", result.stderr)

    def test_rtti_both_abis_without_crypto_or_tk(self):
        rows = [dict(abi="itanium", original="N6secret1XE", decoded="secret::X", opaque="65R" + "a" * 64, protected=True),
                dict(abi="msvc", original=".?AVX@secret@@", decoded="class secret::X", opaque=".?AVR_" + "b" * 64 + "@@", protected=True),
                dict(abi="itanium", original="*N6secret1XE", decoded="secret::X", opaque="*65R" + "c" * 64, protected=True)]
        mapping = self.root / "types.json"
        mapping.write_text(json.dumps(dict(schema=1, rtti=rows)))
        for name in (rows[0]["opaque"], rows[0]["opaque"].removeprefix("65"),
                     rows[1]["opaque"], "class R_" + "b" * 64, "R" + "c" * 64):
            result = self.run_tool("decode.py", "--map", mapping, "--rtti", name, no_site=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("secret::X", json.loads(result.stdout)["results"][0]["decoded"])

    def test_audit_unicode_offsets_packages_and_fail_closed_input(self):
        binary = self.root / "fixture.bin"
        text = "Private\nmessage"
        binary.write_bytes(b"prefix\0" + text.encode("utf-16le") + b"\0\0")
        report = self.root / "audit"
        result = self.run_tool("audit.py", "--binary", binary, "--deny", text,
                               "--all-strings", "--fail-on-deny", "--out", report, no_site=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        findings = json.loads(report.with_suffix(".json").read_text())["findings"]
        self.assertTrue(any(row["category"] == "denied-text" and row["offset"] == 7 for row in findings))
        package = self.root / "stage"
        package.mkdir()
        (package / "private-key.json").write_text("synthetic secret marker")
        result = self.run_tool("audit.py", "--package", package, "--fail-on-private", no_site=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        result = self.run_tool("audit.py", "--package", package, "--require-metadata", no_site=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        (package / "broken.exe").write_bytes(b"MZ" + bytes(64))
        result = self.run_tool("audit.py", "--package", package, "--require-metadata", no_site=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        result = self.run_tool("audit.py", "--source", self.root / "missing", no_site=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    @unittest.skipUnless(os.name == "posix" and shutil.which("c++"), "Native fixture requires a POSIX C++ compiler")
    def test_native_cpp_leak_detection_and_release_strip(self):
        source = self.root / "fixture.cpp"
        source.write_text('#include <cstdio>\nint internal_function(int x) { return x + 1; }\n'
                          'int main() { std::puts("Private solver diagnostic"); return internal_function(0)-1; }\n')
        baseline = self.root / "baseline"
        subprocess.run([shutil.which("c++"), "-g", str(source), "-o", str(baseline)], check=True, capture_output=True)
        result = self.run_tool("audit.py", "--binary", baseline, "--deny", "Private solver diagnostic", "--fail-on-deny")
        self.assertEqual(result.returncode, 1)
        strip = shutil.which("strip")
        if strip:
            stripped = self.root / "stripped"
            shutil.copy2(baseline, stripped)
            subprocess.run([strip, "--strip-all", str(stripped)], check=True, capture_output=True)
            self.assertLess(stripped.stat().st_size, baseline.stat().st_size)
            # Stripping cannot remove the literal the program still prints.
            result = self.run_tool("audit.py", "--binary", stripped, "--deny", "Private solver diagnostic", "--fail-on-deny")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(subprocess.run([str(stripped)], capture_output=True).stdout, b"Private solver diagnostic\n")

    def test_generic_measurement_success_and_output_failure(self):
        artifact = self.root / "artifact.bin"
        artifact.write_bytes(b"Synthetic artifact")
        command = [sys.executable, "-c", "print(42)"]
        config = self.root / "workloads.json"
        profiles = [dict(name=name, command=command, artifacts=[artifact.name]) for name in ("baseline", "stripped", "protected")]
        config.write_text(json.dumps(dict(schema=1, profiles=profiles)))
        out = self.root / "measurements"
        args = ("--config", config, "--samples", "3", "--warmups", "0", "--out", out)
        result = self.run_tool("measure.py", *args, no_site=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.with_suffix(".json").read_text())
        self.assertEqual(len(report["profiles"]), 3)
        self.assertTrue(all(row["wall_seconds"]["samples"] == 3 for row in report["profiles"]))
        self.assertEqual(report["profiles"][0]["stdout_sha256"], [hashlib.sha256(b"42\n").hexdigest()] if os.name != "nt" else [hashlib.sha256(b"42\r\n").hexdigest()])
        profiles[0]["expected_stdout_sha256"] = "0" * 64
        config.write_text(json.dumps(dict(schema=1, profiles=profiles)))
        self.assertEqual(self.run_tool("measure.py", *args, no_site=True).returncode, 1)

    def test_measurement_validates_all_profiles_before_execution(self):
        marker = self.root / "must-not-exist"
        profiles = [dict(name="first", command=[sys.executable, "-c",
                                               "from pathlib import Path; Path(" + repr(str(marker)) + ").touch()"]),
                    dict(name="bad", command="not-an-argv-array")]
        config = self.root / "invalid-workloads.json"
        config.write_text(json.dumps(dict(schema=1, profiles=profiles)))
        result = self.run_tool("measure.py", "--config", config, "--out", self.root / "invalid-result")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
