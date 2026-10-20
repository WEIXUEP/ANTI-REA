"""Offline HTML evidence presentation must preserve provenance and inert text."""

import hashlib
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/cpp-leakage-audit/scripts/report_html.py"
spec = importlib.util.spec_from_file_location("report_html", SCRIPT)
report_html = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report_html)


class Document(HTMLParser):
    def __init__(self, data):
        super().__init__()
        self.ids, self.links, self.scripts, self.resources = [], [], [], []
        self.feed(data)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "a":
            self.links.append(attrs.get("href", ""))
        if tag == "script":
            self.scripts.append(attrs)
        if any(key in attrs for key in ("src", "srcset")) or tag == "link":
            self.resources.append((tag, attrs))


def analysis():
    return dict(schema=1, kind="analysis", title="Windows recovery", status="partial",
                summary="Known-corpus evidence; VM semantics unresolved",
                artifacts=[dict(artifact="engine.dll", size=1234, sha256="a" * 64)],
                findings=[dict(category="constant", status="candidate", artifact="engine.dll",
                               offset=4096, rva="0x2000", function="policy", evidence="XOR pair")],
                not_checked=["REA backend unavailable"], limitations=["Known corpus only"])


class HtmlReportTests(unittest.TestCase):
    def test_escaping_stable_navigation_and_no_external_resources(self):
        report = analysis()
        malicious = '</script><script>alert(1)</script><img src="https://example.org/leak" onerror="alert(2)">'
        report["findings"][0]["evidence"] = malicious
        report["findings"][0]["artifact"] = 'javascript:alert(3)" onclick="alert(4)'
        page = report_html.render([("evidence.json", report)])
        doc = Document(page)
        self.assertEqual(len(doc.scripts), 1)
        self.assertEqual(doc.resources, [])
        self.assertTrue(all(link.startswith("#") and link[1:] in doc.ids for link in doc.links))
        self.assertEqual(len(doc.ids), len(set(doc.ids)))
        self.assertIn("&lt;/script&gt;", page)
        self.assertIn("4096 / 0x1000", page)
        self.assertIn("REA backend unavailable", page)
        self.assertIn("a" * 64, page)
        self.assertIn("Content-Security-Policy", page)
        self.assertEqual(doc.ids, Document(report_html.render([("other-name.json", report)])).ids)

    def test_all_supported_reports_keep_incomplete_evidence(self):
        documents = [
            ("scan.json", dict(schema=2, findings=[], artifacts=[], not_checked=["Metadata missing"], comparison={"resolved": []})),
            ("rea.json", dict(schema=1, binding=dict(artifact="app.exe", sha256="b" * 64),
                              candidates=[dict(symbol="strcpy", cwe_hypothesis="CWE-120", status="candidate")],
                              status="incomplete", error="Provider failed", baseline_not_checked=[],
                              rea=dict(envelope=dict(data=dict(normalized_result="partial_pseudocode", evidence_id="e-12"))))),
            ("pairs.json", dict(schema=1, mechanism="adjacent-u32le-xor-known-corpus-v1",
                                binary="app.exe", sha256="c" * 64, complete=False,
                                findings=[dict(offset=12, constant="u32le:42", left="1", right="43")]))]
        page = report_html.render(documents, lang="en")
        for item in ("Metadata missing", "Provider failed", "Pair scan coverage incomplete", "12 / 0xc", "CWE-120", "Baseline comparison", "partial_pseudocode", "unverified"):
            self.assertIn(item, page)
        with self.assertRaises(ValueError):
            report_html.render([("unknown.json", {"schema": 300})])

    def test_cli_isolated_preserves_inputs_and_rejects_existing_or_package_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "report.json"
            source.write_text(json.dumps(analysis()), encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            out = root / "readable.html"
            command = [sys.executable, "-I", "-S", str(SCRIPT), "--input", str(source)]
            def run(*args):
                return subprocess.run([*command, *args], capture_output=True, text=True, cwd=root, timeout=30)
            good = run("--out", out)
            self.assertEqual(good.returncode, 0, good.stderr)
            page = out.read_bytes()
            self.assertEqual(json.loads(good.stdout)["inputs"][0]["sha256"], digest)
            self.assertEqual(run("--out", out).returncode, 2)
            self.assertEqual(out.read_bytes(), page)
            self.assertEqual(run("--out", source).returncode, 2)
            self.assertEqual(run("--out", root / "release/report.html", "--package-root", root / "release").returncode, 2)
            self.assertFalse((root / "release").exists())
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
            source.write_text('{"schema": 999}', encoding="utf-8")
            self.assertEqual(run("--out", root / "invalid.html").returncode, 2)
            self.assertFalse((root / "invalid.html").exists())


if __name__ == "__main__":
    unittest.main()
