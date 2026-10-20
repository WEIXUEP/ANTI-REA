"""Dedicated leak inspection: locations, context, classification and packaging."""

from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/cpp-leakage-audit/scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("ui_test_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit, inspector, renderer = load("audit"), load("leakage_html"), load("report_html")


class Records(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.rows, self.articles, self.resources, self.scripts = [], [], [], 0
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "tr" and attrs.get("class") == "leak-row":
            self.rows.append(attrs)
        if tag == "article":
            self.articles.append(attrs)
        if "src" in attrs or tag == "link":
            self.resources.append(attrs)
        if tag == "script":
            self.scripts += 1


class LeakageUiTests(unittest.TestCase):
    def test_binary_context_binds_exact_offset_and_is_bounded(self):
        data = bytes(200) + b"Private diagnostic" + bytes(200)
        rows, _ = audit.scan_binary(Path("fixture.bin"), deny=["Private diagnostic"], data=data)
        row = next(row for row in rows if row["category"] == "denied-text" and row["encoding"] == "UTF-8")
        context = row["context"]
        self.assertEqual(row["offset"], 200)
        self.assertEqual(context["start"], 184)
        self.assertEqual(bytes.fromhex(context["hex"])[16:34], b"Private diagnostic")
        self.assertEqual(context["match_size"], 18)
        long = b"x" * 200
        row = next(r for r in audit.scan_binary(Path("long.bin"), deny=[long.decode()], data=long)[0] if r["category"] == "denied-text")
        self.assertLessEqual(len(bytes.fromhex(row["context"]["hex"])), 64)
        self.assertEqual(row["context"]["match_size"], 200)

    def test_source_context_has_correct_lines_and_highlights_as_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.cpp"
            path.write_text('int x;\nint y;\nprintf("<script>secret</script>");\nint z;\nint w;\nint k;\n')
            row = next(r for r in audit.scan_source(path) if r["category"] == "diagnostic")
            self.assertEqual(row["line"], 3)
            self.assertEqual([r["line"] for r in row["context"]["lines"]], [1, 2, 3, 4, 5])
            html = inspector.context_html(row, inspector.WORDS["en"])
            self.assertIn('class="match-line"', html)
            self.assertIn('&lt;script&gt;secret&lt;/script&gt;', html)
            self.assertNotIn('<script>', html)

    def test_leaks_are_distinct_from_metadata_and_rows_select_detail_records(self):
        rows = [dict(artifact="app.exe", category="import-symbol", status="confirmed", evidence="strcpy"),
                dict(artifact="app.exe", category="path", status="candidate", evidence="C:/private/file.cpp", offset=0),
                dict(artifact="app.exe", category="denied-text", status="confirmed", evidence='</script><img src="https://example.org" onerror="x()">', offset=15),
                dict(artifact="app.exe", category="export-symbol", status="confirmed", evidence="public_api"),
                dict(artifact="app.exe", category="denied-text", status="allowed", evidence="permitted")]
        report = dict(schema=2, findings=rows, artifacts=[dict(artifact="app.exe", sha256="a" * 64, size=100)], not_checked=[])
        page = renderer.render([("scan.json", report)], lang="en")
        parsed = Records(page)
        self.assertEqual([row["data-status"] for row in parsed.rows], ["confirmed", "candidate", "candidate", "allowed", "inventory"])
        self.assertEqual({r["data-target"] for r in parsed.rows}, {a["id"] for a in parsed.articles})
        self.assertEqual(parsed.scripts, 1)
        self.assertEqual(parsed.resources, [])
        self.assertIn('15 / 0xf', page)
        self.assertIn('a' * 64, page)
        self.assertNotIn('<img src=', page)
        self.assertIn('No context was captured', page)
        old = Records(renderer.render([("renamed.json", report)], lang="en"))
        self.assertEqual([a["id"] for a in parsed.articles], [a["id"] for a in old.articles])
        self.assertIn('class="findings"', renderer.render([("scan.json", report)], lang="en", view="analysis"))
        with self.assertRaises(ValueError):
            renderer.render([("pair.json", dict(schema=1))], view="leakage")


if __name__ == "__main__":
    unittest.main()
