"""Static Python/package leakage inspection; target code is never executed."""
import argparse
import ast
import dis
import hashlib
from html import escape
import importlib.util
import io
import json
import marshal
import os
from pathlib import Path
import re
import subprocess
import sys
import types

VERSION = "python-audit-1"
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FINDINGS = 10000


def code_inventory(path):
    data = Path(path).read_bytes()
    if len(data) > 4 * 1024 * 1024 or data[:4] != importlib.util.MAGIC_NUMBER:
        raise ValueError("unsupported or oversized pyc (use its matching Python interpreter)")
    root = marshal.loads(data[16:])
    if not isinstance(root, types.CodeType):
        raise ValueError("pyc root is not code")
    result, pending = [], [(root, 0)]
    while pending:
        code, depth = pending.pop()
        if len(result) >= 1024 or depth > 64:
            raise ValueError("code inventory budget exceeded")
        stream = io.StringIO()
        dis.dis(code, file=stream, depth=0)
        result.append(dict(name=code.co_qualname, filename=code.co_filename,
                           line=code.co_firstlineno, names=list(code.co_names),
                           strings=[v[:512] for v in code.co_consts if isinstance(v, str)],
                           disassembly=stream.getvalue()[:32768]))
        pending.extend((v, depth + 1) for v in code.co_consts if isinstance(v, types.CodeType))
    return result


def files_under(root):
    if root.is_symlink() or (hasattr(root, "is_junction") and root.is_junction()):
        raise ValueError("linked input rejected")
    total, files = 0, []
    def walk():
        if root.is_file():
            yield root
            return
        for directory, directories, names in os.walk(root, followlinks=False):
            for name in directories:
                path = Path(directory) / name
                if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                    raise ValueError("linked package directory rejected")
            for name in sorted(names):
                yield Path(directory) / name
    for path in walk():
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("linked package member rejected")
        if not path.is_file():
            continue
        total += path.stat().st_size
        if len(files) >= 4096 or total > MAX_TOTAL or path.stat().st_size > MAX_FILE:
            raise ValueError("input scan budget exceeded")
        files.append(path)
    if not files:
        raise ValueError("empty input")
    return files


def scan(root, corpus):
    report = dict(schema=1, scanner=VERSION, root=str(root), corpus=corpus,
                  scanner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  artifacts=[], findings=[], gaps=[], code=[], limits=[
                      "Exact corpus hits do not establish algorithm use or complete protection.",
                      "Archives require a separate bounded extraction pass; encrypted members remain opaque.",
                      "pyc inspection uses matching interpreter metadata, not source decompilation."])
    base = root if root.is_dir() else root.parent
    for path in files_under(root):
        relative = path.relative_to(base).as_posix()
        data = path.read_bytes()
        report["artifacts"].append(dict(file=relative, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        for match in re.finditer(rb"(?:[A-Za-z]:[\\/]|/(?:home|Users|tmp|private)/)[ -~]{3,240}", data):
            report["findings"].append(dict(file=relative, category="path-candidate",
                value=match.group().decode("ascii"), offset=match.start(),
                context=data[max(0, match.start()-24):match.start()+72].hex()))
            if len(report["findings"]) > MAX_FINDINGS:
                raise ValueError("path inventory budget exceeded")
        if data.startswith(b"MZ"):
            report["gaps"].append(relative + ": native metadata and machine-code semantics require a separate native analysis pass")
        if data.startswith((b"PK\x03\x04", b"PYZ\0")):
            report["gaps"].append(relative + ": archive members require explicit bounded extraction and rescanning")
        for value in corpus:
            for encoding in ("utf-8", "utf-16le"):
                needle, offset = value.encode(encoding), 0
                while (offset := data.find(needle, offset)) >= 0:
                    report["findings"].append(dict(file=relative, category="corpus", value=value,
                        encoding=encoding, offset=offset,
                        context=data[max(0, offset - 24):offset + len(needle) + 24].hex()))
                    offset += len(needle)
                    if len(report["findings"]) >= MAX_FINDINGS:
                        raise ValueError("finding budget exceeded")
        if path.suffix == ".py":
            try:
                if len(data) > 4 * 1024 * 1024:
                    raise ValueError("source metadata parse exceeds 4 MiB budget")
                tree = ast.parse(data, filename=relative)
                lines = data.decode("utf-8").splitlines()
                for node in ast.walk(tree):
                    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                        report["findings"].append(dict(file=relative, category="source-name", value=node.name,
                            line=node.lineno, context='\n'.join(lines[node.lineno-1:node.lineno+5])[:1024]))
                        if len(report["findings"]) > MAX_FINDINGS:
                            raise ValueError("source metadata inventory budget exceeded")
            except (SyntaxError, UnicodeError, RecursionError, ValueError) as error:
                report["gaps"].append(relative + ": " + str(error))
        if path.suffix == ".pyc":
            command = [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--code-worker", str(path)]
            try:
                run = subprocess.run(command, capture_output=True, timeout=10)
                if run.returncode or len(run.stdout) > 16 * 1024 * 1024:
                    raise ValueError(run.stderr.decode("utf-8", "replace")[-512:])
                for code in json.loads(run.stdout):
                    report["code"].append(dict(file=relative, **code))
                    report["findings"].append(dict(file=relative, category="code-object", value=code["name"],
                        line=code["line"], context=code["filename"] + "\n" + code["disassembly"]))
            except (subprocess.TimeoutExpired, ValueError) as error:
                report["gaps"].append(relative + ": " + str(error))
        if len(report["findings"]) > MAX_FINDINGS or len(report["code"]) > 4096:
            raise ValueError("metadata inventory budget exceeded")
    return report


def render(report):
    e = lambda value: escape(str(value), quote=True)
    rows = []
    for i, row in enumerate(report["findings"]):
        location = "0x%x" % row["offset"] if "offset" in row else "line " + str(row.get("line", "?"))
        rows.append('<details class="finding" data-file="' + e(row["file"]) + '"><summary><span>' +
                    e(row["file"]) + '</span><b>' + e(row["value"]) + '</b><span>' + e(location) +
                    '</span><small>' + e(row["category"]) + '</small></summary><pre>' + e(row.get("context", "")) + '</pre></details>')
    options = ''.join('<option>' + e(a["file"]) + '</option>' for a in report["artifacts"])
    inventory = ''.join('<tr><td>' + e(a["file"]) + '</td><td>' + str(a["bytes"]) +
                        '</td><td class="hash">' + e(a["sha256"]) + '</td></tr>' for a in report["artifacts"])
    return '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Python 泄露诊断</title><style>
*{box-sizing:border-box}body{margin:0;color:#253037;background:#fff;font:14px/1.5 'Segoe UI','Microsoft YaHei',sans-serif;letter-spacing:0}
header{padding:18px 24px;border-bottom:1px solid #cad3d6}h1{font-size:23px;margin:0}header p{margin:6px 0;overflow-wrap:anywhere;color:#53646c}
main{padding:18px 24px;max-width:1500px;margin:auto}nav{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}input,select{font:inherit;border:1px solid #8b999f;padding:7px;max-width:100%;border-radius:4px}input{flex:1;min-width:170px}select{width:340px}
summary{display:grid;grid-template-columns:minmax(180px,2fr) minmax(150px,2fr) 90px 100px;gap:12px;padding:12px;border-bottom:1px solid #d8dfe1;cursor:pointer}summary:hover{background:#eef7f6}summary>*{overflow-wrap:anywhere;min-width:0}summary b{color:#9f3034;font-weight:600}small{color:#5a6870}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;padding:16px;background:#f2f5f6;font:13px/1.6 Consolas,monospace}h2{font-size:17px;margin:24px 0 10px}.gap{color:#9f3034}table{border-collapse:collapse;width:100%;table-layout:fixed}td{padding:8px;border-bottom:1px solid #d8dfe1;overflow-wrap:anywhere}.hash{font:12px Consolas,monospace}input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #197a76;outline-offset:2px}[hidden]{display:none!important}@media(max-width:700px){header,main{padding:14px}summary{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}select{width:100%}}
</style><header><h1>Python 泄露诊断</h1><p>''' + e(report["root"]) + '</p><p>' + str(len(report["findings"])) + ' 项记录 / ' + str(len(report["artifacts"])) + ''' 个文件</p></header><main>
<nav><select id="file" aria-label="文件"><option value="">全部文件</option>''' + options + '''</select><input id="search" type="search" aria-label="搜索" placeholder="搜索内容、文件或位置"></nav>
<section>''' + ''.join(rows) + '</section><h2>未完成检查</h2><pre class="gap">' + e('\n'.join(report["gaps"]) or '无已记录缺项；不代表完整恢复或无泄露。') + '</pre><h2>Baseline 对比</h2><pre>' + e(json.dumps(report.get("comparison", {}), ensure_ascii=False, indent=2)) + '</pre><h2>范围与限制</h2><pre>' + e('\n'.join(report["limits"])) + '</pre><h2>文件身份</h2><table><tbody>' + inventory + '''</tbody></table></main><script>
const file=document.querySelector('#file'),search=document.querySelector('#search');
function filter(){for(const row of document.querySelectorAll('.finding'))row.hidden=(file.value&&row.dataset.file!==file.value)||!row.textContent.toLowerCase().includes(search.value.toLowerCase());}
file.addEventListener('change',filter);search.addEventListener('input',filter);
</script></html>'''


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--code-worker":
        print(json.dumps(code_inventory(sys.argv[2])))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--deny", action="append", default=[])
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="New private report prefix outside target")
    parser.add_argument("--fail-on-deny", action="store_true")
    args = parser.parse_args()
    try:
        if args.package.is_symlink() or (hasattr(args.package, "is_junction") and args.package.is_junction()):
            raise ValueError("linked package root rejected")
        root, output = args.package.resolve(), args.out.resolve()
        if not root.exists() or (root.is_dir() and output.is_relative_to(root)):
            raise ValueError("report must be outside an existing target")
        if not all(0 < len(s) <= 512 for s in args.deny):
            raise ValueError("corpus entries must be 1..512 characters")
        destinations = [output.with_suffix(suffix) for suffix in (".json", ".html")]
        if any(p.exists() or p == root for p in destinations):
            raise ValueError("report destinations must be new and distinct from inputs")
        report = scan(root, args.deny)
        if args.baseline:
            previous = json.loads(args.baseline.read_text(encoding="utf-8"))
            if (previous["scanner"] != VERSION or previous.get("scanner_sha256") != report["scanner_sha256"]
                    or previous["corpus"] != args.deny):
                raise ValueError("baseline scanner/corpus mismatch; rescan retained originals")
            old = {r["value"] for r in previous["findings"] if r["category"] == "corpus"}
            new = {r["value"] for r in report["findings"] if r["category"] == "corpus"}
            report["comparison"] = dict(baseline=str(args.baseline.resolve()), resolved=sorted(old-new),
                                        persistent=sorted(old & new), new=sorted(new-old),
                                        note="Corpus-level comparison; profile inventories may differ.")
        output.parent.mkdir(parents=True, exist_ok=True)
        with destinations[0].open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
        with destinations[1].open("x", encoding="utf-8") as stream:
            stream.write(render(report))
        print(json.dumps(dict(findings=len(report["findings"]), gaps=len(report["gaps"]), report=str(destinations[1]))))
        if report["gaps"]:
            raise SystemExit(2)
        if args.fail_on_deny and any(r["category"] == "corpus" for r in report["findings"]):
            raise SystemExit(1)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
