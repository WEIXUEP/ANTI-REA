#!/usr/bin/env python3
"""Render private, self-contained HTML from audit, REA, pair and analysis JSON."""

import argparse
import base64
import hashlib
from html import escape
import json
from pathlib import Path
import sys


LABELS = {
    "en": {
        "title": "Analysis evidence", "private": "Private analysis", "reports": "Reports",
        "findings": "Findings", "gaps": "Coverage gaps", "artifacts": "Artifacts", "artifact_records": "Artifact records",
        "evidence": "Evidence", "location": "Location", "category": "Category",
        "status": "Status", "all": "All", "search": "Search evidence, files, addresses",
        "empty": "No findings match the current filters.", "none": "No findings recorded.",
        "raw": "Complete source record", "limits": "Limitations", "comparison": "Baseline comparison",
        "source": "Source report", "fingerprints": "Artifact fingerprints", "bytes": "Bytes",
        "summary": "Summary", "offset": "File offset", "line": "Line", "unknown": "Not supplied",
        "scope": "Scan / request scope", "result": "Result", "unreviewed": "No overall verdict supplied",
        "notice": "Private evidence. Counts and no-match results are not a security verdict.",
        "nojs": "Filtering needs JavaScript. All evidence remains readable below.",
    },
    "zh-CN": {
        "title": "分析证据报告", "private": "内部分析", "reports": "报告",
        "findings": "发现", "gaps": "覆盖缺口", "artifacts": "产物", "artifact_records": "产物记录",
        "evidence": "证据", "location": "位置", "category": "类别",
        "status": "状态", "all": "全部", "search": "搜索证据、文件、地址",
        "empty": "没有符合当前筛选条件的发现。", "none": "未记录发现。",
        "raw": "完整原始记录", "limits": "限制", "comparison": "Baseline 对比",
        "source": "来源报告", "fingerprints": "产物指纹", "bytes": "字节数",
        "summary": "摘要", "offset": "文件偏移", "line": "行", "unknown": "未提供",
        "scope": "扫描 / 请求范围", "result": "结果", "unreviewed": "未提供整体判定",
        "notice": "内部证据。数量和零命中结果不代表安全性结论。",
        "nojs": "筛选需要 JavaScript；下方证据仍可完整阅读。",
    },
}

STYLE = """
:root{color-scheme:light;--ink:#20262d;--muted:#56616d;--paper:#fff;--ground:#f2f4f6;
--line:#cdd4dc;--accent:#006d77;--warning:#925600;--danger:#a02c42}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:var(--ground);
font:14px/1.55 'Segoe UI','Microsoft YaHei',sans-serif;letter-spacing:0}
a{color:var(--accent);text-underline-offset:3px}a:focus-visible,input:focus-visible,
select:focus-visible,summary:focus-visible{outline:3px solid #2391ab;outline-offset:3px}
header{background:var(--paper);border-bottom:1px solid var(--line);padding:22px 30px 16px}
header p{margin:4px 0;color:var(--muted)}h1{font-size:26px;line-height:1.25;margin:4px 0 10px}
h2{font-size:20px;line-height:1.35;margin:0 0 10px}h3{font-size:15px;margin:22px 0 8px}
.layout{display:grid;grid-template-columns:220px minmax(0,1fr);max-width:1600px;margin:auto}
aside{padding:24px 18px;position:sticky;top:0;align-self:start;max-height:100vh;overflow:auto}
aside a{display:block;padding:8px 0;overflow-wrap:anywhere}aside strong{display:block;margin:0 0 6px}
main{min-width:0;padding:24px 30px;background:var(--paper);border-left:1px solid var(--line)}
.counts{display:flex;flex-wrap:wrap;gap:12px 32px;border-bottom:1px solid var(--line);padding:0 0 18px;margin-bottom:20px}
.counts span{color:var(--muted)}.counts b{color:var(--ink);font-size:22px;margin-right:6px}
.toolbar{display:grid;grid-template-columns:minmax(200px,1fr) minmax(140px,200px) minmax(130px,180px);gap:12px}
label{display:grid;gap:5px;color:var(--muted)}input,select{width:100%;min-width:0;border:1px solid #9ea9b5;
border-radius:4px;padding:9px;background:#fff;color:var(--ink);font:inherit}
.result-count{display:block;margin:10px 0;color:var(--muted)}section{padding:24px 0;border-top:2px solid var(--line);scroll-margin-top:12px}
.provenance{color:var(--muted);margin:0 0 14px;overflow-wrap:anywhere}.warning{color:var(--warning);border-left:3px solid #c38a25;padding:8px 12px;background:#fff8e8}
.verdict{font-weight:600}ul{padding-left:22px}li{overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;table-layout:fixed;margin:12px 0}th{text-align:left;background:#edf1f4;color:#394653;font-weight:600}
td,th{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.findings th:nth-child(1){width:8%}.findings th:nth-child(2){width:17%}.findings th:nth-child(3){width:13%}.findings th:nth-child(4){width:23%}
code,pre{font-family:Consolas,'Cascadia Mono',monospace;font-size:12px;letter-spacing:0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:8px 0;max-height:36rem;overflow:auto;background:#f5f7f8;padding:12px;border:1px solid #e0e5e9;border-radius:4px}
details{margin:8px 0}summary{cursor:pointer;color:var(--accent)}.position{display:block;margin-top:5px}
.finding:target{background:#e8f6f6;outline:2px solid var(--accent);outline-offset:-2px}.finding{scroll-margin-top:12px}
.empty{color:var(--muted);padding:12px 0}.record-list{margin-top:16px}[hidden]{display:none!important}
@media(max-width:800px){header{padding:18px 16px}.layout{display:block}aside{position:static;max-height:none;padding:12px 16px;border-bottom:1px solid var(--line)}
aside a{display:inline-block;margin-right:18px}main{padding:18px 16px;border-left:0}.toolbar{grid-template-columns:1fr 1fr}.toolbar label:first-child{grid-column:1/-1}
.findings,.findings tbody,.findings tr,.findings td{display:block}.findings thead{display:none}.findings tr{border-bottom:2px solid var(--line);padding:8px 0}
.findings td{border:0;padding:4px 8px}.findings td:before{content:attr(data-label);display:block;color:var(--muted);font-size:12px}.findings td:first-child:before{display:none}
.fingerprints th:nth-child(2),.fingerprints td:nth-child(2){width:18%}}
@media print{aside,.toolbar,.result-count{display:none}.layout{display:block}main{border:0;padding:0}header{padding-left:0}pre{max-height:none;overflow:visible}section{break-before:auto}a{color:inherit}}
"""

SCRIPT = """
const rows = [...document.querySelectorAll('.finding')];
const search = document.querySelector('#search');
const category = document.querySelector('#category');
const statusFilter = document.querySelector('#status');
function applyFilters(){
  const term = search.value.toLocaleLowerCase(); let count = 0;
  for(const row of rows){
    row.hidden = !(row.textContent.toLocaleLowerCase().includes(term)
      && (!category.value || row.dataset.category === category.value)
      && (!statusFilter.value || row.dataset.status === statusFilter.value));
    if(!row.hidden) count++;
  }
  document.querySelector('#visible-count').textContent = count + ' / ' + rows.length;
  document.querySelector('#empty-filter').hidden = count !== 0;
}
function revealHash(){
  const target = document.getElementById(location.hash.slice(1));
  if(target && target.classList.contains('finding')){
    search.value = ''; category.value = ''; statusFilter.value = ''; applyFilters();
    for(const detail of target.querySelectorAll('details')) detail.open = true;
    target.scrollIntoView({block:'start'});
  }
}
for(const control of [search,category,statusFilter]) control.addEventListener('input',applyFilters);
addEventListener('hashchange',revealHash);
applyFilters(); revealHash();
"""


def text(value):
    return escape(str(value), quote=True)


def pretty(value):
    return '<pre>' + text(json.dumps(value, ensure_ascii=False, indent=2)) + '</pre>'


def detail(label, value):
    return '<details><summary>' + text(label) + '</summary>' + pretty(value) + '</details>'


def normalize(report):
    if not isinstance(report, dict):
        raise ValueError("Report must be a JSON object")
    if report.get("schema") == 2 and all(isinstance(report.get(k), list) for k in ("findings", "artifacts", "not_checked")):
        return "Leakage audit", report["findings"], report["artifacts"], report["not_checked"]
    if report.get("schema") == 1 and isinstance(report.get("binding"), dict) and isinstance(report.get("candidates"), list):
        baseline_gaps = report.get("baseline_not_checked", [])
        request = report.get("request", {})
        if not isinstance(baseline_gaps, list) or not isinstance(request, dict):
            raise ValueError("REA baseline gaps must be an array and request an object")
        gaps = list(baseline_gaps)
        if report.get("status") != "completed":
            gaps.append(report.get("error") or "REA investigation is planned, not completed")
        rows = list(report["candidates"])
        rea = report.get("rea", {})
        envelope = rea.get("envelope") if isinstance(rea, dict) else None
        data = envelope.get("data") if isinstance(envelope, dict) else None
        if data is not None:
            rows.append(dict(category="rea-evidence", status="derived" if report.get("status") == "completed" else "unverified",
                             artifact=report["binding"].get("artifact", ""),
                             function=request.get("selector"), evidence=data))
        return "REA risk triage", rows, [report["binding"]], gaps
    if report.get("schema") == 1 and report.get("mechanism") == "adjacent-u32le-xor-known-corpus-v1":
        if not isinstance(report.get("findings"), list):
            raise ValueError("Pair report requires findings")
        rows = [dict(row, artifact=report.get("binary", ""), category="xor-pair", status="candidate") for row in report["findings"]]
        gaps = [] if report.get("complete") is True else ["Pair scan coverage incomplete"]
        return "Numeric pair probe", rows, [dict(artifact=report.get("binary", ""), sha256=report.get("sha256", ""), size=report.get("size_bytes", ""))], gaps
    if report.get("schema") == 1 and report.get("kind") == "analysis":
        if not all(isinstance(report.get(k), list) for k in ("findings", "artifacts", "limitations", "not_checked")):
            raise ValueError("Analysis report requires findings, artifacts, limitations and not_checked arrays")
        return report.get("title", "Analysis"), report["findings"], report["artifacts"], report["not_checked"]
    raise ValueError("Unsupported report schema; use audit, REA triage, pair probe or kind=analysis")


def location(row, labels):
    evidence = row.get("evidence")
    artifact = row.get("artifact", evidence.get("artifact", "") if isinstance(evidence, dict) else "")
    pieces = [text(artifact)] if artifact else []
    for key, label in (("line", labels["line"]), ("offset", labels["offset"]), ("rva", "RVA"), ("va", "VA"), ("address", "Address")):
        value = row.get(key)
        if value is not None:
            formatted = f"{value} / 0x{value:x}" if type(value) is int and key != "line" else str(value)
            pieces.append('<code class="position">' + text(label + ": " + formatted) + '</code>')
    if row.get("function"):
        pieces.append('<code class="position">' + text(row["function"]) + '</code>')
    return ''.join(pieces) or text(labels["unknown"])


def render(documents, title=None, lang="zh-CN"):
    """Documents are (source label, JSON object) pairs; report values are inert text."""
    labels = LABELS[lang]
    title = title or labels["title"]
    sections, navigation, categories, statuses = [], [], set(), set()
    total_findings = total_gaps = total_artifacts = 0
    seen = set()
    for source, report in documents:
        name, rows, artifacts, gaps = normalize(report)
        if any(not isinstance(row, dict) for row in [*rows, *artifacts]):
            raise ValueError("Findings and artifacts must contain JSON objects")
        limits = report.get("limitations", [report["limitation"]] if report.get("limitation") else [])
        if not isinstance(gaps, list) or not isinstance(limits, list):
            raise ValueError("Coverage gaps and limitations must be arrays")
        canonical = json.dumps(report, sort_keys=True, ensure_ascii=False).encode()
        identity = "r-" + hashlib.sha256(canonical).hexdigest()[:16]
        if identity in seen:
            continue
        seen.add(identity)
        total_findings += len(rows)
        total_gaps += len(gaps)
        total_artifacts += len(artifacts)
        navigation.append('<a href="#' + identity + '">' + text(name) + '</a>')
        parts = ['<section id="' + identity + '"><h2>' + text(name) + '</h2>']
        parts.append('<p class="verdict">' + text(labels["result"] + ": " + str(report.get("status", labels["unreviewed"]))) + '</p>')
        if report.get("summary"):
            parts.append('<h3>' + text(labels["summary"]) + '</h3><p>' + text(report["summary"]) + '</p>')
        if gaps:
            parts.append('<div class="warning"><strong>' + text(labels["gaps"]) + '</strong><ul>' + ''.join('<li>' + text(gap) + '</li>' for gap in gaps) + '</ul></div>')
        parts.append('<details><summary>' + text(labels["source"]) + '</summary><p class="provenance">' + text(source) + '<br>Canonical JSON SHA-256: <code>' + hashlib.sha256(canonical).hexdigest() + '</code></p></details>')
        parts.append(detail(labels["scope"], report.get("scan", report.get("request", report.get("corpus", {})))))
        if report.get("comparison") is not None:
            parts.append(detail(labels["comparison"], report["comparison"]))
        parts.append('<h3>' + text(labels["findings"]) + '</h3>')
        if not rows:
            parts.append('<p class="empty">' + text(labels["none"]) + '</p>')
        else:
            parts.append('<table class="findings"><thead><tr>' + ''.join('<th scope="col">' + text(value) + '</th>' for value in ("ID", labels["category"], labels["status"], labels["location"], labels["evidence"])) + '</tr></thead><tbody>')
            for index, row in enumerate(rows, 1):
                category = str(row.get("category", row.get("cwe_hypothesis", "analysis")))
                status = str(row.get("status", "unreviewed"))
                categories.add(category)
                statuses.add(status)
                anchor = identity + "-f-" + str(index)
                evidence = row.get("evidence", row.get("constant", row.get("symbol", "")))
                if not isinstance(evidence, str):
                    evidence = json.dumps(evidence, ensure_ascii=False)
                if row.get("question"):
                    evidence += "\n" + str(row["question"])
                cells = ('<a href="#' + anchor + '">' + str(index) + '</a>', text(category), text(status), location(row, labels),
                         '<pre>' + text(evidence) + '</pre>' + detail(labels["raw"], row))
                parts.append('<tr class="finding" id="' + anchor + '" data-category="' + text(category) + '" data-status="' + text(status) + '">' + ''.join('<td data-label="' + text(label) + '">' + value + '</td>' for label, value in zip(("ID", labels["category"], labels["status"], labels["location"], labels["evidence"]), cells)) + '</tr>')
            parts.append('</tbody></table>')
        if artifacts:
            parts.append('<h3>' + text(labels["fingerprints"]) + '</h3><table class="fingerprints"><thead><tr><th>' + text(labels["artifacts"]) + '</th><th>' + text(labels["bytes"]) + '</th><th>SHA-256</th></tr></thead><tbody>')
            for row in artifacts:
                parts.append('<tr><td>' + text(row.get("artifact", row.get("path", labels["unknown"]))) + '</td><td>' + text(row.get("size", labels["unknown"])) + '</td><td><code>' + text(row.get("sha256", labels["unknown"])) + '</code></td></tr>')
            parts.append('</tbody></table>')
        if limits:
            parts.append('<h3>' + text(labels["limits"]) + '</h3><ul>' + ''.join('<li>' + text(value) + '</li>' for value in limits) + '</ul>')
        parts.append(detail(labels["raw"], report))
        parts.append('</section>')
        sections.append(''.join(parts))
    if not sections:
        raise ValueError("At least one supported report is required")
    def options(values):
        return '<option value="">' + text(labels["all"]) + '</option>' + ''.join('<option value="' + text(value) + '">' + text(value) + '</option>' for value in sorted(values))
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    style_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    policy = "default-src 'none'; script-src 'sha256-" + script_hash + "'; style-src 'sha256-" + style_hash + "'; base-uri 'none'; form-action 'none'"
    counts = ''.join('<span><b>' + str(count) + '</b>' + text(labels[key]) + '</span>' for count, key in ((len(sections), "reports"), (total_findings, "findings"), (total_gaps, "gaps"), (total_artifacts, "artifact_records")))
    return ('<!doctype html><html lang="' + lang + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="' + text(policy) + '"><title>' + text(title) + '</title><style>' + STYLE + '</style></head><body>'
            '<header id="top"><p>' + text(labels["private"]) + '</p><h1>' + text(title) + '</h1><p>' + text(labels["notice"]) + '</p></header>'
            '<div class="layout"><aside aria-label="' + text(labels["reports"]) + '"><strong>' + text(labels["reports"]) + '</strong>' + ''.join(navigation) + '</aside>'
            '<main><div class="counts">' + counts + '</div><div class="toolbar"><label>' + text(labels["search"]) + '<input type="search" id="search"></label>'
            '<label>' + text(labels["category"]) + '<select id="category">' + options(categories) + '</select></label>'
            '<label>' + text(labels["status"]) + '<select id="status">' + options(statuses) + '</select></label></div>'
            '<output id="visible-count" class="result-count" aria-live="polite"></output><p id="empty-filter" class="empty" hidden>' + text(labels["empty"]) + '</p>'
            '<noscript><p class="warning">' + text(labels["nojs"]) + '</p></noscript>' + ''.join(sections) + '</main></div><script>' + SCRIPT + '</script></body></html>')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True, help="New private .html file")
    parser.add_argument("--package-root", type=Path, action="append", default=[], help="Reject output inside each release root")
    parser.add_argument("--title")
    parser.add_argument("--lang", choices=LABELS, default="zh-CN")
    args = parser.parse_args(argv)
    try:
        output = args.out.resolve()
        if output.suffix.lower() != ".html" or args.out.exists() or args.out.is_symlink():
            raise ValueError("Use a new .html output; existing files are never replaced")
        if any(output.is_relative_to(path.resolve()) for path in args.package_root):
            raise ValueError("Keep HTML outside release packages")
        documents, identities = [], []
        for path in args.input:
            with path.open("rb") as stream:
                data = stream.read(32 * 1024 * 1024 + 1)
            if len(data) > 32 * 1024 * 1024:
                raise ValueError("Each input report must be at most 32 MiB")
            report = json.loads(data.decode("utf-8-sig"))
            documents.append((str(path) + " [SHA-256: " + hashlib.sha256(data).hexdigest() + "]", report))
            identities.append(dict(path=str(path), sha256=hashlib.sha256(data).hexdigest()))
            if isinstance(report, dict) and isinstance(report.get("binding"), dict):
                if output == Path(report["binding"].get("path", "")).resolve():
                    raise ValueError("Output must not replace a bound target")
        page = render(documents, args.title, args.lang)
        output.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            stream.write(page)
        print(json.dumps(dict(status="rendered", html=str(output), inputs=identities)))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print("HTML report failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
