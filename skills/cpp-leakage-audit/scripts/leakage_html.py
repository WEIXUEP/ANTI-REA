"""Dedicated offline leakage-location inspector for schema-2 audit reports."""

import base64
import hashlib
from html import escape
import json
from pathlib import Path


WORDS = {
    "zh-CN": dict(title="C++ 泄露诊断", files="文件", all_files="全部文件", findings="泄露项",
        content="泄露内容", category="类别", status="状态", location="泄露位置", detail="位置详情",
        confirmed="已知敏感项命中", candidate="待审查", allowed="已允许", inventory="元数据清单", path="原始文件路径",
        search="搜索内容、文件或偏移", all="全部", show_inventory="显示普通元数据", empty="没有符合条件的泄露项。",
        select="未选中泄露项", offset="文件偏移", line="源码行", encoding="编码", unknown="未提供",
        context="位置上下文", raw="原始记录", provenance="扫描来源与范围", gaps="未完成检查",
        limits="扫描限制", hash="文件 SHA-256", comparison="Baseline 对比", no_context="此记录未采集上下文。",
        no_location="未提供精确位置", notice="已知敏感项与待审查候选分别列出。", nojs="JavaScript 已关闭；所有位置详情列在下方。"),
    "en": dict(title="C++ Leakage Diagnostics", files="Files", all_files="All files", findings="Leakage items",
        content="Exposed content", category="Category", status="Status", location="Leak location", detail="Location details",
        confirmed="Known sensitive hits", candidate="Needs review", allowed="Allowed", inventory="Metadata inventory", path="Original file path",
        search="Search content, files or offsets", all="All", show_inventory="Show ordinary metadata", empty="No matching leakage items.",
        select="No item selected", offset="File offset", line="Source line", encoding="Encoding", unknown="Not supplied",
        context="Location context", raw="Original record", provenance="Scan provenance and scope", gaps="Incomplete checks",
        limits="Scanner limitations", hash="File SHA-256", comparison="Baseline comparison", no_context="No context was captured for this record.",
        no_location="Exact location not supplied", notice="Known sensitive hits and review candidates are listed separately.",
        nojs="JavaScript is disabled; all location details are listed below."),
}
KNOWN = {"denied-text", "specified-function", "specified-variable", "specified-constant", "private-artifact"}
INVENTORY = {"pe-machine", "readable-string"}


def text(value):
    return escape(str(value), quote=True)


def disposition(row):
    category = str(row.get("category", "unknown"))
    if category in INVENTORY or category.startswith(("import-", "delay-import-")):
        return "inventory"
    if row.get("status") == "allowed":
        return "allowed"
    if row.get("status") == "confirmed" and category in KNOWN:
        return "confirmed"
    return "candidate"


def position(row, words):
    result = []
    if row.get("line") is not None:
        result.append(words["line"] + ": " + str(row["line"]))
    offset = row.get("offset")
    if type(offset) is int:
        result.append(words["offset"] + f": {offset} / 0x{offset:x}")
    for field in ("rva", "va"):
        if row.get(field) is not None:
            result.append(field.upper() + ": " + str(row[field]))
    return "\n".join(result) or words["no_location"]


def context_html(row, words):
    context = row.get("context")
    if not isinstance(context, dict):
        return '<p class="muted">' + text(words["no_context"]) + '</p>'
    if context.get("kind") == "source" and isinstance(context.get("lines"), list):
        lines = []
        for line in context["lines"]:
            if not isinstance(line, dict):
                continue
            active = ' class="match-line"' if line.get("line") == row.get("line") else ''
            lines.append('<span' + active + '><span class="line-number">' + text(line.get("line", "")) + '</span>' + text(line.get("text", "")) + '</span>')
        return '<pre class="source-context">' + ''.join(lines) + '</pre>'
    if context.get("kind") == "bytes":
        try:
            data = bytes.fromhex(context["hex"])
            start, match_start, match_size = context["start"], context["match_start"], context["match_size"]
            if (len(data) > 96 or any(type(value) is not int or value < 0 for value in (start, match_start, match_size))):
                raise ValueError("Invalid bounded byte context")
            lines = []
            for offset in range(0, len(data), 16):
                cells, ascii_cells = [], []
                for index, value in enumerate(data[offset:offset + 16], start + offset):
                    marked = match_start <= index < match_start + match_size
                    begin, end = ('<mark>', '</mark>') if marked else ('', '')
                    cells.append(begin + f"{value:02x}" + end)
                    ascii_cells.append(begin + text(chr(value) if 32 <= value < 127 else '.') + end)
                lines.append(f"{start + offset:08x}  " + ' '.join(cells) + '   ' + ''.join(ascii_cells))
            return '<pre class="hex-context">' + '\n'.join(lines) + '</pre>'
        except (ValueError, TypeError, KeyError):
            return '<p class="muted">' + text(words["no_context"]) + '</p>'
    return '<p class="muted">' + text(words["no_context"]) + '</p>'


STYLE = """
:root{color-scheme:light;--ink:#20282d;--muted:#56646b;--line:#cbd4d8;--accent:#006b70;--bg:#f1f4f5}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 'Segoe UI','Microsoft YaHei',sans-serif;letter-spacing:0;color:var(--ink);background:#fff}
h1{font-size:23px;line-height:1.3;margin:0}h2{font-size:17px;margin:0 0 14px}h3{font-size:14px;margin:22px 0 8px}
a{color:var(--accent);text-underline-offset:3px}a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #1d899d;outline-offset:2px}
header{display:flex;justify-content:space-between;align-items:center;gap:20px;padding:18px 24px;border-bottom:1px solid var(--line)}header p{margin:5px 0 0;color:var(--muted)}
.totals{display:flex;gap:24px;flex-wrap:wrap}.totals span{color:var(--muted)}.totals b{display:block;font-size:22px;color:var(--ink)}
.workspace{display:grid;grid-template-columns:210px minmax(0,1fr);min-height:calc(100vh - 90px)}
.files{background:var(--bg);border-right:1px solid var(--line);padding:20px 12px;min-width:0}.files h2{padding:0 8px}
.file-link{display:flex;gap:12px;justify-content:space-between;align-items:start;padding:10px 8px;text-decoration:none;border-left:3px solid transparent;overflow-wrap:anywhere}
.file-link span{min-width:0}.file-link.active{background:#dcebed;border-left-color:var(--accent)}.file-link small{color:var(--muted);flex-shrink:0}
main{min-width:0}.filters{display:grid;grid-template-columns:minmax(150px,1fr) 180px 160px;gap:12px;padding:18px 20px 10px;border-bottom:1px solid var(--line)}
label{display:grid;gap:5px;color:var(--muted)}input,select{font:inherit;color:var(--ink);background:#fff;border:1px solid #a2b1b8;border-radius:4px;min-width:0;width:100%;padding:8px}
.filter-footer{grid-column:1/-1;display:flex;gap:20px;align-items:center;justify-content:space-between;color:var(--muted)}.inventory-toggle{display:flex;align-items:center;gap:8px}.inventory-toggle input{width:auto}
.inspector{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,42%);align-items:start}.matches{min-width:0;padding:16px 16px 20px 20px}.details-pane{min-width:0;padding:18px 20px;border-left:1px solid var(--line);min-height:65vh;background:#fafcfc;position:sticky;top:0;max-height:100vh;overflow:auto}
table{border-collapse:collapse;width:100%;table-layout:fixed}th{text-align:left;background:#edf2f3;font-weight:600;color:#45565f}td,th{padding:10px 8px;border-bottom:1px solid #dce2e5;vertical-align:top;overflow-wrap:anywhere}
th:nth-child(1){width:22%}th:nth-child(2){width:32%}.leak-row.active{background:#e4f3f3;box-shadow:inset 3px 0 var(--accent)}.leak-row a{display:block;color:inherit;white-space:pre-wrap;text-decoration:none}.leak-row a:hover{text-decoration:underline}
.leak-row .minor{display:block;color:var(--muted);font-size:12px;margin-top:5px}.disposition{font-size:12px;font-weight:600}.disposition.confirmed{color:#a3263e}.disposition.allowed{color:#267048}.disposition.candidate{color:#855600}
.evidence{font:13px/1.65 Consolas,'Cascadia Mono',monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#fff;border:1px solid var(--line);padding:12px;margin:10px 0}
dl{margin:12px 0}dt{color:var(--muted);font-size:12px;margin-top:12px}dd{margin:3px 0;overflow-wrap:anywhere;white-space:pre-wrap}code{font-family:Consolas,'Cascadia Mono',monospace;font-size:12px}
pre{font:12px/1.7 Consolas,'Cascadia Mono',monospace;letter-spacing:0;white-space:pre-wrap;overflow-wrap:anywhere;margin:10px 0;background:#fff;border:1px solid var(--line);padding:10px;max-height:28rem;overflow:auto}
.hex-context{white-space:pre;overflow:auto}.source-context>span{display:block;white-space:pre-wrap}.line-number{display:inline-block;min-width:38px;color:#6f7c83;user-select:none}.match-line{background:#fff0c4}.match-line .line-number{color:#684500}mark{background:#ffdf8c;color:#3e3010}
.muted{color:var(--muted)}details{margin:12px 0}summary{cursor:pointer;color:var(--accent)}.provenance{padding:18px 20px;border-top:1px solid var(--line);overflow-wrap:anywhere}.warning{padding:10px 14px;background:#fff6df;border-left:3px solid #b67a16;margin:0 0 12px}.warning ul{margin:5px 0;padding-left:20px}
.leak-detail{scroll-margin-top:12px;overflow-wrap:anywhere}.js .leak-detail{display:none}.js .leak-detail.active{display:block}.no-selection{color:var(--muted)}[hidden]{display:none!important}
@media(min-width:1550px){.workspace{grid-template-columns:240px minmax(0,1fr)}.inspector{grid-template-columns:minmax(0,1fr) minmax(400px,40%)}}
@media(max-width:1100px){.inspector{display:block}.details-pane{position:static;max-height:none;min-height:0;border-left:0;border-top:1px solid var(--line)}.filters{grid-template-columns:minmax(150px,1fr) 160px 140px}}
@media(max-width:700px){header{display:block;padding:16px}.totals{gap:18px;margin-top:14px}.totals b{font-size:19px}.workspace{display:block}.files{border-right:0;border-bottom:1px solid var(--line);padding:12px}.files h2{margin:0}.file-list{display:flex;flex-wrap:wrap}.file-link{max-width:100%}.filters{padding:14px 16px;grid-template-columns:1fr 1fr}.filters>label:first-child{grid-column:1/-1}.matches,.details-pane{padding:16px}.filter-footer{flex-wrap:wrap;gap:8px}th:nth-child(1){width:25%}th:nth-child(2){width:34%}}
@media print{.files,.filters{display:none}.workspace,.inspector{display:block}.details-pane{position:static;max-height:none}.js .leak-detail{display:block!important}.leak-detail{break-inside:avoid;border-top:1px solid var(--line);padding-top:16px}pre{max-height:none}}
"""

SCRIPT = """
document.body.classList.add('js');
const rows=[...document.querySelectorAll('.leak-row')];
const details=[...document.querySelectorAll('.leak-detail')];
const search=document.querySelector('#leak-search'), category=document.querySelector('#leak-category'), statusFilter=document.querySelector('#leak-status'), inventory=document.querySelector('#show-inventory');
let selectedFile='';
function selectRow(row){
  for(const item of rows)item.classList.toggle('active',item===row);
  for(const detail of details)detail.classList.toggle('active',!!row&&detail.id===row.dataset.target);
  document.querySelector('#no-selection').hidden=!!row;
}
function applyFilters(){
  const term=search.value.toLocaleLowerCase();let visible=[];
  for(const row of rows){
    const match=(!selectedFile||row.dataset.file===selectedFile)&&(!category.value||row.dataset.category===category.value)
      &&(!statusFilter.value||row.dataset.status===statusFilter.value)&&(inventory.checked||row.dataset.status!=='inventory')
      &&row.dataset.search.toLocaleLowerCase().includes(term);
    row.hidden=!match;if(match)visible.push(row);
  }
  document.querySelector('#leak-count').textContent=visible.length+' / '+rows.length;
  document.querySelector('#leak-empty').hidden=visible.length!==0;
  selectRow(visible.find(row=>row.classList.contains('active'))||visible[0]||null);
  for(const link of document.querySelectorAll('.file-link'))link.classList.toggle('active',link.dataset.file===selectedFile);
}
function revealHash(){
  const target=location.hash.slice(1);const row=rows.find(row=>row.dataset.target===target);
  if(!row)return;
  if(row.hidden){selectedFile='';search.value='';category.value='';statusFilter.value='';inventory.checked=row.dataset.status==='inventory';applyFilters();}
  selectRow(row);
  if(innerWidth<=1100)document.getElementById(target).scrollIntoView({block:'start'});
}
for(const link of document.querySelectorAll('.file-link'))link.addEventListener('click',event=>{event.preventDefault();selectedFile=link.dataset.file;applyFilters();});
for(const control of [search,category,statusFilter,inventory])control.addEventListener('input',applyFilters);
for(const link of document.querySelectorAll('.leak-row a'))link.addEventListener('click',()=>{selectRow(link.closest('tr'));});
addEventListener('hashchange',revealHash);applyFilters();revealHash();
"""


def render(documents, title=None, lang="zh-CN"):
    documents = list(documents)
    words = WORDS[lang]
    title = title or words["title"]
    rows, files, sources, gaps, seen = [], {}, [], [], set()
    for source, report in documents:
        if (not isinstance(report, dict) or report.get("schema") != 2
                or not all(isinstance(report.get(key), list) for key in ("findings", "artifacts", "not_checked"))):
            raise ValueError("Leakage interface accepts only schema-2 audit reports")
        identity = hashlib.sha256(json.dumps(report, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
        if identity in seen:
            continue
        seen.add(identity)
        artifacts = {}
        for artifact in report["artifacts"]:
            if not isinstance(artifact, dict):
                raise ValueError("Artifact records must be objects")
            artifacts[artifact.get("artifact")] = artifact
        gaps.extend(report["not_checked"])
        for index, row in enumerate(report["findings"], 1):
            if not isinstance(row, dict):
                raise ValueError("Finding records must be objects")
            artifact = str(row.get("artifact", words["unknown"]))
            file_id = identity + "-" + hashlib.sha256(artifact.encode()).hexdigest()[:12]
            source_label = Path(str(source).split(" [SHA-256:", 1)[0]).name
            display = source_label + " / " + artifact if len(documents) > 1 else artifact
            files.setdefault(file_id, dict(label=display, count=0))["count"] += 1
            rows.append(dict(record=row, anchor="leak-" + identity + "-" + str(index), file_id=file_id,
                             artifact=artifact, fingerprint=artifacts.get(artifact, {}), source=source))
        sources.append(dict(source=source, scanner_sha256=report.get("scanner_sha256"), scan=report.get("scan"),
                            artifacts=report["artifacts"], limitations=report.get("limitations", []), comparison=report.get("comparison")))
    if not sources:
        raise ValueError("At least one leakage audit is required")
    order = {name: index for index, name in enumerate(("confirmed", "candidate", "allowed", "inventory"))}
    rows.sort(key=lambda item: order[disposition(item["record"])])
    counts = {key: 0 for key in ("confirmed", "candidate", "allowed", "inventory")}
    for item in rows:
        counts[disposition(item["record"])]+=1
    nav = ['<a class="file-link active" href="#leak-list" data-file=""><span>' + text(words["all_files"]) + '</span><small>' + str(len(rows)) + '</small></a>']
    for file_id, file in files.items():
        nav.append('<a class="file-link" href="#leak-list" data-file="' + file_id + '"><span>' + text(file["label"]) + '</span><small>' + str(file["count"]) + '</small></a>')
    table, panels, categories = [], [], set()
    for item in rows:
        row, anchor, artifact = item["record"], item["anchor"], item["artifact"]
        category = str(row.get("category", "unknown"))
        categories.add(category)
        state = disposition(row)
        evidence = row.get("evidence", "")
        if not isinstance(evidence, str):
            evidence = json.dumps(evidence, ensure_ascii=False)
        loc = position(row, words)
        searchable = artifact + " " + loc + " " + json.dumps(row, ensure_ascii=False)
        table.append('<tr class="leak-row" data-target="' + anchor + '" data-file="' + item["file_id"] + '" data-category="' + text(category) + '" data-status="' + state + '" data-search="' + text(searchable) + '">'
                     '<td><span class="disposition ' + state + '">' + text(words[state]) + '</span><span class="minor">' + text(category) + '</span></td>'
                     '<td><a href="#' + anchor + '">' + text(artifact) + '<span class="minor">' + text(loc) + '</span></a></td>'
                     '<td><a href="#' + anchor + '">' + text(evidence[:180]) + ('…' if len(evidence)>180 else '') + '</a></td></tr>')
        metadata = [(words["files"], artifact), (words["path"], row.get("path") or item["fingerprint"].get("path", words["unknown"])), (words["location"], loc), (words["encoding"], row.get("encoding") or words["unknown"]),
                    (words["hash"], item["fingerprint"].get("sha256", words["unknown"])), (words["provenance"], item["source"])]
        panels.append('<article class="leak-detail" id="' + anchor + '"><h2>' + text(words["detail"]) + '</h2><span class="disposition ' + state + '">' + text(words[state]) + '</span>'
                      '<pre class="evidence">' + text(evidence) + '</pre><dl>' + ''.join('<dt>' + text(key) + '</dt><dd><code>' + text(value) + '</code></dd>' for key,value in metadata) + '</dl>'
                      '<h3>' + text(words["context"]) + '</h3>' + context_html(row, words) + '<p><a href="#' + anchor + '">#' + anchor + '</a></p>'
                      '<details><summary>' + text(words["raw"]) + '</summary><pre>' + text(json.dumps(row, ensure_ascii=False, indent=2)) + '</pre></details></article>')
    options = '<option value="">' + text(words["all"]) + '</option>'
    category_options = options + ''.join('<option>' + text(category) + '</option>' for category in sorted(categories))
    status_options = options + ''.join('<option value="' + key + '">' + text(words[key]) + '</option>' for key in counts)
    warning = ('<div class="warning"><strong>' + text(words["gaps"]) + '</strong><ul>' + ''.join('<li>' + text(gap) + '</li>' for gap in gaps) + '</ul></div>') if gaps else ''
    def digest(value):
        return base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()
    policy = "default-src 'none'; script-src 'sha256-" + digest(SCRIPT) + "'; style-src 'sha256-" + digest(STYLE) + "'; base-uri 'none'; form-action 'none'"
    return ('<!doctype html><html lang="' + lang + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="' + text(policy) + '"><title>' + text(title) + '</title><style>' + STYLE + '</style></head><body>'
        '<header><div><h1>' + text(title) + '</h1><p>' + text(words["notice"]) + '</p></div><div class="totals">' + ''.join('<span><b>' + str(counts[key]) + '</b>' + text(words[key]) + '</span>' for key in ("confirmed", "candidate", "allowed")) + '</div></header>'
        '<div class="workspace"><aside class="files"><h2>' + text(words["files"]) + '</h2><nav class="file-list">' + ''.join(nav) + '</nav></aside><main>'
        '<div class="filters"><label>' + text(words["search"]) + '<input type="search" id="leak-search"></label><label>' + text(words["category"]) + '<select id="leak-category">' + category_options + '</select></label>'
        '<label>' + text(words["status"]) + '<select id="leak-status">' + status_options + '</select></label><div class="filter-footer"><output id="leak-count" aria-live="polite"></output>'
        '<label class="inventory-toggle"><input type="checkbox" id="show-inventory">' + text(words["show_inventory"]) + ' (' + str(counts["inventory"]) + ')</label></div></div>'
        '<div class="inspector"><div class="matches" id="leak-list">' + warning + '<h2>' + text(words["findings"]) + '</h2><noscript>' + text(words["nojs"]) + '</noscript>'
        '<p id="leak-empty" hidden>' + text(words["empty"]) + '</p><table><thead><tr><th>' + text(words["status"]) + '</th><th>' + text(words["location"]) + '</th><th>' + text(words["content"]) + '</th></tr></thead><tbody>' + ''.join(table) + '</tbody></table></div>'
        '<div class="details-pane"><p class="no-selection" id="no-selection">' + text(words["select"]) + '</p>' + ''.join(panels) + '</div></div>'
        '<details class="provenance"><summary>' + text(words["provenance"]) + '</summary><pre>' + text(json.dumps(sources, ensure_ascii=False, indent=2)) + '</pre></details>'
        '</main></div><script>' + SCRIPT + '</script></body></html>')
