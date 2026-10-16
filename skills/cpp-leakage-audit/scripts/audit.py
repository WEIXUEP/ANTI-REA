#!/usr/bin/env python3
"""Standalone source and ELF/PE information-leakage inventory. No rewriting."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import sys

PATH = re.compile(r"(?:(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s<>\"|]*|\\\\[A-Za-z0-9_.-]+\\[^\s<>\"|]+|(?<![A-Za-z0-9:])/(?:[A-Za-z0-9_.+@-]+/)+[A-Za-z0-9_.+@-]*|(?:[A-Za-z0-9_.-]+[/\\])+[A-Za-z0-9_.-]+\.[A-Za-z0-9]+)")
URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"|]+")
FILENAME = re.compile(r"(?<![\w.-])[\w.-]+\.(?:cpp|cxx|cc|hpp|hxx|h|f90|cu|pdb|ll|obj|o)(?!\w)", re.I)
SOURCE_PATTERNS = {
    "source-location": r"\b(?:__FILE__|__LINE__|__FILE_NAME__|source_location)\b",
    "function-signature": r"\b(?:__PRETTY_FUNCTION__|__FUNCSIG__|__func__)\b",
    "diagnostic": r"\b(?:assert|abort|printf|fprintf|puts|runtime_error|MFEM_VERIFY|MFEM_ASSERT)\s*\(|\b(?:cerr|clog)\s*<<",
    "rtti-name": r"\btypeid\s*\(|\.name\s*\(\s*\)",
    "explicit-export": r"__declspec\s*\(\s*dllexport|visibility\s*\(\s*\"default\"",
}
PRIVATE_SUFFIXES = {".pdb", ".ilk", ".exp", ".obj", ".o", ".lib", ".a", ".ll", ".bc", ".map"}


def private_artifact(path):
    path = Path(path)
    return (path.suffix.lower() in PRIVATE_SUFFIXES
            or any(part.lower() in {"private", ".private", "maps"} for part in path.parts)
            or bool(re.search(r"(?:^|[-_.])(?:keys?|codebook)(?:[-_.]|$)", path.name, re.I)))


def path_matches(text):
    urls = [match.span() for match in URL.finditer(text)]
    return [match for match in PATH.finditer(text)
            if not any(match.start() < end and match.end() > start for start, end in urls)]


def strings(data, minimum=4):
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        yield match.start(), "ASCII", match[0].decode("ascii")
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, data):
        yield match.start(), "UTF-16LE", match[0].decode("utf-16le")
    for match in re.finditer(rb"(?:\x00[\x20-\x7e]){%d,}" % minimum, data):
        yield match.start(), "UTF-16BE", match[0].decode("utf-16be")


def metadata(data):
    rows, unchecked = [], []
    if data.startswith(b"\x7fELF"):
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection
        except ImportError:
            return [], ["ELF sections/symbols/RUNPATH: install pyelftools"]
        elf = ELFFile(io.BytesIO(data))
        for section in elf.iter_sections():
            if section.name.startswith((".debug", ".zdebug")):
                rows.append(("debug-metadata", section.name))
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name:
                        category = ("import-symbol" if symbol.entry.st_shndx == "SHN_UNDEF" else "export-symbol") if section.name == ".dynsym" else "static-symbol"
                        rows.append((category, symbol.name))
            if section.name == ".dynamic":
                for tag in section.iter_tags():
                    if tag.entry.d_tag in {"DT_RPATH", "DT_RUNPATH"}:
                        rows.append(("runtime-path", getattr(tag, "rpath", getattr(tag, "runpath", ""))))
    elif data.startswith(b"MZ"):
        try:
            import pefile
        except ImportError:
            return [], ["PE imports/exports/CodeView: install pefile"]
        # Parse only metadata covered by this auditor. Unwind/disassembly
        # warnings are unrelated, while recovered import/export failures must
        # remain visible as incomplete checks.
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[name] for name in (
            "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
            "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_DEBUG")])
        rows.append(("pe-machine", hex(pe.FILE_HEADER.Machine)))
        for directory, prefix in (("DIRECTORY_ENTRY_IMPORT", "import"), ("DIRECTORY_ENTRY_DELAY_IMPORT", "delay-import")):
            for entry in getattr(pe, directory, []):
                rows.append((prefix + "-library", entry.dll.decode(errors="replace")))
                for item in entry.imports:
                    if item.name:
                        rows.append((prefix + "-symbol", item.name.decode(errors="replace")))
                    else:
                        rows.append((prefix + "-ordinal", entry.dll.decode(errors="replace") + "!" + str(item.ordinal)))
        for item in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            name = item.name.decode(errors="replace") if item.name else "ordinal:" + str(item.ordinal)
            rows.append(("export-symbol", name))
            if item.forwarder:
                rows.append(("forwarded-export", name + " -> " + item.forwarder.decode(errors="replace")))
        for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            if entry.struct.Type == 2:
                start, size = entry.struct.PointerToRawData, entry.struct.SizeOfData
                codeview = data[start:start + size]
                if codeview.startswith(b"RSDS"):
                    if len(codeview) < 25 or b"\0" not in codeview[24:]:
                        raise ValueError("Invalid RSDS record")
                    rows.append(("pdb-reference", codeview[24:].split(b"\0", 1)[0].decode(errors="replace")))
                elif codeview.startswith(b"NB10") and len(codeview) > 16 and b"\0" in codeview[16:]:
                    rows.append(("pdb-reference", codeview[16:].split(b"\0", 1)[0].decode(errors="replace")))
                else:
                    unchecked.append("PE CodeView: unsupported or malformed record")
        if pe.FILE_HEADER.NumberOfSymbols:
            rows.append(("debug-metadata", "COFF symbol table present"))
        unchecked.extend("PE metadata parser warning: " + warning for warning in pe.get_warnings())
    else:
        unchecked.append("Structured metadata: not an ELF or PE artifact")
    return rows, unchecked


def scan_binary(path, functions=(), variables=(), deny=(), data=None):
    path = Path(path)
    if data is None:
        data = path.read_bytes()
    findings, seen = [], set()

    def add(category, evidence, offset=None, encoding=None, status="candidate"):
        key = category, evidence, offset, encoding
        if key not in seen:
            seen.add(key)
            findings.append(dict(artifact=path.name, category=category, evidence=evidence[:1024],
                                 offset=offset, encoding=encoding, status=status))

    for offset, encoding, text in strings(data):
        for match in URL.finditer(text):
            add("url", match[0], offset, encoding)
        for match in path_matches(text):
            add("path", match[0], offset + match.start() * (2 if encoding.startswith("UTF") else 1), encoding)
        for match in FILENAME.finditer(text):
            add("filename", match[0], offset, encoding)
        if re.search(r"(?:_ZTS|_ZTI|\.\?(?:A[UV]|[PQ][A-Z])|65R[a-f0-9]{64})", text):
            add("rtti", text, offset, encoding)
    # Search the bytes themselves: short names, Unicode and strings next to
    # nonprintable bytes must not disappear behind printable-string heuristics.
    for category, names in (("specified-function", functions), ("specified-variable", variables), ("denied-text", deny)):
        for name in names:
            if not name:
                continue
            for encoding in ("utf-8", "utf-16le", "utf-16be"):
                needle = name.encode(encoding)
                start = 0
                while (offset := data.find(needle, start)) >= 0:
                    add(category, name, offset, encoding.upper(), "confirmed")
                    start = offset + len(needle)
    try:
        rows, unchecked = metadata(data)
        for category, evidence in rows:
            add(category, evidence, status="confirmed")
    except Exception as error:
        unchecked = ["Structured metadata parse failed: " + type(error).__name__]
    return findings, unchecked


def compare_baseline(result, baseline):
    if baseline.get("schema") != 2 or "scan" not in baseline:
        raise ValueError("Baseline must be a schema-2 audit from this scanner")
    if baseline["scan"] != result["scan"]:
        raise ValueError("Baseline scope, sensitive corpus or allow rules differ; repeat the same scan")
    if baseline.get("scanner_sha256") != result["scanner_sha256"]:
        raise ValueError("Baseline scanner version differs; capture a new baseline with the same scanner")
    if baseline.get("not_checked"):
        raise ValueError("Baseline has unperformed checks; complete them before comparing")
    before = {row["artifact"] for row in baseline["artifacts"]}
    after = {row["artifact"] for row in result["artifacts"]}
    if before != after:
        raise ValueError("Baseline artifact inventory differs; compare the same release contents")

    def identities(report):
        return {(row["artifact"], row["category"], row["evidence"], row["status"])
                for row in report["findings"]}

    old, new = identities(baseline), identities(result)
    return {name: [dict(zip(("artifact", "category", "evidence", "status"), item)) for item in sorted(items)]
            for name, items in (("resolved", old - new), ("persistent", old & new), ("introduced", new - old))}


def scan_source(root):
    findings = []
    root = Path(root)
    paths = [root] if root.is_file() else sorted(root.rglob("*"))
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in {".cpp", ".cc", ".cxx", ".c", ".hpp", ".h", ".cu", ".cmake"}:
            continue
        relative = Path(path.name) if root.is_file() else path.relative_to(root)
        if any(part in {"build", "out", ".git", ".private", ".venv"} for part in relative.parts):
            continue
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            for match in path_matches(line):
                findings.append(dict(artifact=path.name if root.is_file() else path.relative_to(root).as_posix(),
                                     category="source-path", evidence=match[0], line=number, status="candidate"))
            for category, pattern in SOURCE_PATTERNS.items():
                if re.search(pattern, line):
                    findings.append(dict(artifact=path.name if root.is_file() else path.relative_to(root).as_posix(),
                                         category=category, evidence=line.strip()[:512], line=number,
                                         status="candidate"))
    return findings


def markdown(result):
    lines = ["# C++ Leakage Audit", "", "A match is evidence, not proof that reverse engineering is prevented.", "",
             f"Findings: {len(result['findings'])}. Not checked: {len(result['not_checked'])}.", "",
             "| Artifact | Category | Status | Evidence |", "| --- | --- | --- | --- |"]
    for row in result["findings"]:
        evidence = row["evidence"].replace("|", "\\|").replace("\n", " ").replace("`", "'")
        lines.append(f"| {row['artifact']} | {row['category']} | {row['status']} | `{evidence}` |")
    if result["not_checked"]:
        lines.extend(["", "## Not Checked", ""] + ["- " + text for text in result["not_checked"]])
    if result.get("comparison") is not None:
        lines.extend(["", "## Baseline Comparison", "",
                      "Counts use unique artifact/category/evidence/status tuples, not byte offsets.", ""])
        for category, rows in result["comparison"].items():
            lines.append(f"- {category}: {len(rows)}")
    lines.extend(["", "## Artifact Fingerprints", "", "| Artifact | Bytes | SHA-256 |", "| --- | --- | --- |"])
    for row in result["artifacts"]:
        lines.append(f"| {row['artifact']} | {row['size']} | `{row['sha256']}` |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", default=[])
    parser.add_argument("--source")
    parser.add_argument("--package", help="Inventory and scan every file in a staged release directory")
    parser.add_argument("--baseline", help="Compare against a saved original-program audit JSON")
    parser.add_argument("--require-metadata", action="store_true", help="Fail if any structured binary check is unavailable")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--variable", action="append", default=[])
    parser.add_argument("--deny", action="append", default=[])
    parser.add_argument("--allow", help="JSON list of pattern/reason objects")
    parser.add_argument("--out", help="Report prefix; writes .json and .md")
    parser.add_argument("--fail-on-deny", action="store_true")
    args = parser.parse_args(argv)
    if args.baseline and args.out and Path(args.out).with_suffix(".json").resolve() == Path(args.baseline).resolve():
        parser.error("Use a separate output; do not overwrite the original baseline")
    if not args.binary and not args.source and not args.package:
        parser.error("Provide --binary, --package and/or --source")
    rules = json.loads(Path(args.allow).read_text(encoding="utf-8")) if args.allow else []
    for rule in rules:
        if not rule.get("reason", "").strip():
            parser.error("Every allow rule requires a reason")
        re.compile(rule["pattern"])
    result = dict(schema=2, scanner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  findings=[], not_checked=[], artifacts=[], scan=dict(
        functions=sorted(set(args.function)), variables=sorted(set(args.variable)),
        deny=sorted(set(args.deny)), allow=rules, source=bool(args.source),
        package=bool(args.package), binary_count=len(args.binary)), limitations=[
        "Paths and source matches are candidates; arbitrary data may resemble paths.",
        "No disassembly, memory inspection, encrypted-data recovery, or complete local-variable enumeration.",
        "PDB contents and DWARF variable DIEs are not parsed; keep private debug artifacts out of releases."])
    inputs = [(f"binary/{index}/{Path(binary).name}", Path(binary), True)
              for index, binary in enumerate(args.binary)]
    if args.package:
        package = Path(args.package)
        if not package.is_dir() or package.is_symlink():
            parser.error("Package must be a real directory")
        for path in sorted(package.rglob("*")):
            if path.is_symlink() or not path.resolve().is_relative_to(package.resolve()):
                parser.error("Package contains a link outside the audited file inventory")
            if path.is_file():
                inputs.append(("package/" + path.relative_to(package).as_posix(), path, False))
    if args.out:
        destinations = [Path(args.out).with_suffix(suffix).resolve() for suffix in (".json", ".md")]
        originals = {path.resolve() for _, path, _ in inputs}
        if any(path in originals for path in destinations):
            parser.error("Audit output must not overwrite an input artifact")
        if args.package and any(path.is_relative_to(package.resolve()) for path in destinations):
            parser.error("Keep audit reports outside the release package")
    for label, binary, explicit in inputs:
        data = binary.read_bytes()
        result["artifacts"].append(dict(artifact=label, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
        rows, unchecked = scan_binary(binary, args.function, args.variable, args.deny, data=data)
        for row in rows:
            row["artifact"] = label
        result["findings"].extend(rows)
        native_name = binary.suffix.lower() in {".exe", ".dll", ".pyd", ".sys", ".so", ".dylib"} or ".so." in binary.name
        if explicit or native_name or data.startswith((b"MZ", b"\x7fELF")):
            result["not_checked"].extend(label + ": " + text for text in unchecked)
        if not explicit and private_artifact(Path(label).relative_to("package")):
            result["findings"].append(dict(artifact=label, category="private-artifact", evidence=label,
                                            status="confirmed"))
    if args.package and not any(label.startswith("package/") for label, _, _ in inputs):
        parser.error("Package is empty")
    if args.source:
        result["findings"].extend(scan_source(args.source))
    for rule in rules:
        for row in result["findings"]:
            if re.search(rule["pattern"], row["evidence"]):
                row.update(status="allowed", reason=rule["reason"])
    if args.baseline:
        try:
            result["comparison"] = compare_baseline(result, json.loads(Path(args.baseline).read_text(encoding="utf-8")))
            result["baseline_sha256"] = hashlib.sha256(Path(args.baseline).read_bytes()).hexdigest()
        except ValueError as error:
            parser.error(str(error))
    if args.out:
        prefix = Path(args.out)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        prefix.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        prefix.with_suffix(".md").write_text(markdown(result), encoding="utf-8")
    print(json.dumps(dict(findings=len(result["findings"]), artifacts=len(result["artifacts"]),
                         not_checked=result["not_checked"], comparison={k: len(v) for k, v in result.get("comparison", {}).items()})))
    if args.require_metadata and result["not_checked"]:
        return 2
    return int(args.fail_on_deny and any(row["status"] == "confirmed" and row["category"] in {
        "denied-text", "specified-function", "specified-variable", "private-artifact"} for row in result["findings"]))


if __name__ == "__main__":
    raise SystemExit(main())
