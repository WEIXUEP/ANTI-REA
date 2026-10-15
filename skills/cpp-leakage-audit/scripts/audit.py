#!/usr/bin/env python3
"""Standalone source and ELF/PE information-leakage inventory. No rewriting."""
import argparse
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
        pe = pefile.PE(data=data)
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            rows.append(("import-library", entry.dll.decode(errors="replace")))
            for item in entry.imports:
                if item.name:
                    rows.append(("import-symbol", item.name.decode(errors="replace")))
        for item in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            if item.name:
                rows.append(("export-symbol", item.name.decode(errors="replace")))
        for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            if entry.struct.Type == 2:
                start, size = entry.struct.PointerToRawData, entry.struct.SizeOfData
                codeview = data[start:start + size]
                if codeview.startswith(b"RSDS"):
                    rows.append(("pdb-reference", codeview[24:].split(b"\0", 1)[0].decode(errors="replace")))
        if pe.FILE_HEADER.NumberOfSymbols:
            rows.append(("debug-metadata", "COFF symbol table present"))
    else:
        unchecked.append("Structured metadata: not an ELF or PE artifact")
    return rows, unchecked


def scan_binary(path, functions=(), variables=(), deny=()):
    path = Path(path)
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
        for category, names in (("specified-function", functions), ("specified-variable", variables), ("denied-text", deny)):
            for name in names:
                if name and name in text:
                    add(category, name, offset, encoding, "confirmed")
        if re.search(r"(?:_ZTS|_ZTI|\.?\?AV|\.?\?AU|65R[a-f0-9]{64})", text):
            add("rtti", text, offset, encoding)
    try:
        rows, unchecked = metadata(data)
        for category, evidence in rows:
            add(category, evidence, status="confirmed")
    except Exception as error:
        unchecked = ["Structured metadata parse failed: " + type(error).__name__]
    return findings, unchecked


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
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", default=[])
    parser.add_argument("--source")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--variable", action="append", default=[])
    parser.add_argument("--deny", action="append", default=[])
    parser.add_argument("--allow", help="JSON list of pattern/reason objects")
    parser.add_argument("--out", help="Report prefix; writes .json and .md")
    parser.add_argument("--fail-on-deny", action="store_true")
    args = parser.parse_args(argv)
    if not args.binary and not args.source:
        parser.error("Provide --binary and/or --source")
    result = dict(schema=1, findings=[], not_checked=[], limitations=[
        "Paths and source matches are candidates; arbitrary data may resemble paths.",
        "No disassembly, memory inspection, encrypted-data recovery, or complete local-variable enumeration.",
        "PDB contents and DWARF variable DIEs are not parsed; keep private debug artifacts out of releases."])
    for binary in args.binary:
        rows, unchecked = scan_binary(binary, args.function, args.variable, args.deny)
        result["findings"].extend(rows)
        result["not_checked"].extend(unchecked)
    if args.source:
        result["findings"].extend(scan_source(args.source))
    if args.allow:
        rules = json.loads(Path(args.allow).read_text())
        for rule in rules:
            if not rule.get("reason", "").strip():
                parser.error("Every allow rule requires a reason")
            for row in result["findings"]:
                if re.search(rule["pattern"], row["evidence"]):
                    row.update(status="allowed", reason=rule["reason"])
    if args.out:
        prefix = Path(args.out)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        prefix.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
        prefix.with_suffix(".md").write_text(markdown(result))
    print(json.dumps(dict(findings=len(result["findings"]), not_checked=result["not_checked"])))
    return int(args.fail_on_deny and any(row["status"] == "confirmed" and row["category"] in {
        "denied-text", "specified-function", "specified-variable"} for row in result["findings"]))


if __name__ == "__main__":
    raise SystemExit(main())
