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
FILENAME = re.compile(r"(?<![\w.-])[\w.-]+\.(?:cpp|cxx|cc|c|hpp|hxx|h|f90|cu|cuh|pdb|ll|obj|o)(?!\w)", re.I)
SOURCE_PATTERNS = {
    "source-location": r"\b(?:__FILE__|__LINE__|__FILE_NAME__|source_location)\b",
    "function-signature": r"\b(?:__PRETTY_FUNCTION__|__FUNCSIG__|__func__)\b",
    "diagnostic": r"\b(?:assert|abort|printf|fprintf|puts|runtime_error|[A-Z][A-Z0-9_]*(?:VERIFY|ASSERT|ABORT|WARNING))\s*\(|\b(?:cerr|clog)\s*<<",
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


def scan_binary(path, functions=(), variables=(), deny=(), all_strings=False):
    path = Path(path)
    data = path.read_bytes()
    findings, seen = [], set()

    def add(category, evidence, offset=None, encoding=None, status="candidate"):
        key = category, evidence, offset, encoding
        if key not in seen:
            seen.add(key)
            findings.append(dict(artifact=str(path), category=category, evidence=evidence[:1024],
                                 offset=offset, encoding=encoding, status=status))

    for offset, encoding, text in strings(data):
        width = 2 if encoding.startswith("UTF") else 1
        if all_strings:
            add("readable-string", text, offset, encoding)
        for match in URL.finditer(text):
            add("url", match[0], offset + match.start() * width, encoding)
        for match in path_matches(text):
            add("path", match[0], offset + match.start() * (2 if encoding.startswith("UTF") else 1), encoding)
        for match in FILENAME.finditer(text):
            add("filename", match[0], offset + match.start() * width, encoding)
        for category, names in (("specified-function", functions), ("specified-variable", variables), ("denied-text", deny)):
            for name in names:
                if name and name in text:
                    add(category, name, offset + text.index(name) * width, encoding, "confirmed")
        if re.search(r"(?:_ZTS|_ZTI|\.?\?AV|\.?\?AU|65R[a-f0-9]{64})", text):
            add("rtti", text, offset, encoding)
    try:
        rows, unchecked = metadata(data)
        for category, evidence in rows:
            add(category, evidence, status="confirmed")
    except Exception as error:
        unchecked = ["Structured metadata parse failed: " + type(error).__name__]
    # Exact sensitive matches are not limited to printable-string boundaries.
    # This also finds short, Unicode or multiline corpus entries.
    for category, names in (("specified-function", functions), ("specified-variable", variables), ("denied-text", deny)):
        for name in names:
            for encoding, codec in (("ASCII", "utf-8"), ("UTF-16LE", "utf-16le"), ("UTF-16BE", "utf-16be")):
                needle = name.encode(codec)
                position = data.find(needle) if needle else -1
                while position >= 0:
                    label = "UTF-8" if encoding == "ASCII" and not name.isascii() else encoding
                    add(category, name, position, label, "confirmed")
                    position = data.find(needle, position + len(needle))
    return findings, unchecked


def scan_source(root):
    findings = []
    root = Path(root)
    if not root.exists():
        raise ValueError("Source input does not exist")
    paths = [root] if root.is_file() else sorted(root.rglob("*"))
    for path in paths:
        if path.is_symlink() or not path.is_file() or (path.name != "CMakeLists.txt" and path.suffix.lower() not in {".cpp", ".cc", ".cxx", ".c", ".hpp", ".hxx", ".h", ".cu", ".cuh", ".cmake"}):
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


def package_files(root):
    """Inventory a staging tree without following package symlinks."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError("Package input is not a directory")
    natives, findings, unchecked = [], [], []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            unchecked.append("Package symlink not followed: " + str(path))
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic.startswith((b"\x7fELF", b"MZ")):
            natives.append(path)
        if (any(part.lower() in {"private", ".private", "maps", "ir"} for part in relative.parts)
                or path.suffix.lower() in {".pdb", ".ll", ".bc", ".debug", ".key", ".pem", ".obj", ".o"}
                or re.search(r"(?:(?:private|secret)[-_.]|compiler[-_]?keys|diagnostics\.json|^keys\.json$)", path.name, re.I)):
            findings.append(dict(artifact=str(path), category="private-artifact", evidence=relative.as_posix(),
                                 status="candidate", offset=None, encoding=None))
    return natives, findings, unchecked


def markdown(result):
    lines = ["# C++ Leakage Audit", "", "A match is evidence, not proof that reverse engineering is prevented.", "",
             f"Findings: {len(result['findings'])}. Not checked: {len(result['not_checked'])}.", "",
             "| Artifact | Category | Status | Evidence |", "| --- | --- | --- | --- |"]
    for row in result["findings"]:
        evidence = row["evidence"].replace("|", "\\|").replace("\n", " ").replace("`", "'")
        artifact = row['artifact'].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {artifact} | {row['category']} | {row['status']} | `{evidence}` |")
    if result["not_checked"]:
        lines.extend(["", "## Not Checked", ""] + ["- " + text for text in result["not_checked"]])
    return "\n".join(lines) + "\n"


def _main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", default=[])
    parser.add_argument("--source")
    parser.add_argument("--package", action="append", default=[], help="Staged tree: scan ELF/PE and flag private artifacts")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--variable", action="append", default=[])
    parser.add_argument("--deny", action="append", default=[])
    parser.add_argument("--allow", help="JSON list of pattern/reason objects")
    parser.add_argument("--deny-file", help="UTF-8 JSON list of exact sensitive strings")
    parser.add_argument("--all-strings", action="store_true", help="Include readable strings; reports may be confidential")
    parser.add_argument("--out", help="Report prefix; writes .json and .md")
    parser.add_argument("--fail-on-deny", action="store_true")
    parser.add_argument("--require-metadata", action="store_true", help="Nonzero status for unperformed structured checks")
    parser.add_argument("--fail-on-private", action="store_true", help="Nonzero status for unaccepted package private-artifact candidates")
    args = parser.parse_args(argv)
    if not args.binary and not args.source and not args.package:
        parser.error("Provide --binary, --source and/or --package")
    if args.deny_file:
        corpus = json.loads(Path(args.deny_file).read_text(encoding="utf-8-sig"))
        if not isinstance(corpus, list) or not all(isinstance(item, str) and item for item in corpus):
            raise ValueError("Sensitive corpus must be a JSON array of nonempty strings")
        args.deny.extend(corpus)
    result = dict(schema=1, findings=[], not_checked=[], limitations=[
        "Paths and source matches are candidates; arbitrary data may resemble paths.",
        "No disassembly, memory inspection, encrypted-data recovery, or complete local-variable enumeration.",
        "PDB contents and DWARF variable DIEs are not parsed; keep private debug artifacts out of releases."])
    result["artifacts"] = []
    binaries = [Path(path) for path in args.binary]
    for package in args.package:
        natives, rows, unchecked = package_files(package)
        if not natives:
            unchecked.append("No regular ELF/PE artifacts discovered in package: " + str(package))
        binaries.extend(natives)
        result["findings"].extend(rows)
        result["not_checked"].extend(unchecked)
    for binary in sorted(set(path.resolve() for path in binaries)):
        data = binary.read_bytes()
        result["artifacts"].append(dict(path=str(binary), bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        rows, unchecked = scan_binary(binary, args.function, args.variable, args.deny, args.all_strings)
        result["findings"].extend(rows)
        result["not_checked"].extend(str(binary) + ": " + item for item in unchecked)
    if args.package:
        result["limitations"].append("Package nonnative asset contents are not scanned automatically; pass selected assets with --binary. Symlink targets need separate scope review.")
    if args.source:
        result["findings"].extend(scan_source(args.source))
    if args.allow:
        rules = json.loads(Path(args.allow).read_text(encoding="utf-8-sig"))
        if not isinstance(rules, list):
            raise ValueError("Allow rules must be an array")
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("pattern"), str) or not isinstance(rule.get("reason"), str) or not rule["reason"].strip():
                parser.error("Every allow rule requires a reason")
            pattern = re.compile(rule["pattern"])
            for row in result["findings"]:
                if pattern.search(row["evidence"]):
                    row.update(status="allowed", reason=rule["reason"])
    if args.out:
        prefix = Path(args.out)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        prefix.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        prefix.with_suffix(".md").write_text(markdown(result), encoding="utf-8")
    print(json.dumps(dict(findings=len(result["findings"]), not_checked=result["not_checked"])))
    return int((args.fail_on_deny and any(row["status"] == "confirmed" and row["category"] in {
        "denied-text", "specified-function", "specified-variable"} for row in result["findings"]))
        or (args.require_metadata and bool(result["not_checked"]))
        or (args.fail_on_private and any(row["category"] == "private-artifact" and row["status"] != "allowed" for row in result["findings"])))


def main(argv=None):
    try:
        return _main(argv)
    except (OSError, ValueError, TypeError, re.error) as error:
        print("Audit failed: " + type(error).__name__ + "; check input paths, JSON schemas and permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
