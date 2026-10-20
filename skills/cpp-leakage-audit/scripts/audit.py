#!/usr/bin/env python3
"""Standalone source and ELF/PE information-leakage inventory. No rewriting."""
import argparse
import hashlib
import io
import json
import math
from pathlib import Path
import re
import runpy
import struct
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
PRIVATE_SUFFIXES = {".pdb", ".ilk", ".exp", ".obj", ".o", ".lib", ".a", ".ll", ".bc", ".map", ".debug", ".key", ".pem"}


def constant_bytes(specification):
    """Encode an explicitly selected value; never guess widths or byte order."""
    if not isinstance(specification, str):
        raise ValueError("Constant must be a type:value string")
    kind, separator, value = specification.partition(":")
    formats = {"u32le": "<I", "u32be": ">I", "u64le": "<Q", "u64be": ">Q",
               "f32le": "<f", "f32be": ">f", "f64le": "<d", "f64be": ">d"}
    if not separator or kind not in formats or not value.strip():
        raise ValueError("Use u32le/u32be/u64le/u64be/f32le/f32be/f64le/f64be:value")
    try:
        number = int(value, 0) if kind.startswith("u") else float(value)
        if kind.startswith("f") and not math.isfinite(number):
            raise ValueError("Floating constants must be finite")
        return struct.pack(formats[kind], number)
    except (ValueError, OverflowError, struct.error) as error:
        raise ValueError("Invalid or out-of-range numeric constant") from error


def private_artifact(path):
    path = Path(path)
    return (path.suffix.lower() in PRIVATE_SUFFIXES
            or any(part.lower() in {"private", ".private", "maps", "ir"} for part in path.parts)
            or bool(re.search(r"(?:^|[-_.])(?:keys?|codebook)(?:[-_.]|$)|(?:private|secret)[-_.]|^diagnostics\.json$", path.name, re.I)))


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


def scan_binary(path, functions=(), variables=(), deny=(), data=None, *, all_strings=False, constants=()):
    path = Path(path)
    if data is None:
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
    for specification in constants:
        needle = constant_bytes(specification)
        start = 0
        while (offset := data.find(needle, start)) >= 0:
            add("specified-constant", specification, offset, specification.split(":", 1)[0].upper(), "confirmed")
            start = offset + 1
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
    """Inventory every staged file; reject links outside the audited inventory."""
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Package must be a real directory")
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Package contains a link outside the audited file inventory")
        if path.is_file():
            files.append(path)
    if not files:
        raise ValueError("Package is empty")
    return files


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
    if result.get("comparison") is not None:
        lines.extend(["", "## Baseline Comparison", "",
                      "Counts use unique artifact/category/evidence/status tuples, not byte offsets.", ""])
        for category, rows in result["comparison"].items():
            lines.append(f"- {category}: {len(rows)}")
    lines.extend(["", "## Artifact Fingerprints", "", "| Artifact | Bytes | SHA-256 |", "| --- | --- | --- |"])
    for row in result["artifacts"]:
        lines.append(f"| {row['artifact']} | {row['size']} | `{row['sha256']}` |")
    return "\n".join(lines) + "\n"


def _main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", default=[])
    parser.add_argument("--source")
    parser.add_argument("--package", action="append", default=[], help="Inventory and scan every file in a staged release directory; repeatable")
    parser.add_argument("--baseline", help="Compare against a saved original-program audit JSON")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--variable", action="append", default=[])
    parser.add_argument("--constant", action="append", default=[], help="Exact numeric bytes, e.g. u32le:0x5a827999 or f64be:0.125; repeatable")
    parser.add_argument("--deny", action="append", default=[])
    parser.add_argument("--allow", help="JSON list of pattern/reason objects")
    parser.add_argument("--deny-file", help="UTF-8 JSON list of exact sensitive strings")
    parser.add_argument("--all-strings", action="store_true", help="Include readable strings; reports may be confidential")
    parser.add_argument("--out", help="Private report prefix; writes .json, .md and offline .html")
    parser.add_argument("--fail-on-deny", action="store_true")
    parser.add_argument("--require-metadata", action="store_true", help="Nonzero status for unperformed structured checks")
    parser.add_argument("--fail-on-private", action="store_true", help="Nonzero status for unaccepted package private-artifact candidates")
    args = parser.parse_args(argv)
    for specification in args.constant:
        constant_bytes(specification)
    if args.deny_file:
        corpus = json.loads(Path(args.deny_file).read_text(encoding="utf-8-sig"))
        if not isinstance(corpus, list) or not all(isinstance(item, str) and item for item in corpus):
            raise ValueError("Sensitive corpus must be a JSON array of nonempty strings")
        args.deny.extend(corpus)
    if args.baseline and args.out and Path(args.out).with_suffix(".json").resolve() == Path(args.baseline).resolve():
        parser.error("Use a separate output; do not overwrite the original baseline")
    if not args.binary and not args.source and not args.package:
        parser.error("Provide --binary, --package and/or --source")
    rules = json.loads(Path(args.allow).read_text(encoding="utf-8-sig")) if args.allow else []
    if not isinstance(rules, list):
        raise ValueError("Allow rules must be an array")
    for rule in rules:
        if (not isinstance(rule, dict) or not isinstance(rule.get("pattern"), str)
                or not isinstance(rule.get("reason"), str) or not rule["reason"].strip()):
            parser.error("Every allow rule requires a reason")
        re.compile(rule["pattern"])
    result = dict(schema=2, scanner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  findings=[], not_checked=[], artifacts=[], scan=dict(
        functions=sorted(set(args.function)), variables=sorted(set(args.variable)),
        constants=sorted(set(args.constant)),
        deny=sorted(set(args.deny)), allow=rules, source=bool(args.source),
        package=bool(args.package), package_count=len(args.package),
        all_strings=args.all_strings, binary_count=len(args.binary)), limitations=[
        "Paths and source matches are candidates; arbitrary data may resemble paths.",
        "No disassembly, memory inspection, encrypted-data recovery, or complete local-variable enumeration.",
        "Numeric matches confirm encoded bytes only, not their type, ownership, execution or role; transformed or split constants may be missed.",
        "PDB contents and DWARF variable DIEs are not parsed; keep private debug artifacts out of releases."])
    inputs = [(f"binary/{index}/{Path(binary).name}", Path(binary), True)
              for index, binary in enumerate(args.binary)]
    packages = [Path(path) for path in args.package]
    for index, package in enumerate(packages):
        prefix = "package/" if len(packages) == 1 else f"package/{index}/"
        for path in package_files(package):
            inputs.append((prefix + path.relative_to(package).as_posix(), path, False))
    if args.out:
        destinations = [Path(args.out).with_suffix(suffix).resolve() for suffix in (".json", ".md", ".html")]
        originals = {path.resolve() for _, path, _ in inputs}
        originals.update(Path(path).resolve() for path in (args.baseline, args.deny_file, args.allow) if path)
        if any(path in originals for path in destinations):
            parser.error("Audit output must not overwrite an input artifact")
        if any(path.is_relative_to(package.resolve()) for path in destinations for package in packages):
            parser.error("Keep audit reports outside the release package")
    for label, binary, explicit in inputs:
        data = binary.read_bytes()
        result["artifacts"].append(dict(artifact=label, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
        rows, unchecked = scan_binary(binary, args.function, args.variable, args.deny,
                                      data=data, all_strings=args.all_strings, constants=args.constant)
        for row in rows:
            row["artifact"] = label
        result["findings"].extend(rows)
        native_name = binary.suffix.lower() in {".exe", ".dll", ".pyd", ".sys", ".so", ".dylib"} or ".so." in binary.name
        if explicit or native_name or data.startswith((b"MZ", b"\x7fELF")):
            result["not_checked"].extend(label + ": " + text for text in unchecked)
        if not explicit and private_artifact(Path(label).relative_to("package")):
            result["findings"].append(dict(artifact=label, category="private-artifact", evidence=label,
                                            status="confirmed"))
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
        renderer = runpy.run_path(str(Path(__file__).with_name("report_html.py")))["render"]
        prefix.with_suffix(".html").write_text(renderer([(str(prefix.with_suffix(".json")), result)]), encoding="utf-8")
    print(json.dumps(dict(findings=len(result["findings"]), artifacts=len(result["artifacts"]),
                         not_checked=result["not_checked"], comparison={k: len(v) for k, v in result.get("comparison", {}).items()})))
    if args.require_metadata and result["not_checked"]:
        return 2
    return int((args.fail_on_deny and any(row["status"] == "confirmed" and row["category"] in {
        "denied-text", "specified-function", "specified-variable", "specified-constant", "private-artifact"} for row in result["findings"]))
        or (args.fail_on_private and any(row["category"] == "private-artifact" and row["status"] != "allowed"
                                        for row in result["findings"])))


def main(argv=None):
    try:
        return _main(argv)
    except (OSError, ValueError, TypeError, re.error) as error:
        print("Audit failed: " + type(error).__name__ + "; check input paths, JSON schemas and permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
