#!/usr/bin/env python3
"""Baseline-bound native risk triage and optional read-only REA queries."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys


# These are review seeds, not vulnerability signatures. Only parsed imports count.
SINKS = {}
for names, cwe, question in (
    ("gets strcpy strcat wcscpy wcscat sprintf vsprintf", "CWE-120",
     "Can input exceed the destination capacity, including its terminator?"),
    ("scanf sscanf fscanf wscanf swscanf fwscanf", "CWE-120",
     "Do string conversions have widths consistent with destination capacities?"),
    ("memcpy memmove wmemcpy wmemmove", "CWE-787",
     "Are source and destination ranges and size arithmetic validated on every path?"),
    ("printf fprintf vprintf vfprintf syslog", "CWE-134",
     "Can an untrusted value become the format argument rather than a data argument?"),
    ("system popen _popen WinExec CreateProcessA CreateProcessW ShellExecuteA ShellExecuteW", "CWE-78",
     "Can external input control a shell command, executable or argument boundary?"),
    ("LoadLibraryA LoadLibraryW LoadLibraryExA LoadLibraryExW dlopen", "CWE-427",
     "Can a writable search directory or untrusted path select the loaded library?"),
    ("mktemp tmpnam tempnam _mktemp _tempnam", "CWE-377",
     "Is a temporary name used without atomic creation and suitable permissions?"),
):
    for name in names.split():
        SINKS[name] = (cwe, question)

OPERATIONS = {"search-procedures": "search_procedures", "search-strings": "search_strings",
              "function": "analyze_function", "instructions": "read_function_instructions",
              "decompile": "procedure_pseudo_code", "xrefs": "xrefs",
              "values": "trace_native_values", "call-targets": "resolve_native_call_targets"}
ACTIONS = ("plan", *OPERATIONS)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_baseline(path, binary, artifact=None):
    raw = path.read_bytes()
    report = json.loads(raw.decode("utf-8-sig"))
    if (not isinstance(report, dict) or report.get("schema") != 2
            or not isinstance(report.get("scan"), dict)
            or not isinstance(report.get("artifacts"), list)
            or not isinstance(report.get("findings"), list)
            or not isinstance(report.get("not_checked"), list)):
        raise ValueError("Use an original schema-2 audit.py baseline")
    scanner = Path(__file__).with_name("audit.py")
    if report.get("scanner_sha256") != sha256(scanner.read_bytes()):
        raise ValueError("Baseline scanner differs; retain it and capture a fresh baseline with this skill")
    data = binary.read_bytes()
    digest = sha256(data)
    matches = [row for row in report["artifacts"] if isinstance(row, dict)
               and row.get("sha256") == digest and row.get("size") == len(data)
               and (artifact is None or row.get("artifact") == artifact)]
    if len(matches) != 1 or not isinstance(matches[0].get("artifact"), str):
        raise ValueError("Target must match exactly one baseline artifact by SHA-256 and size; use --artifact for duplicates")
    if not data.startswith((b"MZ", b"\x7fELF")):
        raise ValueError("Native triage accepts only PE/ELF byte carriers; metadata/provider admission still applies")
    label = PurePosixPath(matches[0]["artifact"])
    if (not label.parts or label.is_absolute() or ".." in label.parts
            or label.parts[0] not in {"binary", "package"}):
        raise ValueError("Invalid baseline artifact label")
    binding = dict(baseline_sha256=sha256(raw), artifact=matches[0]["artifact"],
                   path=str(binary), size=len(data), sha256=digest)
    return report, binding


def import_name(symbol):
    # PE import decorations and ELF symbol versions; never substring-match C++ names.
    name = re.sub(r"@(?:@?GLIBC[^@]*|[0-9]+)$", "", symbol)
    name = name.removeprefix("__imp_")
    if name in SINKS:
        return name
    return name.removeprefix("_")


def risk_candidates(baseline, artifact):
    candidates = []
    for row in baseline["findings"]:
        if (not isinstance(row, dict) or row.get("artifact") != artifact
                or row.get("category") not in {"import-symbol", "delay-import-symbol"}
                or row.get("status") not in {"confirmed", "allowed"}
                or not isinstance(row.get("evidence"), str)):
            continue
        name = import_name(row["evidence"])
        if name not in SINKS:
            continue
        cwe, question = SINKS[name]
        candidates.append(dict(status="candidate", symbol=row["evidence"], cwe_hypothesis=cwe,
                               evidence=dict(category=row["category"], artifact=artifact),
                               question=question, next_action="search-procedures"))
    return candidates


def query_arguments(action, binary, selector, provider):
    if not selector:
        raise ValueError("Select an exact procedure/address or search term with --selector")
    if action.startswith("search-"):
        query = ["search", str(binary), "--pattern=" + selector,
                 "--kind=" + action.removeprefix("search-"), "--mode=literal"]
    elif action in {"function", "instructions", "decompile", "xrefs"}:
        option = "address" if action == "xrefs" else "procedure"
        query = [action, str(binary), "--" + option + "=" + selector]
    else:
        # These REA commands only accept positional selectors. Admit addresses
        # returned by the provider, so selector text cannot become CLI options.
        if not re.fullmatch(r"0x[0-9a-fA-F]+", selector):
            raise ValueError("values/call-targets require an exact 0x-prefixed address from REA")
        command = "trace-native-values" if action == "values" else "resolve-native-call-targets"
        query = [command, str(binary), selector]
        if action == "values":
            query += ["--max-depth=2", "--max-functions=8", "--max-call-sites=128"]
    # REA's built-in output flags require spaced values, unlike named selectors.
    return query + ["--provider=" + provider, "--format", "json", "--full-output"]


def validate_output(output, baseline, binary, binding, package_root):
    if output.exists():
        raise ValueError("Use a new private output directory; evidence is never overwritten")
    label = PurePosixPath(binding["artifact"])
    if label.parts[0] == "package":
        if package_root is None:
            raise ValueError("Package evidence requires --package-root to keep reports outside the release")
        parts = label.parts[2:] if baseline["scan"].get("package_count", 1) > 1 else label.parts[1:]
        if binary.relative_to(package_root).as_posix() != PurePosixPath(*parts).as_posix():
            raise ValueError("--package-root does not match the baseline artifact layout")
    if package_root is not None and output.is_relative_to(package_root):
        raise ValueError("Keep private REA evidence outside the release package")


def evidence_matches(evidence, binding, action, provider):
    if (not isinstance(evidence, dict) or not evidence.get("evidence_id")
            or not isinstance(evidence.get("subject"), dict)
            or not isinstance(evidence["subject"].get("digest"), dict)
            or evidence["subject"]["digest"].get("sha256") != binding["sha256"]
            or evidence.get("operation") != OPERATIONS[action]
            or not isinstance(evidence.get("provider"), dict)):
        return False
    if action != "values":
        return evidence["provider"].get("id") == provider
    # Value tracing is owned by REA's composed workflow; the constituent
    # procedure records, rather than the parent, identify the selected engine.
    result = evidence.get("normalized_result")
    return (evidence["provider"].get("id") == "rea-workflow"
            and isinstance(result, dict) and result.get("target_sha256") == binding["sha256"]
            and isinstance(result.get("procedures"), list) and bool(result["procedures"])
            and all(isinstance(row, dict) and row.get("provider") == provider and row.get("evidence_id")
                    for row in result["procedures"]))


def run_query(rea_root, node, arguments, output, binding, action, provider):
    entry = rea_root / "scripts/rea.mjs"
    if not entry.is_file():
        raise ValueError("REA missing: initialize third_party/rea or supply --rea-root; plan needs no REA")
    executable = shutil.which(node)
    if executable is None:
        raise ValueError("Node.js missing; supply --node pointing to a supported runtime")
    package = json.loads((rea_root / "package.json").read_text(encoding="utf-8"))
    if not isinstance(package, dict) or not isinstance(package.get("version"), str):
        raise ValueError("REA package.json must declare a version")
    git = shutil.which("git")
    revision = (subprocess.run([git, "-C", str(rea_root), "rev-parse", "HEAD"],
                               capture_output=True, check=False)
                if git and (rea_root / ".git").exists() else None)
    command = [executable, str(entry), *arguments]
    # REA owns provider deadlines and process-tree cleanup. No shell, target
    # execution, setup, annotation, snapshot replacement or automatic install.
    process = subprocess.run(command, cwd=rea_root, stdin=subprocess.DEVNULL, capture_output=True)
    (output / "rea.stdout.txt").write_bytes(process.stdout)
    (output / "rea.stderr.txt").write_bytes(process.stderr)
    try:
        envelope = json.loads(process.stdout)
    except (ValueError, UnicodeError):
        envelope = None
    error = None
    if process.returncode != 0 or not isinstance(envelope, dict) or envelope.get("ok") is not True:
        error = "REA query failed or did not return a successful JSON envelope; inspect retained stdout/stderr"
    else:
        if not evidence_matches(envelope.get("data"), binding, action, provider):
            error = "REA Evidence does not match the requested artifact digest, operation and provider"
    completed = error is None
    return dict(status="completed" if completed else "incomplete", command=command,
                version=package.get("version"),
                commit=revision.stdout.decode("utf-8", errors="replace").strip()
                if revision is not None and revision.returncode == 0 else None,
                entry_sha256=sha256(entry.read_bytes()), exit_code=process.returncode,
                stdout_sha256=sha256(process.stdout), stderr_sha256=sha256(process.stderr),
                envelope=envelope, error=error)


def markdown(report):
    lines = ["# Native Risk Triage", "", "Status: " + report["status"], "",
             "Artifact: " + report["binding"]["artifact"],
             "SHA-256: " + report["binding"]["sha256"], "",
             "Candidates are review seeds, not confirmed vulnerabilities.", ""]
    for row in report["candidates"]:
        lines.append("- " + row["symbol"].replace("\n", " ") + " (" + row["cwe_hypothesis"] + "): " + row["question"])
    if "error" in report:
        lines += ["", "Incomplete: " + report["error"]]
    lines += ["", "See report.json and retained REA stdout/stderr for complete evidence, coverage and limitations.", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--artifact", help="Exact baseline artifact label when duplicate hashes exist")
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--action", choices=ACTIONS, default="plan")
    parser.add_argument("--selector")
    parser.add_argument("--provider", choices=("ghidra", "ida", "hopper"), default="ghidra")
    default_root = Path(__file__).resolve().parents[3] / "third_party/rea"
    parser.add_argument("--rea-root", type=Path, default=default_root)
    parser.add_argument("--node", default="node")
    parser.add_argument("--out", type=Path, required=True, help="New private evidence directory")
    args = parser.parse_args(argv)
    try:
        # Preserve the selected path for REA's own component/alias admission.
        binary = args.binary.absolute()
        baseline, binding = load_baseline(args.baseline, binary, args.artifact)
        output = args.out.resolve()
        package_root = args.package_root.resolve(strict=True) if args.package_root else None
        validate_output(output, baseline, binary, binding, package_root)
        arguments = query_arguments(args.action, binary, args.selector, args.provider) if args.action != "plan" else None
        report = dict(schema=1, status="planned", tool_sha256=sha256(Path(__file__).read_bytes()),
                      binding=binding, candidates=risk_candidates(baseline, binding["artifact"]),
                      request=dict(action=args.action, selector=args.selector, provider=args.provider),
                      baseline_not_checked=baseline["not_checked"], limitations=[
                          "Import presence does not prove a call, external input control or a vulnerability.",
                          "Static linking, inlining, ordinal/dynamic imports and custom code can hide sinks.",
                          "REA pseudocode/dataflow are derived evidence; preserve unresolved edges and truncation.",
                          "No target execution, exploitability test or complete security assessment was performed."])
        output.mkdir(parents=True, exist_ok=False)
        if arguments is not None:
            try:
                report["rea"] = run_query(args.rea_root.resolve(), args.node, arguments, output,
                                          binding, args.action, args.provider)
                report["status"] = report["rea"]["status"]
                if report["rea"]["error"]:
                    report["error"] = report["rea"]["error"]
            except (OSError, ValueError) as error:
                report.update(status="incomplete", error=str(error))
        # A query must never silently bind evidence to a changed on-disk target.
        try:
            if sha256(binary.read_bytes()) != binding["sha256"]:
                report.update(status="incomplete", error="Target changed during analysis; retain evidence and capture a new baseline")
        except OSError as error:
            report.update(status="incomplete", error="Target unavailable after analysis: " + str(error))
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (output / "report.md").write_text(markdown(report), encoding="utf-8")
        print(json.dumps(dict(status=report["status"], candidates=len(report["candidates"]), report=str(output / "report.json"))))
        return 2 if report["status"] == "incomplete" else 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print("REA audit failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
