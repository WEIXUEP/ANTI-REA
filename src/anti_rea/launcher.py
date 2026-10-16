"""CMake CPU compile launcher: emit IR, protect, verify, obfuscate once, compile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
from .crypto import load_keys, write_private
from .generate import enabled
from .ir import transform

XOLLVM_VERSION = "v0.11.1"
XOLLVM_COMMIT = "eb0850bd7cc87f551ad2948826605e518f5b8aa2"


def run(command, **kwargs):
    return subprocess.run([str(v) for v in command], check=True, **kwargs)


def version(tool):
    result = run([tool, "--version"], capture_output=True, text=True).stdout
    match = re.search(r"(?:clang|LLVM) version (\d+)", result, re.I)
    if not match:
        raise ValueError("Cannot identify LLVM version: " + str(tool))
    line = next(line.strip() for line in result.splitlines() if re.search(r"(?:clang|LLVM) version \d+", line, re.I))
    return int(match[1]), line


def doctor(compiler, opt, level="NONE", plugin=""):
    major, compiler_version = version(compiler)
    opt_major, opt_version = version(opt)
    if major != opt_major:
        raise ValueError("Compiler and opt LLVM major versions differ")
    if level != "NONE":
        if major not in {22, 23}:
            raise ValueError("xollvm v0.11.1 requires LLVM 22 or 23")
        if os.name == "nt" and plugin:
            raise ValueError("Windows requires an xollvm static-extension toolchain")
        command = [opt]
        if plugin:
            command.append("-load-pass-plugin=" + plugin)
        command.extend(["-passes=obfuscation,verify", "-disable-output", "-obf-seed=20261015", "-obf-deterministic"])
        run(command, input="; ANTI-REA capability probe\n", text=True, capture_output=True)
    return dict(compiler=compiler_version, opt=opt_version, level=level,
                xollvm_expected_tag=XOLLVM_VERSION, xollvm_expected_commit=XOLLVM_COMMIT,
                provenance="User-supplied; pass capability checked, upstream revision must be verified by operator")


def validate_obfuscation(report, level):
    if report.get("schema") != "llvm_obfuscator.obf_map":
        raise ValueError("Unknown xollvm report schema")
    evidence = []
    for target in ("policy_dispatch", "policy_token"):
        functions = [item for item in report.get("functions", []) if target in item.get("name", "")]
        if len(functions) != 1 or functions[0].get("skipped"):
            raise ValueError("Required obfuscation target missing or skipped: " + target)
        changed = [item["id"] for item in functions[0].get("passes", [])
                   if item.get("status") == "ran" and item.get("changed")]
        required = ("vm" if level == "MIXED_VM" and target == "policy_token" else
                    "flattening" if level in {"HEAVY", "MIXED_VM"} and target == "policy_dispatch" else None)
        if not changed or (required and required not in changed):
            raise ValueError("Required xollvm transformation did not run: " + target)
        evidence.append(dict(function=target, changed=changed))
    return evidence


def windows_words(text):
    result, word, quoted, active = [], [], False, False
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace() and not quoted:
            if active:
                result.append("".join(word))
                word, active = [], False
            index += 1
            continue
        active = True
        if char == "\\":
            start = index
            while index < len(text) and text[index] == "\\":
                index += 1
            count = index - start
            if index < len(text) and text[index] == '"':
                word.extend("\\" * (count // 2))
                if count % 2:
                    word.append('"')
                else:
                    quoted = not quoted
                index += 1
            else:
                word.extend("\\" * count)
            continue
        if char == '"':
            quoted = not quoted
        else:
            word.append(char)
        index += 1
    if quoted:
        raise ValueError("Unterminated response-file quote")
    if active:
        result.append("".join(word))
    return result


def expand_response(arguments, msvc, depth=0):
    if depth > 8:
        raise ValueError("Too many nested response files")
    result = []
    for argument in arguments:
        if argument.startswith("@"):
            data = Path(argument[1:]).read_bytes()
            text = data.decode("utf-16") if data.startswith((b"\xff\xfe", b"\xfe\xff")) else data.decode("utf-8-sig")
            result.extend(expand_response(windows_words(text) if msvc else shlex.split(text), msvc, depth + 1))
        else:
            result.append(argument)
    return result


def split_compile(arguments, msvc):
    sources, output, compile_flags, index = [], None, [], 0
    while index < len(arguments):
        arg = arguments[index]
        lower = arg.lower()
        if arg == "--":
            index += 1
            continue
        if arg.startswith("-flto") or lower.startswith(("/gl", "-gl")) or arg in {"-fmodules", "-include-pch"}:
            raise ValueError("LTO, modules and precompiled headers are unsupported")
        if arg in {"-o", "/Fo", "-Fo"}:
            if output is not None:
                raise ValueError("Multiple compiler outputs")
            output = arguments[index + 1]
            index += 2
            continue
        if msvc and lower.startswith(("/fo", "-fo")):
            output = arg[3:]
            index += 1
            continue
        if lower in {"/c", "-c", "/tp", "-tp", "/showincludes", "-showincludes"}:
            index += 1
            continue
        if Path(arg).suffix.lower() in {".cpp", ".cxx", ".cc"} and not lower.startswith(("/fi", "-include")):
            sources.append(arg)
        else:
            compile_flags.append(arg)
        index += 1
    if len(sources) != 1 or not output:
        raise ValueError("Expected exactly one C++ source and one explicit object output")
    if msvc and any(flag.lower().startswith(("/yc", "/yu", "/clr", "/ifc", "/scan")) for flag in compile_flags):
        raise ValueError("Unsupported clang-cl PCH, CLR, or module scan invocation")
    return sources[0], output, compile_flags


def launch(argv):
    parser = argparse.ArgumentParser()
    for name in ("build", "keys", "opt", "plugin", "level", "protected"):
        parser.add_argument("--" + name, required=name not in {"plugin"}, default="")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise ValueError("Missing compiler command")
    compiler = Path(os.path.abspath(command[0]))
    msvc = "clang-cl" in compiler.name.lower()
    arguments = expand_response(command[1:], msvc)
    source, output, flags = split_compile(arguments, msvc)
    build = Path(args.build)
    identity = hashlib.sha256(str(Path(output).resolve()).encode()).hexdigest()[:24]
    work = build / "private/ir" / identity
    work.mkdir(parents=True, exist_ok=True)
    original, transformed, obfuscated = (work / name for name in ("original.ll", "protected.ll", "obfuscated.ll"))
    # Frontend dependency information is generated here, never from the IR phase.
    if msvc:
        run([compiler, *flags, "/clang:-S", "/clang:-emit-llvm",
             "/clang:-Xclang", "/clang:-disable-llvm-passes", "/showIncludes", "/c", source, "/Fo" + str(original)])
    else:
        run([compiler, *flags, "-S", "-emit-llvm", "-Xclang", "-disable-llvm-passes", source, "-o", original])
    ir = original.read_text(encoding="utf-8")
    rows = []
    if enabled(args.protected):
        keys = load_keys(build / "private/compiler-keys.json")
        demangler = compiler.parent / ("llvm-undname.exe" if msvc else "llvm-cxxfilt")
        if not demangler.exists():
            alternate = shutil.which("llvm-undname" if msvc else "c++filt")
            if not alternate and not (msvc and os.name == "nt"):
                raise ValueError("Install llvm-undname (Windows) or c++filt (Linux) for RTTI selection")
            demangler = Path(alternate) if alternate else None
        ir, rows = transform(ir, keys["master"], demangler, msvc)
    transformed.write_text(ir, encoding="utf-8")
    run([args.opt, "-passes=verify", "-disable-output", transformed])
    current = transformed
    report = dict(schema=1, source=Path(source).name, object=str(Path(output).resolve().relative_to(build.resolve())),
                  abi="msvc" if msvc else "itanium",
                  level=args.level, rtti=rows, xollvm="Not run")
    if args.level != "NONE":
        command = [args.opt]
        if args.plugin:
            command.append("-load-pass-plugin=" + args.plugin)
        report_path = work / "xollvm.json"
        run([*command, "-passes=obfuscation,verify", transformed, "-S", "-o", obfuscated,
             "-obf-seed=20261015", "-obf-deterministic", "-obf-verify", "-obf-ir-budget-max=20000",
             "-obf-report-json=" + str(report_path)])
        if 'obf:' in ir and (not report_path.exists() or obfuscated.read_text() == ir):
            raise ValueError("Annotated translation unit did not produce obfuscation evidence")
        report["xollvm"] = json.loads(report_path.read_text()) if report_path.exists() else "No annotations in translation unit"
        if 'obf:' in ir:
            report["verified_passes"] = validate_obfuscation(report["xollvm"], args.level)
        current = obfuscated
    # Private IR keeps source metadata for development. Release objects do not.
    native = work / "native.ll"
    run([args.opt, "-passes=strip,verify", "-S", current, "-o", native])
    native_ir = native.read_text()
    native_ir = re.sub(r'^source_filename = .*$', 'source_filename = "unit-' + identity + '"', native_ir, flags=re.M)
    native.write_text(native_ir)
    if msvc:
        backend = [flag for flag in flags if re.match(r"^[-/](?:O[012dx]|MDd?$|MTd?$|arch:|fp:)", flag, re.I)]
        run([compiler, *backend, "/c", "/clang:-x", "/clang:ir", native, "/Fo" + output])
    else:
        backend = [flag for flag in flags if re.match(r"^-(?:O|fPIC|fpic|fPIE|fpie|m|pthread|target=|march=|ffast-math|fno-exceptions)", flag)]
        run([compiler, *backend, "-c", "-x", "ir", native, "-o", output])
    write_private(build / "private/maps" / (identity + ".json"), report)
    return 0
