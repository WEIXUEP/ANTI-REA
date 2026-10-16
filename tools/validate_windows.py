#!/usr/bin/env python3
"""Native Windows acceptance of the demo, launcher and standalone audit skill."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.crypto import generate_keys, load_keys


def require(ok, message):
    if not ok:
        raise ValueError(message)


def environment(batch):
    env = dict(os.environ)
    if batch:
        batch = str(Path(batch).resolve())
        require(Path(batch).is_file() and not any(c in batch for c in '\"%\r\n'), "Invalid environment batch path")
        result = subprocess.run(f'cmd.exe /d /s /c "call "{batch}" intel64 >nul 2>&1 && set"',
                                capture_output=True, check=True)
        env = {key.upper(): value for key, value in env.items()}
        for line in result.stdout.decode("mbcs").splitlines():
            key, sep, value = line.partition("=")
            if key and sep:
                env[key.upper()] = value
    return env


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--environment", help="Optional Intel oneAPI setvars.bat; otherwise use the current x64 developer shell")
    parser.add_argument("--sodium-prefix", type=Path, required=True, help="Prefix containing include/sodium.h")
    parser.add_argument("--sodium-library", type=Path, help="Explicit MSVC import library if not under prefix/lib")
    parser.add_argument("--sodium-runtime", type=Path, help="Runtime DLL copied into each fresh staged package")
    parser.add_argument("--generator", default="NMake Makefiles JOM", choices=["NMake Makefiles JOM", "Ninja"])
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--out", type=Path, help="New evidence directory; never reuse an old acceptance run")
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("Run on native Windows; Linux/WSL cannot establish MSVC runtime correctness")
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
    import pefile
    env = environment(args.environment)
    llvm = args.llvm_bin.resolve()
    env["PATH"] = str(llvm) + os.pathsep + env.get("PATH", "")
    compiler, opt = llvm / "clang-cl.exe", llvm / "opt.exe"
    require(compiler.is_file() and opt.is_file(), "clang-cl.exe and opt.exe are required")
    cmake = shutil.which("cmake", path=env["PATH"])
    ctest = shutil.which("ctest", path=env["PATH"])
    require(cmake and ctest, "CMake and CTest are required in the developer environment")
    require((args.sodium_prefix / "include/sodium.h").is_file(), "Missing libsodium headers")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = (args.out or ROOT / "build/windows-acceptance" / stamp).resolve()
    output.mkdir(parents=True, exist_ok=False)
    evidence = dict(schema=1, status="running", platform=sys.platform, commands=[], configurations={},
                    limitations=["Demo acceptance only; no Palace, numerical dependency, LTO, PCH or arbitrary plugin ABI claim.",
                                 "Protected private PDBs retain linker symbols; source debug metadata is removed by the launcher."])

    def save():
        (output / "result.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    def run(command, cwd=ROOT, expected=0, timeout=300, runtime_env=None):
        command = [str(v) for v in command]
        result = subprocess.run(command, cwd=cwd, env=runtime_env or env, capture_output=True, timeout=timeout)
        log = f"command-{len(evidence['commands']):03d}.log"
        text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        (output / log).write_text(text, encoding="utf-8")
        evidence["commands"].append(dict(argv=command, cwd=str(cwd), exit_code=result.returncode, log=log))
        save()
        require(result.returncode == expected, f"{log}: expected {expected}, got {result.returncode}\n{text[-6000:]}")
        return text

    audit = ROOT / "skills/cpp-leakage-audit/scripts/audit.py"
    private = output / "private"
    private.mkdir()
    keys = private / "keys.json"
    generate_keys(keys)
    initial_keys = load_keys(keys)
    builds, maps, names = {}, {}, {}

    def records(build):
        reports = [json.loads(p.read_text()) for p in (build / "private/maps").glob("*.json")]
        require(len(reports) == 6, "All six target/TU objects must pass through the launcher")
        require({r["source"] for r in reports} == {"engine.cpp", "main.cpp", "policy.cpp", "rtti.cpp", "diagnostics.cpp"},
                "Missing translation-unit coverage")
        require(len({r["object"] for r in reports}) == 6 and all(r["abi"] == "msvc" for r in reports), "Invalid object/ABI coverage")
        result = {}
        for report in reports:
            for row in report["rtti"]:
                previous = result.setdefault(row["original"], row)
                require(previous == row, "Inconsistent names across translation units")
        require(any(r["protected"] for r in result.values()), "No RTTI selected")
        return result

    def configure(build, config, protected):
        flags = "/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO"
        command = [cmake, "-S", ROOT, "-B", build, "-G", args.generator,
                   "-DCMAKE_BUILD_TYPE=" + config, "-DCMAKE_CXX_COMPILER=" + str(compiler),
                   "-DPython3_EXECUTABLE=" + sys.executable, "-DANTI_REA_OPT=" + str(opt),
                   "-DANTI_REA_CODE_PROTECTION=" + ("ON" if protected else "OFF"),
                   "-DANTI_REA_OBFUSCATION=NONE", "-DANTI_REA_KEYS=" + str(keys),
                   "-DCMAKE_PREFIX_PATH=" + str(args.sodium_prefix.resolve())]
        for kind in ("EXE", "SHARED"):
            command.append(f"-DCMAKE_{kind}_LINKER_FLAGS_{config.upper()}={flags}")
        if args.sodium_library:
            command.append("-DSODIUM_LIBRARY=" + str(args.sodium_library.resolve()))
        run(command)

    def build_and_test(build):
        run([cmake, "--build", build, "--parallel", args.jobs])
        if args.sodium_runtime:
            shutil.copy2(args.sodium_runtime, build / "bin" / args.sodium_runtime.name)
        run([ctest, "--test-dir", build, "--output-on-failure"])
        text = run([build / "bin/anti-rea-demo.exe", "rtti-test"])
        require("RESULT\t39\t0" in text and "\tFAIL\t" not in text, "RTTI boundary suite failed")
        return {parts[1]: parts[2:] for line in text.splitlines() if (parts := line.split("\t"))[0] == "TYPE"}

    def stage(build, label, protected, mapping):
        package = output / "packages" / label
        run([cmake, "--install", build, "--prefix", package])
        if args.sodium_runtime:
            shutil.copy2(args.sodium_runtime, package / "bin" / args.sodium_runtime.name)
        # Run the installed package from a different working directory with no
        # dependency prefix added to PATH. Required non-system DLLs must ship.
        runtime_env = dict(env)
        excluded = [str(p.resolve()).lower() for p in (llvm, args.sodium_prefix, output)]
        runtime_env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep)
            if p and not any(str(Path(p).resolve()).lower().startswith(root + os.sep) or str(Path(p).resolve()).lower() == root
                             for root in excluded))
        relocated = output / "relocated" / label
        shutil.copytree(package, relocated)
        run([relocated / "bin/anti-rea-demo.exe", "resource"], cwd=private, runtime_env=runtime_env)
        run([relocated / "bin/anti-rea-demo.exe", "rtti-test"], cwd=private, runtime_env=runtime_env)
        binaries = [package / "bin/anti-rea-demo.exe", package / "bin/engine.dll"]
        fingerprints = {}
        for path in binaries:
            data = path.read_bytes()
            rows = mapping.values() if protected else []
            for row in rows:
                if row["protected"]:
                    require(row["original"].encode() + b"\0" not in data, "Original RTTI remains: " + row["decoded"])
            for field in ("master", "private"):
                for value in (initial_keys[field], load_keys(keys)[field]):
                    require(value.encode() not in data and bytes.fromhex(value) not in data, "Private key in PE")
            pe = pefile.PE(data=data)
            exports = [e.name.decode() for e in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) if e.name]
            if path.name == "engine.dll":
                require(set(exports) == {"ar_create", "ar_destroy", "ar_type", "ar_throw", "ar_compute", "ar_create_kind", "ar_reverse_cast"}, "Unexpected public exports")
            pdbs = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
                if entry.struct.Type == 2:
                    record = data[entry.struct.PointerToRawData:entry.struct.PointerToRawData + entry.struct.SizeOfData]
                    require(record.startswith(b"RSDS"), "Unsupported CodeView record")
                    pdb = record[24:].split(b"\0", 1)[0].decode()
                    require(pdb and "/" not in pdb and "\\" not in pdb and ":" not in pdb, "Developer path in CodeView")
                    pdbs.append(pdb)
                    require(any(build.rglob(pdb)), "Internal PDB missing")
            require(pdbs, "No CodeView/PDB evidence")
            fingerprints[path.name] = dict(sha256=hashlib.sha256(data).hexdigest(), exports=exports, pdb_references=pdbs)
        corpus = ["Invalid mesh topology", "Internal constitutive tensor inversion failed", "preconditioner stalled",
                  ".?AUResonantKernel@internal@aegis@@"]
        common = [sys.executable, audit]
        for binary in binaries:
            common.extend(["--binary", binary])
        for value in corpus:
            common.extend(["--deny", value])
        report = output / (label + "-audit")
        extra = ["--baseline", output / (label.split("-protected")[0] + "-baseline-audit.json"), "--fail-on-deny"] if protected else []
        run([*common, *extra, "--require-metadata", "--out", report])
        original_report = json.loads(report.with_suffix(".json").read_text())
        if not protected:
            require({r["evidence"] for r in original_report["findings"] if r["category"] == "denied-text"} == set(corpus), "Baseline did not detect the known leaks")
        run([sys.executable, audit, "--package", package, "--require-metadata", "--fail-on-deny",
             "--out", output / (label + "-package")])
        return fingerprints

    try:
        evidence["compiler"] = run([compiler, "--version"]).strip()
        evidence["opt"] = run([opt, "--version"]).strip()
        evidence["tools_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (compiler, opt)}
        run([sys.executable, "-m", "unittest", "discover", "-s", ROOT / "tests", "-p", "test_*.py", "-v"])
        for config in ("Debug", "Release"):
            for protected in (False, True):
                label = config.lower() + ("-protected" if protected else "-baseline")
                print(label + ": building and testing", flush=True)
                build = output / label
                configure(build, config, protected)
                builds[label] = build
                names[label] = build_and_test(build)
                mapping = records(build) if protected else {}
                maps[label] = mapping
                if protected:
                    baseline_names = names[label.replace("protected", "baseline")]
                    for name, (raw, pretty) in names[label].items():
                        require((raw != baseline_names[name][0]) == (name not in {"foreign", "foreign_template"}), "Wrong RTTI selection: " + name)
                        if name not in {"foreign", "foreign_template"}:
                            require(any(r["opaque"] == raw and r["protected"] for r in mapping.values()), "Runtime name missing from map")
                    run([sys.executable, ROOT / "tools/anti_rea.py", "decode", "--build", build, "--rtti", names[label]["class"][0]])
                evidence["configurations"][label] = dict(status="passed", rtti_checks=39,
                    artifacts=stage(build, label, protected, mapping), mapped_types=len(mapping))
                save()
        build = builds["release-protected"]
        before = maps["release-protected"]
        run([cmake, "--build", build, "--clean-first", "--parallel", args.jobs])
        require(records(build) == before, "Same-key clean rebuild changed RTTI identifiers")
        evidence["same_key_rebuild"] = "passed"
        map_times = {p.name: p.stat().st_mtime_ns for p in (build / "private/maps").glob("*.json")}
        rotated = private / "rotated.json"
        generate_keys(rotated)
        shutil.copyfile(rotated, keys)
        # Changing the existing key file must trigger CMake regeneration and all
        # object rebuilds without requiring --clean-first from the operator.
        build_and_test(build)
        after = records(build)
        refreshed = {p.name: p.stat().st_mtime_ns for p in (build / "private/maps").glob("*.json")}
        require(map_times.keys() == refreshed.keys() and all(refreshed[name] > time for name, time in map_times.items()),
                "Key rotation did not rebuild every EXE/DLL compilation object")
        require(set(before) == set(after), "Key rotation changed RTTI coverage")
        for raw, row in before.items():
            require((row["opaque"] != after[raw]["opaque"]) == row["protected"], "Partial or ineffective key rotation")
        evidence["rotated_release"] = stage(build, "release-protected-rotated", True, after)
        evidence["key_rotation"] = "passed"
        evidence["key_rotation_recompiled_objects"] = len(refreshed)
        evidence["status"] = "passed"
        save()
        print(json.dumps(dict(status="passed", result=str(output / "result.json"))))
        return 0
    except Exception as error:
        evidence["status"] = "failed"
        evidence["error"] = str(error)
        save()
        raise


if __name__ == "__main__":
    raise SystemExit(main())
