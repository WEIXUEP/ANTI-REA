#!/usr/bin/env python3
"""Build and accept the independent Windows CNG resource/cache case (no Palace)."""
import argparse
import csv
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SENSITIVE = ["ConfidentialResourceModel_27ce194f", "SensitiveCoefficientSet_78eb2a91", "PrivateWeightTable_ac91b620"]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def developer_environment(batch):
    env = dict(os.environ)
    if batch:
        batch = str(Path(batch).resolve())
        if not Path(batch).is_file() or any(c in batch for c in '\"%\r\n'):
            raise ValueError("Invalid environment batch path")
        result = subprocess.run(f'cmd.exe /d /s /c "call "{batch}" intel64 >nul 2>&1 && set"', capture_output=True, check=True)
        env = {key.upper(): value for key, value in env.items()}
        for line in result.stdout.decode("mbcs").splitlines():
            key, separator, value = line.partition("=")
            if key and separator:
                env[key.upper()] = value
    return env


def expected_hash(bias=7, scale=3, weights=(2, 5, 11, 17), option=1):
    """Independent source-grounded uint32 arithmetic, serialized explicitly LE."""
    output = bytearray()
    for index in range(32768):
        value = index + bias + option * scale
        for step in range(128):
            value = ((value * 1664525 + 1013904223 + weights[(index + step) % 4]) & 0xffffffff) ^ (value >> 13)
        output.extend(struct.pack("<I", value))
    return hashlib.sha256(output).hexdigest()


def serialize(entries):
    body = bytearray(struct.pack("<I", len(entries)))
    for name, content in entries:
        name = name.encode("ascii")
        body.extend(struct.pack("<I", len(name)) + name + struct.pack("<I", len(content)) + content)
    return bytes(body)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--environment", help="Optional Intel oneAPI setvars.bat; otherwise use the current x64 developer environment")
    parser.add_argument("--generator", choices=["NMake Makefiles JOM", "Ninja"], default="NMake Makefiles JOM")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("Native Windows is required")
    if args.jobs < 1 or args.samples < 3:
        parser.error("Use at least one job and three timing samples")
    env = developer_environment(args.environment)
    compiler = args.llvm_bin.resolve() / "clang-cl.exe"
    if not compiler.is_file():
        parser.error("Missing clang-cl.exe")
    env["PATH"] = str(compiler.parent) + os.pathsep + env.get("PATH", "")
    cmake = shutil.which("cmake", path=env["PATH"])
    if not cmake:
        parser.error("CMake is required in the developer environment")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = (args.out or ROOT / "build/resource-acceptance" / stamp).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    shutil.copytree(ROOT / "cases/runtime-resources", source)
    shutil.copyfile(__file__, output / "validate_resources_windows.py")
    private = output / "private"
    private.mkdir()
    working = output / "unrelated-cwd"
    working.mkdir()
    key_file = private / "resource-key.state"
    report = dict(schema=1, status="running", platform=sys.platform, commands=[], checks=[], profiles={},
                  source_sha256={str(p.relative_to(source)): digest(p) for p in source.rglob("*") if p.is_file()},
                  compiler_sha256=digest(compiler), limitations=[
                      "Windows CNG case only; not a universal resource transformer or a Palace acceptance.",
                      "Embedded AES key is recoverable; GCM is not publisher authentication against key extraction.",
                      "Cache is non-executable numeric data with corruption hashes, not malicious-writer authentication.",
                      "No compression, remote key service, arbitrary dependency parser or complete memory-erasure claim.",
                      "Nonce state must remain with the active key; rollback/copying active state can reuse nonces.",
                      "Timings are case observations, not application budgets or proof of performance improvement."])

    def save():
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    def check(name, condition, **details):
        report["checks"].append(dict(name=name, passed=bool(condition), **details))
        save()
        if not condition:
            raise ValueError("Acceptance failed: " + name)

    def run(command, expected=0, cwd=working, timeout=300):
        command = [str(item) for item in command]
        started = time.perf_counter()
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=timeout)
        wall = time.perf_counter() - started
        log = f"command-{len(report['commands']):03d}.log"
        text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        (output / log).write_text(text, encoding="utf-8")
        report["commands"].append(dict(argv=command, cwd=str(cwd), exit_code=result.returncode, wall_seconds=wall, log=log))
        save()
        if result.returncode != expected:
            raise ValueError(f"{log}: expected {expected}, got {result.returncode}\n{text[-6000:]}")
        return text

    def configure(build, config, protected):
        run([cmake, "-S", source, "-B", build, "-G", args.generator,
             "-DCMAKE_BUILD_TYPE=" + config, "-DCMAKE_CXX_COMPILER=" + str(compiler),
             "-DAR_ENCRYPT_RESOURCES=" + ("ON" if protected else "OFF"), "-DAR_RESOURCE_KEY_FILE=" + str(key_file)])

    def build(build_dir, target=None):
        command = [cmake, "--build", build_dir, "--parallel", args.jobs]
        if target:
            command.extend(["--target", target])
        return run(command)

    reference = expected_hash()
    option_reference = expected_hash(option=2)
    audit = ROOT / "skills/cpp-leakage-audit/scripts/audit.py"
    corpus = private / "corpus.json"
    corpus.write_text(json.dumps(SENSITIVE), encoding="utf-8")
    packages = {}
    builds = {}
    cache_roots = {}

    def consume(exe, cache, *extra, expected=0, oracle=reference):
        text = run([exe, "--cache-dir", cache, *extra], expected=expected)
        if expected:
            check("rejection emits no result or selected plaintext", '"sha256"' not in text and
                  all(value not in text for value in SENSITIVE))
            return text
        value = json.loads(text)
        check("independent numerical oracle", value["sha256"] == oracle)
        return value

    try:
        run([compiler, "--version"])
        for config in ("Debug", "Release"):
            for protected in (False, True):
                role = config.lower() + ("-protected" if protected else "-baseline")
                directory = output / role
                configure(directory, config, protected)
                build(directory)
                packer = directory / "bin/resource-packer.exe"
                test = json.loads(run([packer, "selftest"]))
                check(role + " CNG known vector", set(test) == {"known_vector", "roundtrip", "wrong_key_rejected", "aad_rejected"} and all(test.values()))
                if not key_file.exists():
                    run([packer, "keygen", key_file])
                    before = key_file.read_bytes()
                    run([packer, "keygen", key_file], expected=2)
                    check("exclusive key creation", key_file.read_bytes() == before)
                package = output / "packages" / role
                run([cmake, "--install", directory, "--prefix", package])
                exe = package / "bin/resource-demo.exe"
                cache = output / "caches" / role
                cold = consume(exe, cache)
                warm = consume(exe, cache)
                disabled = consume(exe, cache, "--no-cache")
                changed = consume(exe, cache, "--option", "2", oracle=option_reference)
                check(role + " process reuse and option invalidation", cold["cache"] == "miss" and cold["stored"] and
                      warm["cache"] == "hit" and not warm["stored"] and disabled["cache"] == "disabled" and
                      changed["cache"] == "miss" and changed["cache_key"] != warm["cache_key"])
                scan = output / (role + "-audit")
                run([sys.executable, audit, "--package", package, "--deny-file", corpus, "--require-metadata",
                     "--fail-on-deny", "--out", scan], expected=0 if protected else 1)
                raw = json.loads(scan.with_suffix(".json").read_text(encoding="utf-8"))
                matches = [row for row in raw["findings"] if row["category"] == "denied-text"]
                check(role + " baseline/release sensitive corpus", not matches if protected else len(matches) >= 3)
                files = {p.relative_to(package).as_posix(): digest(p) for p in package.rglob("*") if p.is_file()}
                check(role + " package isolation", set(files) == {"bin/resource-demo.exe"} if protected else
                      set(files) == {"bin/resource-demo.exe", *{"bin/resources/" + p.relative_to(source / "resources").as_posix()
                                                               for p in (source / "resources").rglob("*") if p.is_file()}})
                report["profiles"][role] = dict(package_sha256=files, cold=cold, warm=warm, disabled=disabled,
                                                option=changed, audit=str(scan.with_suffix(".html")))
                if protected:
                    embedded = exe.read_bytes().find(key_file.read_bytes()[4:36])
                    check(role + " embedded resource key is recoverable material", embedded >= 0, key_file_offset=embedded)
                packages[role], builds[role], cache_roots[role] = package, directory, cache

        role = "release-protected"
        directory, package, cache = builds[role], packages[role], cache_roots[role]
        exe = package / "bin/resource-demo.exe"
        packer = directory / "bin/resource-packer.exe"
        bundle_file = directory / "private/resources.arc"
        original_bundle = bundle_file.read_bytes()
        entries = [(p.relative_to(source / "resources").as_posix(), p.read_bytes())
                   for p in sorted((source / "resources").rglob("*")) if p.is_file()]
        plaintext = serialize(entries)
        raw_input = private / "manifest.bin"
        raw_input.write_bytes(plaintext)
        damaged_state = private / "damaged-key.state"
        state = bytearray(key_file.read_bytes()); state[-1] ^= 1; damaged_state.write_bytes(state)
        rejected_bundle = private / "must-not-exist.arc"
        run([packer, "seal", raw_input, damaged_state, rejected_bundle], expected=2)
        check("corrupt nonce state is rejected without healing", damaged_state.read_bytes() == state and not rejected_bundle.exists())
        missing_state = private / "missing.state"
        run([packer, "seal", raw_input, missing_state, rejected_bundle], expected=2)
        check("missing key does not regenerate", not missing_state.exists() and not rejected_bundle.exists())
        exhausted_state = private / "exhausted.state"
        state = bytearray(key_file.read_bytes()); state[40:48] = struct.pack("<Q", 1 << 20)
        state[48:80] = hashlib.sha256(state[:48]).digest(); exhausted_state.write_bytes(state)
        run([packer, "seal", raw_input, exhausted_state, rejected_bundle], expected=2)
        check("nonce counter cannot wrap", exhausted_state.read_bytes() == state and not rejected_bundle.exists())
        warm = consume(exe, cache)
        mutations = {"ciphertext": (64, 1), "tag": (len(original_bundle) - 1, 1), "nonce-aad": (16, 1),
                     "key-id": (32, 1), "version": (8, 2), "length": (28, 1)}
        for name, (offset, mask) in mutations.items():
            corrupted = bytearray(original_bundle)
            corrupted[offset] ^= mask
            path = private / (name + ".arc")
            path.write_bytes(corrupted)
            consume(exe, cache, "--bundle", path, expected=2)
            check(name + " rejected with warm cache", True)
        truncated = private / "truncated.arc"
        truncated.write_bytes(original_bundle[:50])
        consume(exe, cache, "--bundle", truncated, expected=2)
        other_key = private / "other-key.state"
        run([packer, "keygen", other_key])
        wrong_bundle = private / "wrong-key.arc"
        run([packer, "seal", raw_input, other_key, wrong_bundle])
        consume(exe, cache, "--bundle", wrong_bundle, expected=2)

        malformed = {
            "empty-count": struct.pack("<I", 0),
            "huge-count": struct.pack("<I", 129),
            "duplicate": serialize([entries[0], entries[0]]),
            "oversized-name": struct.pack("<II", 1, 201),
            "oversized-content": struct.pack("<II", 1, 1) + b"a" + struct.pack("<I", 1024 * 1024 + 1),
            "trailing": plaintext + b"extra",
            "truncated-manifest": plaintext[:-1],
            "traversal": serialize([("../escape.txt", b"data")]),
            "unsupported-include": serialize([(n, c.replace(b"include nested/coefficients.txt", b"include ../escape.txt")) for n, c in entries]),
        }
        for name, content in malformed.items():
            raw_input.write_bytes(content)
            path = private / (name + ".arc")
            run([packer, "seal", raw_input, key_file, path])
            consume(exe, cache, "--bundle", path, expected=2)
            check("authenticated " + name + " rejected", True)
        raw_input.write_bytes(plaintext)

        # Concurrent packers reserve different nonces in the same persistent key state.
        concurrent_bundles = [private / f"parallel-{index}.arc" for index in range(6)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda path: subprocess.run([str(packer), "seal", str(raw_input), str(key_file), str(path)],
                                cwd=working, env=env, capture_output=True, timeout=30), concurrent_bundles))
        check("concurrent packers succeed", all(result.returncode == 0 for result in results))
        nonces = [path.read_bytes()[16:28] for path in concurrent_bundles]
        check("concurrent nonce uniqueness", len(set(nonces)) == 6 and original_bundle[16:28] not in nonces)
        report["concurrent_bundles"] = {str(path.relative_to(output)): digest(path) for path in concurrent_bundles}
        for path in concurrent_bundles:
            value = consume(exe, cache, "--bundle", path)
            check("randomness independent semantic cache", value["cache"] == "hit" and value["cache_key"] == warm["cache_key"])

        cache_file = cache / (warm["cache_key"] + ".cache")
        forged_payload = bytes(32768 * 4)
        forged = bytearray(cache_file.read_bytes())
        forged[40:72] = hashlib.sha256(forged_payload).digest()
        forged[76:] = forged_payload
        cache_file.write_bytes(forged)
        accepted_forgery = json.loads(run([exe, "--cache-dir", cache]))
        check("unkeyed cache hash does not authenticate malicious replacements",
              accepted_forgery["cache"] == "hit" and accepted_forgery["sha256"] == hashlib.sha256(forged_payload).hexdigest()
              and accepted_forgery["sha256"] != reference)
        corrupt = bytearray(cache_file.read_bytes()); corrupt[-1] ^= 1; cache_file.write_bytes(corrupt)
        repaired = consume(exe, cache)
        check("corrupt cache recomputed and replaced", repaired["cache"] == "miss" and repaired["stored"])
        check("repaired cache reusable", consume(exe, cache)["cache"] == "hit")
        blocked = private / "not-a-directory"
        blocked.write_text("blocked", encoding="ascii")
        check("unwritable/unusable cache fallback", consume(exe, blocked)["cache"] == "unavailable")
        denied = private / "denied-cache"
        denied.mkdir()
        user = run(["whoami", "/user", "/fo", "csv", "/nh"])
        sid = next(csv.reader(user.strip().splitlines()))[-1]
        check("current token SID identified", sid.startswith("S-1-"))
        run(["icacls", denied, "/deny", f"*{sid}:(OI)(CI)(W)"])
        try:
            check("permission-denied cache recomputes", consume(exe, denied)["cache"] == "unavailable")
        finally:
            run(["icacls", denied, "/remove:d", "*" + sid])
        check("denied cache did not publish data", not list(denied.iterdir()))
        disabled_cache = private / "disabled-cache"
        consume(exe, disabled_cache, "--no-cache")
        check("disabled cache does not create directories", not disabled_cache.exists())
        previous_appdata = env.get("LOCALAPPDATA")
        env["LOCALAPPDATA"] = str(private / "localappdata")
        try:
            default_cold = json.loads(run([exe]))
            default_warm = json.loads(run([exe]))
            check("default user-scoped cache", default_cold["sha256"] == reference and default_cold["cache"] == "miss" and
                  default_warm["sha256"] == reference and default_warm["cache"] == "hit" and
                  len(list((private / "localappdata/ANTI-REA/resource-demo/v1").glob("*.cache"))) == 1)
        finally:
            if previous_appdata is None:
                env.pop("LOCALAPPDATA", None)
            else:
                env["LOCALAPPDATA"] = previous_appdata
        parallel_cache = output / "caches/parallel"
        parallel_cache.mkdir()
        (parallel_cache / ".resource-interrupted.tmp").write_bytes(b"partial")
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: subprocess.run([str(exe), "--cache-dir", str(parallel_cache)], cwd=working,
                                              env=env, capture_output=True, timeout=60), range(6)))
        check("concurrent consumers agree", all(r.returncode == 0 and json.loads(r.stdout)["sha256"] == reference for r in results))
        report["concurrent_consumers"] = [json.loads(result.stdout) for result in results]
        check("concurrent cache published and reusable", consume(exe, parallel_cache)["cache"] == "hit")
        check("interrupted temp ignored", (parallel_cache / ".resource-interrupted.tmp").read_bytes() == b"partial")

        # Mutations affect only the archived case copy; original sources remain untouched.
        weights_file = source / "resources/nested/weights.txt"
        original_weights = weights_file.read_bytes()
        weights_file.write_bytes(original_weights.replace(b"2 5 11 17", b"2 5 11 19"))
        previous_bundle = digest(bundle_file)
        build(directory)
        changed = consume(directory / "bin/resource-demo.exe", cache, oracle=expected_hash(weights=(2, 5, 11, 19)))
        check("nested dependency incremental invalidation", changed["cache"] == "miss" and digest(bundle_file) != previous_bundle)
        build(directory, "clean"); build(directory)
        rebuilt = consume(directory / "bin/resource-demo.exe", cache, oracle=expected_hash(weights=(2, 5, 11, 19)))
        check("incremental equals clean build", rebuilt["cache"] == "hit" and rebuilt["cache_key"] == changed["cache_key"])
        weights_file.write_bytes(original_weights)
        build(directory)
        base_value = consume(directory / "bin/resource-demo.exe", cache)
        extra = source / "resources/extra.txt"
        extra.write_text("unused resource inventory revision", encoding="ascii")
        build(directory)
        added = consume(directory / "bin/resource-demo.exe", cache)
        check("resource addition invalidates", added["cache_key"] != base_value["cache_key"] and added["cache"] == "miss")
        renamed = source / "resources/renamed.txt"
        extra.rename(renamed)
        build(directory)
        moved = consume(directory / "bin/resource-demo.exe", cache)
        check("resource rename invalidates", moved["cache_key"] != added["cache_key"])
        renamed.unlink()
        build(directory)
        removed = consume(directory / "bin/resource-demo.exe", cache)
        check("resource deletion returns original semantics", removed["cache_key"] == base_value["cache_key"])
        before_rotation = digest(bundle_file)
        rotated = private / "rotated.state"
        run([packer, "keygen", rotated])
        shutil.copyfile(key_file, private / "archived-key-state.DO-NOT-USE")
        os.replace(rotated, key_file)
        build(directory)
        rotation = consume(directory / "bin/resource-demo.exe", cache)
        check("same-path key rotation repackages", digest(bundle_file) != before_rotation)
        check("authenticated numeric cache survives key rotation", rotation["cache_key"] == base_value["cache_key"] and rotation["cache"] == "hit")
        before_noop = digest(bundle_file)
        build(directory)
        check("no-change build does not reencrypt", digest(bundle_file) == before_noop)

        external = output / "external-inputs"
        shutil.copytree(source / "resources", external)
        (external / "nested/weights.txt").write_bytes(original_weights.replace(b"2 5 11 17", b"2 5 11 19"))
        chosen = consume(directory / "bin/resource-demo.exe", cache, "--external-dir", external,
                         oracle=expected_hash(weights=(2, 5, 11, 19)))
        check("explicit external input precedence", chosen["external"])
        consume(directory / "bin/resource-demo.exe", cache, "--external-dir", external, "--bundle", truncated, expected=2)

        # Re-stage after key rotation; old and current packages remain separate evidence.
        latest_package = output / "packages/release-rotated"
        run([cmake, "--install", directory, "--prefix", latest_package])
        latest_exe = latest_package / "bin/resource-demo.exe"
        check("rotated installed output", consume(latest_exe, cache)["cache"] == "hit")
        final_audit = output / "release-rotated-audit"
        run([sys.executable, audit, "--package", latest_package, "--deny-file", corpus,
             "--require-metadata", "--fail-on-deny", "--out", final_audit])
        final_files = {p.relative_to(latest_package).as_posix(): digest(p) for p in latest_package.rglob("*") if p.is_file()}
        check("rotated package contains only the consumer", set(final_files) == {"bin/resource-demo.exe"})
        report["profiles"]["release-rotated"] = dict(package_sha256=final_files, audit=str(final_audit.with_suffix(".html")))
        relocated = output / "relocated-package"
        shutil.copytree(latest_package, relocated)
        check("installed package relocates independently", consume(relocated / "bin/resource-demo.exe", cache)["cache"] == "hit")
        snapshot = {str(p.relative_to(output / "caches")): digest(p) for p in (output / "caches").rglob("*") if p.is_file()}
        check("cache has no selected original labels", all(all(s.encode() not in p.read_bytes() for s in SENSITIVE)
              for p in (output / "caches").rglob("*") if p.is_file()))
        report["cache_sha256"] = snapshot
        # Alternating order limits timing-order bias; correctness remains independently gated.
        timings = {"cold": [], "warm": [], "disabled": []}
        for sample in range(args.samples):
            order = ("cold", "warm", "disabled") if sample % 2 == 0 else ("disabled", "cold", "warm")
            sample_cache = output / "timing" / str(sample)
            for mode in order:
                value = consume(exe, sample_cache, *( ["--no-cache"] if mode == "disabled" else [] ))
                elapsed = report["commands"][-1]["wall_seconds"]
                check("timing cache state", value["cache"] == {"cold": "miss", "warm": "hit", "disabled": "disabled"}[mode])
                timings[mode].append(dict(process_seconds=elapsed, program_ms=value["total_ms"], derive_ms=value["derive_ms"]))
        report["timings"] = {mode: dict(samples=rows, median_program_ms=statistics.median(r["program_ms"] for r in rows),
                                       median_process_seconds=statistics.median(r["process_seconds"] for r in rows),
                                       median_derive_ms=statistics.median(r["derive_ms"] for r in rows)) for mode, rows in timings.items()}
        cache_audit = output / "all-caches-audit"
        run([sys.executable, audit, "--package", output / "caches", "--package", output / "timing",
             "--package", private / "localappdata", "--deny-file", corpus, "--fail-on-deny", "--out", cache_audit])
        check("all default, override and timing caches scanned", True)
        check("selected resource labels are absent from command logs",
              all(all(value not in path.read_text(encoding="utf-8") for value in SENSITIVE) for path in output.glob("command-*.log")))
        report["cache_audit"] = str(cache_audit.with_suffix(".html"))
        report["outcomes"] = dict(runtime_correctness="passed", selected_release_content_hiding="passed",
                                  embedded_key_secrecy="not_provided; known key bytes located in EXE",
                                  hostile_cache_writer_authentication="not_provided; forgery accepted in countertest",
                                  performance="observed; no application budget declared")
        report["status"] = "passed"
        save()
        print(json.dumps(dict(status="passed", checks=len(report["checks"]), evidence=str(output))))
        return 0
    except Exception as error:
        report["status"], report["error"] = "failed", str(error)
        save()
        raise


if __name__ == "__main__":
    raise SystemExit(main())
