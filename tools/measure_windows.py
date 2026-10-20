#!/usr/bin/env python3
"""Measure the Release packages from a completed native Windows demo acceptance."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.compare import expected


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summary(values):
    return dict(samples=len(values), median=statistics.median(values), minimum=min(values),
                maximum=max(values), p95=sorted(values)[math.ceil(len(values) * 0.95) - 1],
                stdev=statistics.pstdev(values))


def prepare(acceptance, output):
    result = json.loads(acceptance.read_text(encoding="utf-8"))
    if result.get("status") != "passed" or result.get("platform") != "win32":
        raise ValueError("A completed native Windows acceptance is required")
    profiles = {}
    for name in ("baseline", "protected"):
        label = "release-" + name
        package = acceptance.parent / "packages" / label
        if output.is_relative_to(package.resolve()):
            raise ValueError("Reports must stay outside release packages")
        accepted = result["configurations"][label]
        if accepted.get("status") != "passed":
            raise ValueError("Release configuration did not pass: " + label)
        artifacts = {}
        for filename, identity in accepted["artifacts"].items():
            path = package / "bin" / filename
            if digest(path) != identity["sha256"]:
                raise ValueError("Accepted artifact changed: " + filename)
            artifacts[filename] = dict(bytes=path.stat().st_size, sha256=identity["sha256"])
        build = acceptance.parent / label
        builds = [row for row in result["commands"] if len(row["argv"]) > 2
                  and row["argv"][1] == "--build"
                  and Path(row["argv"][2]).resolve() == build.resolve()]
        if not builds or builds[0].get("exit_code") != 0 or "wall_seconds" not in builds[0]:
            raise ValueError("Acceptance lacks the initial clean-build timing; run the current validator")
        profiles[name] = dict(executable=str(package / "bin/anti-rea-demo.exe"), artifacts=artifacts,
                              obfuscation=accepted.get("obfuscation", result.get("obfuscation", "NONE") if name == "protected" else "NONE"),
                              core_bytes=sum(row["bytes"] for row in artifacts.values()),
                              package_bytes=sum(p.stat().st_size for p in package.rglob("*") if p.is_file()),
                              build_seconds=builds[0]["wall_seconds"], workloads={})
    return result, profiles


def observe(executable, mode, protected, cwd, reference=None):
    started = time.perf_counter()
    process = subprocess.run([executable, mode, "123"], cwd=cwd, capture_output=True, timeout=30)
    elapsed = time.perf_counter() - started
    if process.returncode != 0:
        raise ValueError("Workload failed: " + mode)
    observed = dict(process_wall_seconds=elapsed)
    if mode in {"startup", "bench"}:
        checksum, inner = process.stdout.decode("ascii").split()
        inner = float(inner)
        if (int(checksum) != reference
                or not math.isfinite(inner) or inner < 0):
            raise ValueError("Independent workload reference mismatch")
        observed.update(inner_seconds=inner, checksum=int(checksum))
    else:
        warning = process.stderr
        if protected:
            if (not re.search(rb"Payload: AR1:[^\s:]+:[A-Za-z0-9+/=]+", warning)
                    or b"preconditioner stalled" in warning or b"<unavailable>" in warning):
                raise ValueError("Protected diagnostic failed")
        elif b"preconditioner stalled after 37 iterations" not in warning:
            raise ValueError("Baseline diagnostic missing")
        observed["stderr_bytes"] = len(warning)
    return observed


def compare_cost(profiles, limits):
    baseline, protected = profiles["baseline"], profiles["protected"]
    metrics = {name: (baseline[name], protected[name]) for name in ("core_bytes", "package_bytes", "build_seconds")}
    for mode, field in (("startup", "process_wall_seconds"), ("bench", "inner_seconds"), ("warning", "process_wall_seconds")):
        metrics[mode] = tuple(profiles[name]["workloads"][mode][field]["median"] for name in ("baseline", "protected"))
    differences = {}
    for name, (before, after) in metrics.items():
        if not all(math.isfinite(value) and value >= 0 for value in (before, after)):
            raise ValueError("Invalid cost metric: " + name)
        differences[name] = dict(delta=after - before, percent=100 * (after - before) / before if before else None,
                                 ratio=after / before if before else None)
        if name in {"startup", "bench", "warning"}:
            if not before or not after:
                differences[name]["ratio"] = None
            differences[name]["relative_speed_percent"] = 100 * before / after if before and after else None
    checks = []
    for name, limit in limits.items():
        if name not in {"startup", "bench", "package_bytes"} or type(limit) not in (int, float) or not math.isfinite(limit) or limit <= 0:
            raise ValueError("Invalid performance budget")
        ratio = differences[name]["ratio"]
        checks.append(dict(metric=name, maximum_ratio=limit, observed_ratio=ratio,
                           status="incomplete" if ratio is None else "passed" if ratio <= limit else "failed"))
    return differences, checks


def render(report):
    lines = ["# Native Windows Protection Cost", "", "| Profile | Build (s) | EXE + DLL bytes | Package bytes | Startup (ms) | Policy loop (ms) | Warning process (ms) |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, row in report["profiles"].items():
        workloads = row["workloads"]
        lines.append(f"| {name} | {row['build_seconds']:.3f} | {row['core_bytes']} | {row['package_bytes']} | "
                     f"{workloads['startup']['process_wall_seconds']['median'] * 1000:.3f} | "
                     f"{workloads['bench']['inner_seconds']['median'] * 1000:.3f} | "
                     f"{workloads['warning']['process_wall_seconds']['median'] * 1000:.3f} |")
    lines.extend(["", "## Process Wall-Time Tails", "",
                  "| Profile | Workload | p95 (ms) | Maximum (ms) |",
                  "| --- | --- | ---: | ---: |"])
    for name, row in report["profiles"].items():
        for mode, workload in row["workloads"].items():
            metric = workload["process_wall_seconds"]
            lines.append(f"| {name} | {mode} | {metric['p95'] * 1000:.3f} | {metric['maximum'] * 1000:.3f} |")
    lines.extend(["", "## Relative Cost and Budgets", "",
                  "Status: " + report["status"], "",
                  "Relative speed = 100 * baseline median / protected median for the same workload.", "",
                  "| Metric | Protected / baseline | Relative speed | Maximum ratio | Gate |",
                  "| --- | ---: | ---: | ---: | --- |"])
    checks = {row["metric"]: row for row in report["budget_checks"]}
    for name, values in report["differences"].items():
        ratio = f"{values['ratio']:.3f}" if values["ratio"] is not None else "N/A"
        speed = f"{values['relative_speed_percent']:.2f}%" if values.get("relative_speed_percent") is not None else "N/A"
        check = checks.get(name)
        limit = str(check["maximum_ratio"]) if check else "None"
        lines.append(f"| {name} | {ratio} | {speed} | {limit} | {check['status'] if check else 'Not requested'} |")
    lines.extend(["", "## Limits", "", *["- " + item for item in report["limitations"]], ""])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path, required=True, help="Private result.json from validate_windows.py")
    parser.add_argument("--samples", type=int, default=31)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--max-bench-slowdown", type=float, help="Maximum protected / baseline inner policy-loop median")
    parser.add_argument("--max-startup-slowdown", type=float, help="Maximum protected / baseline startup process-wall median")
    parser.add_argument("--max-package-ratio", type=float, help="Maximum protected / baseline staged package bytes")
    parser.add_argument("--out", type=Path, required=True, help="New private evidence directory")
    args = parser.parse_args(argv)
    if os.name != "nt" or args.samples < 3 or args.warmups < 0:
        parser.error("Use native Windows, at least three samples and nonnegative warmups")
    limits = {name: value for name, value in (("bench", args.max_bench_slowdown),
              ("startup", args.max_startup_slowdown), ("package_bytes", args.max_package_ratio)) if value is not None}
    if any(not math.isfinite(value) or value <= 0 for value in limits.values()):
        parser.error("Performance budgets must be finite positive ratios")
    output = args.out.resolve()
    try:
        if output.exists():
            raise ValueError("Use a new output directory; retained evidence is never overwritten")
        acceptance = args.acceptance.resolve()
        result, profiles = prepare(acceptance, output)
        output.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(__file__, output / "measure_windows.py")
        report = dict(schema=1, status="running", started=datetime.now(timezone.utc).isoformat(),
                      acceptance_sha256=digest(acceptance), acceptance=str(acceptance),
                      tool_sha256=digest(Path(__file__)), platform=platform.platform(), processor=platform.processor(),
                      compiler=result["compiler"], samples=args.samples, warmups=args.warmups, profiles=profiles, limits=limits,
                      limitations=[
                          "Demo only; protected obfuscation " + profiles["protected"]["obfuscation"] + "; not Palace or whole-application performance.",
                          "Build timing is one initial compile/link observation, excluding configure/tests/install; caches were not flushed.",
                          "Samples alternate profile order; workloads run sequentially, not concurrently with REA.",
                          "Startup/warning include fresh process, loader and I/O costs; warning is not isolated crypto time.",
                          "The policy loop has 500000 iterations; it does not measure RTTI-operation or diagnostic-event throughput.",
                          "Core bytes exclude runtimes; package bytes include the supplied libsodium DLL in both acceptance packages.",
                          "No process CPU-time or memory-peak measurement; medians are local observations, not universal overhead bounds."])

        def save():
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

        save()
        try:
            references = {"startup": expected(123, 1), "bench": expected(123, 500000)}
            for mode in ("startup", "bench", "warning"):
                observations = {name: [] for name in profiles}
                for index in range(args.warmups + args.samples):
                    order = list(profiles) if index % 2 == 0 else list(reversed(profiles))
                    for name in order:
                        observed = observe(profiles[name]["executable"], mode, name == "protected", output,
                                           references.get(mode))
                        if index >= args.warmups:
                            observations[name].append(observed)
                for name, values in observations.items():
                    profiles[name]["workloads"][mode] = dict(
                        process_wall_seconds=summary([row["process_wall_seconds"] for row in values]),
                        observations=values)
                    if mode != "warning":
                        profiles[name]["workloads"][mode]["inner_seconds"] = summary([row["inner_seconds"] for row in values])
                save()
                print(mode + ": completed", flush=True)
            # Preserve the accepted artifact binding across the measurement, too.
            if digest(acceptance) != report["acceptance_sha256"]:
                raise ValueError("Acceptance evidence changed during measurement")
            prepare(acceptance, output)
            report["differences"], report["budget_checks"] = compare_cost(profiles, limits)
            accepted = all(row["status"] == "passed" for row in report["budget_checks"])
            report.update(status="passed" if accepted else "failed", completed=datetime.now(timezone.utc).isoformat())
            save()
            (output / "summary.md").write_text(render(report), encoding="utf-8")
            print(json.dumps(dict(status=report["status"], result=str(output / "result.json"))))
            return 0 if accepted else 1
        except Exception as error:
            report.update(status="failed", error=str(error))
            save()
            raise
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("Windows measurement failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
