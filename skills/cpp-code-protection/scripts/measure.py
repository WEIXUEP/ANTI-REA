"""Measure trusted arbitrary workloads without a project-specific demo checkout."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def summarize(samples):
    return dict(samples=len(samples), median=statistics.median(samples),
                minimum=min(samples), maximum=max(samples), stdev=statistics.pstdev(samples),
                p95=sorted(samples)[math.ceil(len(samples) * 0.95) - 1])


def comparison_specs(config, names):
    specifications = config.get("comparisons", [])
    if not isinstance(specifications, list):
        raise ValueError("comparisons must be an array")
    seen = set()
    for specification in specifications:
        if not isinstance(specification, dict) or set(specification) - {
                "reference", "target", "max_slowdown", "max_size_ratio"}:
            raise ValueError("Unknown comparison fields")
        reference, target = specification.get("reference"), specification.get("target")
        if (not isinstance(reference, str) or not isinstance(target, str)
                or reference not in names or target not in names or reference == target):
            raise ValueError("Comparisons need distinct existing reference and target profiles")
        if (reference, target) in seen:
            raise ValueError("Duplicate comparison")
        seen.add((reference, target))
        for key in ("max_slowdown", "max_size_ratio"):
            if key in specification:
                value = specification[key]
                if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                    raise ValueError("Comparison limits must be finite positive numbers")
    return specifications


def compare_profiles(profiles, specifications):
    rows = {row["name"]: row for row in profiles}
    comparisons = []
    for specification in specifications:
        reference, target = (rows[specification[key]] for key in ("reference", "target"))
        result = dict(**specification, status="incomplete", checks={})
        comparisons.append(result)
        if reference["status"] != "passed" or target["status"] != "passed":
            result["reason"] = "profile_failed"
            continue
        before, after = (row["wall_seconds"]["median"] for row in (reference, target))
        if not all(math.isfinite(value) and value > 0 for value in (before, after)):
            result["reason"] = "invalid_timing_reference"
            continue
        result.update(slowdown=after / before, relative_speed_percent=100 * before / after,
                      size_ratio=target["bytes"] / reference["bytes"]
                      if reference["artifacts"] and target["artifacts"] and reference["bytes"] > 0 else None)
        if "max_size_ratio" in specification and result["size_ratio"] is None:
            result["reason"] = "size_reference_unavailable"
            continue
        for limit, metric in (("max_slowdown", "slowdown"), ("max_size_ratio", "size_ratio")):
            if limit in specification:
                result["checks"][limit] = result[metric] <= specification[limit]
        result["status"] = "passed" if all(result["checks"].values()) else "failed"
    return comparisons


def measure(config, base, samples=7, warmups=1, timeout=30):
    if (not isinstance(config, dict) or config.get("schema") != 1
            or not isinstance(config.get("profiles"), list) or not config["profiles"]):
        raise ValueError("Expected schema 1 and a nonempty profiles array")
    if samples < 3 or warmups < 0 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Invalid sampling limits")
    names = set()
    prepared = []
    # Validate all profiles before starting any configured workload.
    for profile in config["profiles"]:
        if not isinstance(profile, dict):
            raise ValueError("Invalid profile")
        name, command = profile.get("name"), profile.get("command")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("Profile names must be nonempty and unique")
        names.add(name)
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command) or not command[0]:
            raise ValueError("Commands must be nonempty argument arrays")
        if not isinstance(profile.get("cwd", "."), str):
            raise ValueError("cwd must be a path string")
        cwd = (base / profile.get("cwd", ".")).resolve()
        if not cwd.is_dir():
            raise ValueError("Working directory does not exist")
        artifacts = profile.get("artifacts", [])
        if not isinstance(artifacts, list) or not all(isinstance(item, str) and item for item in artifacts):
            raise ValueError("Artifacts must be path strings")
        expected = profile.get("expected_stdout_sha256")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)):
            raise ValueError("Invalid reference hash")
        row = dict(name=name, command=command, cwd=str(cwd), status="passed", artifacts=[])
        for artifact in artifacts:
            path = (base / artifact).resolve()
            if str(path) in {item["path"] for item in row["artifacts"]}:
                raise ValueError("Duplicate artifact in profile")
            row["artifacts"].append(dict(path=str(path), bytes=path.stat().st_size, sha256=digest(path)))
        row["bytes"] = sum(item["bytes"] for item in row["artifacts"])
        prepared.append((profile, cwd, row))
    specifications = comparison_specs(config, names)
    result = dict(schema=1, platform=platform.platform(), profiles=[], orders=[],
                  limitations=["Process wall time includes startup and I/O; it is not isolated kernel time.",
                               "Equal output hashes are not a substitute for functional tests.",
                               "Relative speed is reference median / target median; budgets do not measure resistance.",
                               "Artifact hashes are checked before/after; this does not attest all loaded dependencies or memory.",
                               "Build time must be measured with a separately labelled clean-build command."])
    observations = {row["name"]: dict(durations=[], outputs=set(), errors=set()) for _, _, row in prepared}
    for index in range(warmups + samples):
        offset = index % len(prepared)
        order = prepared[offset:] + prepared[:offset]
        result["orders"].append(dict(phase="warmup" if index < warmups else "measured",
                                     profiles=[row["name"] for _, _, row in order if row["status"] == "passed"]))
        for profile, cwd, row in order:
            if row["status"] != "passed":
                continue
            observation = observations[row["name"]]
            # Spool output to temporary files so a verbose child cannot fill RAM.
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                start = time.perf_counter()
                try:
                    completed = subprocess.run(row["command"], cwd=cwd, stdout=stdout, stderr=stderr,
                                               timeout=timeout, check=False)
                except subprocess.TimeoutExpired:
                    row.update(status="failed", reason="timeout")
                    continue
                elapsed = time.perf_counter() - start
                if completed.returncode != 0:
                    row.update(status="failed", reason="nonzero_exit", exit_code=completed.returncode)
                    continue
                hashes = []
                for stream in (stdout, stderr):
                    stream.seek(0)
                    value = hashlib.sha256()
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        value.update(chunk)
                    hashes.append(value.hexdigest())
                expected = profile.get("expected_stdout_sha256")
                if expected is not None and hashes[0] != expected:
                    row.update(status="failed", reason="expected_output_mismatch", observed_stdout_sha256=hashes[0],
                               failed_phase="warmup" if index < warmups else "measured")
                    continue
                if index >= warmups:
                    observation["durations"].append(elapsed)
                    observation["outputs"].add(hashes[0])
                    observation["errors"].add(hashes[1])
    for profile, cwd, row in prepared:
        observation = observations[row["name"]]
        durations = observation["durations"]
        row["wall_samples_seconds"] = durations
        if row["status"] == "passed":
            row.update(wall_seconds=summarize(durations), stdout_sha256=sorted(observation["outputs"]),
                       stderr_sha256=sorted(observation["errors"]))
        for artifact in row["artifacts"]:
            try:
                path = Path(artifact["path"])
                artifact.update(after_sha256=digest(path), after_bytes=path.stat().st_size)
                if artifact["after_sha256"] != artifact["sha256"] or artifact["after_bytes"] != artifact["bytes"]:
                    row.update(status="failed", reason="artifact_changed")
            except OSError:
                row.update(status="failed", reason="artifact_unavailable")
        result["profiles"].append(row)
    result["comparisons"] = compare_profiles(result["profiles"], specifications)
    result["status"] = "passed" if all(row["status"] == "passed"
                                        for row in result["profiles"] + result["comparisons"]) else "failed"
    return result


def render(report):
    lines = ["# Workload Measurements", "", "| Profile | Status | Bytes | Median (s) | Min / Max (s) |", "| --- | --- | ---: | ---: | --- |"]
    for row in report["profiles"]:
        metric = row.get("wall_seconds")
        timing = (f"{metric['median']:.6f} | {metric['minimum']:.6f} / {metric['maximum']:.6f}"
                  if metric else "- | -")
        name = row["name"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {name} | {row['status']} | {row['bytes']} | {timing} |")
    if report["comparisons"]:
        lines.extend(["", "## Comparison Budgets", "",
                      "Relative speed = 100 * reference median / target median; process wall time, not kernel throughput.", "",
                      "| Target / Reference | Status | Slowdown | Relative speed | Size ratio | Limits |",
                      "| --- | --- | ---: | ---: | ---: | --- |"])
        for row in report["comparisons"]:
            label = (row["target"] + " / " + row["reference"]).replace("|", "\\|").replace("\n", " ")
            slowdown = f"{row['slowdown']:.3f}" if "slowdown" in row else "N/A"
            speed = f"{row['relative_speed_percent']:.2f}%" if "relative_speed_percent" in row else "N/A"
            size = f"{row['size_ratio']:.3f}" if row.get("size_ratio") is not None else "N/A"
            limits = ", ".join(f"{key}={row[key]}" for key in ("max_slowdown", "max_size_ratio") if key in row)
            lines.append(f"| {label} | {row['status']} | {slowdown} | {speed} | {size} | {limits or 'None'} |")
    lines.extend(["", "## Limits", ""] + ["- " + item for item in report["limitations"]])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Trusted JSON with command arrays; executes those commands")
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--out", required=True, type=Path, help="Private report prefix")
    args = parser.parse_args(argv)
    if args.samples < 3 or args.warmups < 0 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("Use at least three samples, nonnegative warmups and a positive timeout")
    try:
        config = json.loads(args.config.read_text(encoding="utf-8-sig"))
        base = args.config.resolve().parent
        destinations = {args.out.with_suffix(suffix).resolve() for suffix in (".json", ".md")}
        inputs = {args.config.resolve()}
        if isinstance(config, dict) and isinstance(config.get("profiles"), list):
            for profile in config["profiles"]:
                if isinstance(profile, dict) and isinstance(profile.get("artifacts", []), list):
                    inputs.update((base / path).resolve() for path in profile.get("artifacts", []) if isinstance(path, str))
        if destinations & inputs:
            raise ValueError("Measurement reports must not overwrite inputs")
        result = measure(config, base, args.samples, args.warmups, args.timeout)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        args.out.with_suffix(".md").write_text(render(result), encoding="utf-8")
        print(json.dumps(dict(profiles=len(result["profiles"]), passed=result["status"] == "passed")))
        return int(result["status"] != "passed")
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print("Measurement failed: check the trusted config, commands, artifacts and permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
