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
                minimum=min(samples), maximum=max(samples), stdev=statistics.pstdev(samples))


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
            row["artifacts"].append(dict(path=str(path), bytes=path.stat().st_size, sha256=digest(path)))
        row["bytes"] = sum(item["bytes"] for item in row["artifacts"])
        prepared.append((profile, cwd, row))
    result = dict(schema=1, platform=platform.platform(), profiles=[],
                  limitations=["Process wall time includes startup and I/O; it is not isolated kernel time.",
                               "Equal output hashes are not a substitute for functional tests.",
                               "Build time must be measured with a separately labelled clean-build command."])
    for profile, cwd, row in prepared:
        durations, outputs, errors = [], set(), set()
        # Spool output to temporary files so a verbose child cannot fill RAM.
        for index in range(warmups + samples):
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                start = time.perf_counter()
                try:
                    completed = subprocess.run(row["command"], cwd=cwd, stdout=stdout, stderr=stderr,
                                               timeout=timeout, check=False)
                except subprocess.TimeoutExpired:
                    row.update(status="failed", reason="timeout")
                    break
                elapsed = time.perf_counter() - start
                if completed.returncode != 0:
                    row.update(status="failed", reason="nonzero_exit", exit_code=completed.returncode)
                    break
                if index >= warmups:
                    durations.append(elapsed)
                    hashes = []
                    for stream in (stdout, stderr):
                        stream.seek(0)
                        value = hashlib.sha256()
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            value.update(chunk)
                        hashes.append(value.hexdigest())
                    outputs.add(hashes[0])
                    errors.add(hashes[1])
        if row["status"] == "passed":
            row.update(wall_seconds=summarize(durations), stdout_sha256=sorted(outputs), stderr_sha256=sorted(errors))
            expected = profile.get("expected_stdout_sha256")
            if expected is not None and outputs != {expected}:
                row.update(status="failed", reason="expected_output_mismatch")
        result["profiles"].append(row)
    return result


def render(report):
    lines = ["# Workload Measurements", "", "| Profile | Status | Bytes | Median (s) | Min / Max (s) |", "| --- | --- | ---: | ---: | --- |"]
    for row in report["profiles"]:
        metric = row.get("wall_seconds")
        timing = (f"{metric['median']:.6f} | {metric['minimum']:.6f} / {metric['maximum']:.6f}"
                  if metric else "- | -")
        name = row["name"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {name} | {row['status']} | {row['bytes']} | {timing} |")
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
        result = measure(config, args.config.resolve().parent, args.samples, args.warmups, args.timeout)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        args.out.with_suffix(".md").write_text(render(result), encoding="utf-8")
        print(json.dumps(dict(profiles=len(result["profiles"]), passed=all(row["status"] == "passed" for row in result["profiles"]))))
        return int(any(row["status"] != "passed" for row in result["profiles"]))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print("Measurement failed: check the trusted config, commands, artifacts and permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
