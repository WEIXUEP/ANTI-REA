#!/usr/bin/env python3
"""Read-only known-corpus search for adjacent little-endian DWORD XOR pairs."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


def constant(value):
    if not value.startswith("u32le:"):
        raise argparse.ArgumentTypeError("Expected u32le:<unsigned integer>")
    try:
        number = int(value.split(":", 1)[1], 0)
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid unsigned integer") from None
    if not 0 <= number <= 0xffffffff:
        raise argparse.ArgumentTypeError("Constant exceeds unsigned 32-bit range")
    return number


def positive(value):
    number = int(value)
    if not 0 < number < sys.maxsize:
        raise argparse.ArgumentTypeError("Limit must be positive and below the platform size bound")
    return number


def snapshot(path, limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Input must be a regular file, not a symlink")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Empty input or input exceeds --max-bytes; no scan performed")
    return data


def probe(data, corpus, max_findings):
    corpus = set(corpus)
    findings = []
    total = max(0, len(data) - 7)
    scanned = 0
    for offset in range(total):
        left, right = struct.unpack_from("<II", data, offset)
        scanned += 1
        value = left ^ right
        if value in corpus:
            findings.append(dict(offset=offset, right_offset=offset + 4,
                                 left=f"0x{left:08x}", right=f"0x{right:08x}",
                                 constant=f"u32le:0x{value:08x}"))
            if len(findings) >= max_findings:
                break
    complete = scanned == total
    return dict(status="incomplete" if not complete else "candidates" if findings else "no-candidates",
                complete=complete, scanned_windows=scanned, total_windows=total,
                findings=findings)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--constant", type=constant, action="append", required=True,
                        help="Repeatable known value; only u32le is supported")
    parser.add_argument("--max-bytes", type=positive, default=64 * 1024 * 1024)
    parser.add_argument("--max-findings", type=positive, default=1000)
    args = parser.parse_args(argv)
    try:
        binary = args.binary.absolute()
        data = snapshot(binary, args.max_bytes)
        digest = hashlib.sha256(data).hexdigest()
        report = probe(data, args.constant, args.max_findings)
        if hashlib.sha256(snapshot(binary, args.max_bytes)).hexdigest() != digest:
            raise ValueError("Input changed during inspection; discard this scan")
        report.update(schema=1, mechanism="adjacent-u32le-xor-known-corpus-v1",
                      binary=str(binary), sha256=digest, size_bytes=len(data),
                      tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      corpus=[f"u32le:0x{value:08x}" for value in sorted(set(args.constant))],
                      limits=dict(max_bytes=args.max_bytes, max_findings=args.max_findings),
                      input_unchanged=True,
                      limitation="Candidates only; no code references, execution or semantic recovery verified")
        print(json.dumps(report, indent=2))
        return 1 if report["findings"] or not report["complete"] else 0
    except (OSError, ValueError) as error:
        print(json.dumps(dict(status="error", error=str(error))), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
