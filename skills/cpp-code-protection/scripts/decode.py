"""Offline headless decoder; no checkout, GUI, network or implicit key creation."""

import argparse
import json
import os
from pathlib import Path
import sys

from _recovery import MAX_INPUT, RecoveryError, decode_text, decode_symbol, identity, load_key, load_maps


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, help="Example-compatible build root")
    parser.add_argument("--map", action="append", default=[], help="Explicit supported map or flat map directory")
    parser.add_argument("--keys", type=Path, help="Explicit private version-1 bundle; no demo fallback")
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--text", help="Protected token or mixed log text")
    inputs.add_argument("--report", type=Path, help="UTF-8 log file")
    inputs.add_argument("--stdin", action="store_true")
    inputs.add_argument("--rtti", help="Opaque RTTI token, optionally demangled")
    inputs.add_argument("--symbol", help="Exact decoy function label from a private map")
    inputs.add_argument("--list-maps", action="store_true", help="Inspect loading inventory without decoding")
    parser.add_argument("--output", type=Path, help="Explicit private JSON output; never overwrite")
    args = parser.parse_args(argv)
    if not args.list_maps and args.text is None and args.report is None and not args.stdin and args.rtti is None and args.symbol is None:
        parser.error("Select --text, --report, --stdin, --rtti, --symbol or --list-maps")
    try:
        books, inventory = load_maps(args.build, args.map)
        key = load_key(args.keys) if args.keys else None
        result = dict(schema=1, maps=inventory, key_id=identity(key) if key else None,
                      limitations=["Version-1 maps have no independent release identity; select the exact release explicitly.",
                                   "Sealed boxes do not authenticate the sender."])
        code = 0
        if not args.list_maps:
            if args.report:
                with args.report.open("rb") as stream:
                    raw = stream.read(MAX_INPUT + 1)
                if len(raw) > MAX_INPUT:
                    raise RecoveryError("input_too_large")
                text = raw.decode("utf-8-sig")
            elif args.stdin:
                text = sys.stdin.read(MAX_INPUT + 1)
            else:
                text = args.rtti if args.rtti is not None else args.text
            result["results"] = ([dict(index=0, offset=0, status="recovered", **decode_symbol(args.symbol, books))]
                                 if args.symbol is not None else decode_text(text, key, books, args.rtti is not None))
            code = int(any(row["status"] != "recovered" for row in result["results"]))
        content = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        return code
    except ImportError:
        print("Decode failed: crypto_dependency_missing; install PyNaCl in the selected environment.", file=sys.stderr)
    except RecoveryError as error:
        print("Decode failed: " + error.code, file=sys.stderr)
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        print("Decode failed: invalid_or_unreadable_input; check paths, schema and permissions.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
