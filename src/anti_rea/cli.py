"""Command dispatch shared by the project entry script."""
import argparse
import json
from pathlib import Path
import runpy
import sys
from .crypto import decode, generate_keys, load_keys
from .generate import enabled, generate
from .launcher import doctor, launch


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    root = Path(__file__).resolve().parents[2]
    if argv[:1] == ["launch"]:
        return launch(argv[1:])
    if argv[:1] == ["audit"]:
        script = root / "skills/cpp-leakage-audit/scripts/audit.py"
        return runpy.run_path(str(script))["main"](argv[1:])
    if argv[:1] == ["compare"]:
        from .compare import compare
        return compare(argv[1:])
    if argv[:1] == ["measure"]:
        from .measurement import main as measure
        return measure(argv[1:])
    parser = argparse.ArgumentParser(description="ANTI-REA build, recovery and audit tools")
    sub = parser.add_subparsers(dest="command", required=True)
    keys = sub.add_parser("keys", help="Generate private deployment keys, never overwrite")
    keys.add_argument("--out", default=str(root / ".private/keys.json"))
    generator = sub.add_parser("generate", help="Internal CMake catalog generation")
    for name in ("root", "build", "keys", "protected"):
        generator.add_argument("--" + name, required=True)
    generator.add_argument("--constants", default="ON")
    check = sub.add_parser("doctor", help="Check compiler/opt and optional xollvm capability")
    for name in ("compiler", "opt"):
        check.add_argument("--" + name, required=True)
    check.add_argument("--level", choices=["NONE", "LIGHT", "MEDIUM", "HEAVY", "MIXED_VM"], default="NONE")
    check.add_argument("--plugin", default="")
    decoder = sub.add_parser("decode", help="Recover a sealed payload or an RTTI name")
    decoder.add_argument("--keys", default=str(root / "demo-keys/keys.json"))
    decoder.add_argument("--build", required=True)
    decoder.add_argument("--token")
    decoder.add_argument("--rtti")
    args = parser.parse_args(argv)
    try:
        if args.command == "keys":
            result = generate_keys(args.out)
        elif args.command == "generate":
            result = generate(args.root, args.build, args.keys, enabled(args.protected), enabled(args.constants))
        elif args.command == "doctor":
            result = doctor(args.compiler, args.opt, args.level, args.plugin)
        elif args.token:
            result = decode(args.token, load_keys(args.keys), args.build)
        elif args.rtti:
            query = args.rtti.removeprefix("class ").removeprefix("struct ")
            result = [row for path in (Path(args.build) / "private/maps").glob("*.json")
                      for row in json.loads(path.read_text()).get("rtti", [])
                      if query in {row["opaque"], row["opaque"].removeprefix("65"), row["opaque"].removeprefix(".?AV").removesuffix("@@")}]
            if not result:
                raise ValueError("RTTI name not found in this build's maps")
        else:
            parser.error("decode requires --token or --rtti")
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, KeyError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 2
