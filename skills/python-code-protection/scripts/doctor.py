"""Report Python protection tool availability without installing or building."""
import argparse
import importlib.metadata
import json
from pathlib import Path
import platform
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require", action="append", choices=("cryptography", "pyinstaller", "nuitka", "pyarmor"), default=[])
    parser.add_argument("--llvm-bin", type=Path)
    args = parser.parse_args()
    checks = {}
    for name in ("cryptography", "pyinstaller", "nuitka", "pyarmor"):
        try:
            checks[name] = dict(status="installed", version=importlib.metadata.version(name))
        except importlib.metadata.PackageNotFoundError:
            checks[name] = dict(status="missing")
    if args.llvm_bin:
        checks["clang-cl"] = dict(status="present" if (args.llvm_bin / "clang-cl.exe").is_file() else "missing",
                                  note="File presence only; does not establish compiler/linker readiness.")
    print(json.dumps(dict(python=sys.version, executable=sys.executable, platform=platform.platform(), checks=checks), indent=2))
    return int(any(checks[name]["status"] != "installed" for name in args.require))


if __name__ == "__main__":
    raise SystemExit(main())
