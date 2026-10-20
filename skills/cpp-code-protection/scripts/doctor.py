"""Read-only dependency and LLVM capability inventory for independent skill use."""

import argparse
import importlib.util
import json
import platform
import re
import shutil
import subprocess
import sys


def version(tool):
    result = subprocess.run([str(tool), "--version"], capture_output=True,
                            text=True, timeout=15, check=True)
    match = re.search(r"(?:clang|LLVM) version (\d+)", result.stdout + result.stderr, re.I)
    if not match:
        raise ValueError("Unknown LLVM version")
    return int(match[1])


def inventory(compiler=None, opt=None, xollvm=False, plugin=None):
    checks = {}
    for name, module in (("crypto", "nacl"), ("elf", "elftools"), ("pe", "pefile")):
        checks[name] = dict(status="available" if importlib.util.find_spec(module) else "missing")
    tools = {name: shutil.which(name) for name in
             ("cmake", "ninja", "jom", "clang++", "clang-cl", "opt", "llvm-strip", "strip", "llvm-readobj", "readelf")}
    checks["cmake"] = dict(status="available" if tools["cmake"] else "missing")
    checks["llvm"] = dict(status="not_checked", reason="Supply explicit --compiler and --opt")
    checks["xollvm"] = dict(status="not_checked", reason="Request --xollvm to probe the supplied opt")
    if compiler and opt:
        try:
            compiler_major, opt_major = version(compiler), version(opt)
            checks["llvm"] = dict(status="available" if compiler_major == opt_major else "incompatible",
                                  compiler_major=compiler_major, opt_major=opt_major)
            if xollvm:
                if compiler_major != opt_major or compiler_major not in {22, 23}:
                    raise ValueError("The pinned xollvm requires matching LLVM 22/23")
                if platform.system() == "Windows" and plugin:
                    raise ValueError("Use a Windows static-extension toolchain")
                command = [str(opt)]
                if plugin:
                    command.append("-load-pass-plugin=" + str(plugin))
                command += ["-passes=obfuscation,verify", "-disable-output", "-obf-seed=1", "-obf-deterministic"]
                subprocess.run(command, input="; capability check\n", text=True,
                               capture_output=True, check=True, timeout=30)
                checks["xollvm"] = dict(status="available", provenance="Pass probe only; verify toolchain revision separately")
        except (OSError, ValueError, subprocess.SubprocessError):
            if checks["llvm"]["status"] == "not_checked":
                checks["llvm"] = dict(status="failed", reason="Compiler/opt invocation or version check failed")
            if xollvm:
                checks["xollvm"] = dict(status="failed", reason="Version, platform or pass probe failed")
    return dict(schema=1, python=platform.python_version(), platform=platform.platform(),
                checks=checks, tools=tools,
                limitations=["Tool presence is not proof of target integration, supported ABI layouts or Windows execution."])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler")
    parser.add_argument("--opt")
    parser.add_argument("--plugin")
    parser.add_argument("--xollvm", action="store_true")
    parser.add_argument("--require", action="append", default=[], choices=["crypto", "elf", "pe", "cmake", "llvm", "xollvm"])
    args = parser.parse_args(argv)
    if bool(args.compiler) != bool(args.opt) or ((args.xollvm or args.plugin) and not args.opt):
        parser.error("Supply both --compiler and --opt; xollvm/plugin checks require them")
    result = inventory(args.compiler, args.opt, args.xollvm, args.plugin)
    print(json.dumps(result, indent=2))
    return int(any(result["checks"][name]["status"] != "available" for name in args.require))


if __name__ == "__main__":
    raise SystemExit(main())
