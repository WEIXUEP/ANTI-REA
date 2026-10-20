"""Runtime acceptance of a complete configuration, including cross-library RTTI."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from anti_rea.crypto import decode, load_keys
from anti_rea.generate import enabled
from anti_rea.compare import expected


def main():
    parser = argparse.ArgumentParser()
    for name in ("exe", "build", "keys", "protected"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    protected = enabled(args.protected)
    exe = Path(args.exe).resolve()
    checks = 0

    def check(value, message):
        nonlocal checks
        checks += 1
        if not value:
            raise AssertionError(message)

    def run(mode):
        return subprocess.run([str(exe), mode], capture_output=True, text=True, timeout=15)

    result = run("selftest")
    rtti = run("rtti-test")
    check(rtti.returncode == 0 and "\tFAIL\t" not in rtti.stdout and "RESULT\t39\t0" in rtti.stdout,
          "Extended RTTI and exception boundary suite")
    reference = 123
    for _ in range(4096):
        reference = (reference * 1664525 + 1013904223) & 0xffffffff
    check(result.returncode == 0 and result.stdout.strip() == "PASS " + str(reference), "RTTI, exceptions, single evaluation and hot loop")
    for seed in (0, 1, 2, 3, 0xffffffff):
        policy = subprocess.run([str(exe), "startup", str(seed)], capture_output=True, text=True, check=True, timeout=15)
        check(int(policy.stdout.split()[0]) == expected(seed, 1), "Independent policy reference")
    seeds = sorted({0, 0xffffffff, *(1 << bit for bit in range(32)),
                    *((1 << bit) - 1 for bit in range(33))})
    state = 0x341082ab
    for _ in range(1024):
        state = (state * 1664525 + 1013904223) & 0xffffffff
        seeds.append(state)
    evaluated = subprocess.run([str(exe), "policy-eval"], input="\n".join(map(str, seeds)) + "\n",
                               capture_output=True, text=True, check=True, timeout=30)
    pairs = [tuple(map(int, line.split())) for line in evaluated.stdout.splitlines()]
    check(len(pairs) == len(seeds), "Policy evaluation coverage")
    for seed, (dispatch, token) in zip(seeds, pairs):
        check(token == (((seed ^ 0x5a827999) * 33) + (seed >> 7)) & 0xffffffff,
              "Independent token boundary/random reference")
        dispatch_reference = ((seed * 17) ^ 0xa341316c, (seed + 0xc8013ea4) ^ (seed >> 3),
                              (seed ^ 0xad90777d) + (seed << 5), seed * 31 + 0x7e95761e)[seed & 3]
        check(dispatch == dispatch_reference & 0xffffffff, "Independent dispatch boundary/random reference")
    check(run("resource").returncode == 0, "Relative resource lookup")
    warning = run("warning")
    check(warning.returncode == 0, "Warning return behavior")
    check(run("exception").returncode == 3, "Exception exit behavior")
    # Disable core files for the intentional fatal cases.
    if os.name != "nt":
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    check(run("verify").returncode != 0, "Verification remains fatal")
    check(run("assert").returncode != 0, "Assertion remains fatal")
    check("Engine warning" in warning.stderr, "Public severity preserved")
    if protected:
        check("preconditioner" not in warning.stderr, "No plaintext warning")
        token = re.search(r"Payload: (AR1:\S+)", warning.stderr)[1]
        recovered = decode(token, load_keys(args.keys), args.build)
        check(recovered["message"].endswith("37 iterations"), "Message and dynamic data recover")
        check(recovered["path"] == "examples/main.cpp" and recovered["line"] > 0, "Location recovers")
        check("aegis" not in run("rtti").stdout and "print_rtti" not in run("rtti").stdout, "Protected RTTI names")
        for artifact in exe.parent.iterdir():
            if artifact.suffix in {".so", ".dll", ".exe"} or artifact == exe:
                raw = artifact.read_bytes()
                # Unstripped build symbols and build RUNPATH are private, not release gates.
                for secret in (b"Invalid mesh topology", b"Internal constitutive tensor inversion failed", b"preconditioner stalled",
                               b"main.cpp", b"engine.cpp", b"policy.cpp", b"diagnostics.cpp"):
                    check(secret not in raw, "Unexpected " + repr(secret) + " in " + artifact.name)
    else:
        check("preconditioner stalled after 37 iterations" in warning.stderr, "Baseline message visible")
        check("aegis" in run("rtti").stdout, "Baseline RTTI visible")
    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory) / "relocated"
        shutil.copytree(exe.parent, destination)
        relocated = subprocess.run([str(destination / exe.name), "resource"], capture_output=True, text=True, cwd=directory)
        check(relocated.returncode == 0, "Relocation keeps resources usable")
    print(json.dumps(dict(runtime_checks=checks, protected=protected, result="PASS")))


if __name__ == "__main__":
    main()
