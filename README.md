# ANTI-REA

A reproducible C++ information-leakage laboratory: observe what a native binary
reveals, apply narrowly scoped protections, and measure what actually changes.

**Protection is not a promise that a program cannot be reverse engineered.**
This project distinguishes four different tools: diagnostic confidentiality,
opaque RTTI names, release-symbol hygiene, and code obfuscation.

## What You Can Reproduce

- Plaintext diagnostics versus public-key-encrypted warnings and offline recovery.
- Source paths, filenames, conditions and function signatures in ordinary builds.
- RTTI name replacement without disabling `dynamic_cast`, `typeid` or exceptions.
- Symbol stripping versus runtime strings: stripping alone does not remove both.
- Relocatable, aliased resource paths and private build artifacts.
- xollvm light, medium, heavy and mixed-function VM configurations.
- A portable source/binary auditor and an installable audit-and-repair skill.

The example is a small generic computational engine, not a real solver. Its
integer workload makes exact correctness comparisons easy and excludes numerical
hot loops from obfuscation. No large numerical dependency is needed.

## Quick Start: Linux

Prerequisites: CMake 3.24+, Ninja, Python 3.10+, a C++20 compiler, and libsodium
development files. Protected builds require Clang and matching `opt` and
`llvm-cxxfilt` next to the compiler. LLVM 18 works for protection without xollvm;
xollvm requires a separately installed LLVM 22/23 toolchain.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt

cmake --preset baseline -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
cmake --build --preset baseline
ctest --test-dir build/baseline --output-on-failure

cmake --preset protected -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
cmake --build --preset protected
ctest --test-dir build/protected --output-on-failure
cmake --install build/protected
```

On Debian/Ubuntu, `libsodium-dev` provides the native encryption dependency.
Activate the Python environment before configuring CMake, or explicitly set
`-DPython3_EXECUTABLE=/path/to/.venv/bin/python`.

```bash
build/baseline/bin/anti-rea-demo warning
build/protected/bin/anti-rea-demo warning
build/protected/bin/anti-rea-demo selftest
out/protected/bin/anti-rea-demo resource
```

`verify` and `assert` intentionally terminate the process; `exception` exits with
status 3. Other commands are `rtti`, `location`, `startup` and `bench`.

## Switches and Comparison

```bash
# Master switch; use a separate build directory when changing protection.
cmake -S . -B build/custom -DANTI_REA_CODE_PROTECTION=ON \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++

# Complete matrix; unavailable xollvm configurations are reported as Not run.
python tools/anti_rea.py compare --compiler /path/to/llvm/bin/clang++ --jobs 8

# One-command baseline / stripped-only / protected measurement (8 jobs by default).
python tools/measure.py
```

Fresh custom configurations default to `ANTI_REA_CODE_PROTECTION=ON` and
`ANTI_REA_STRIP_RELEASE=ON`, with `ANTI_REA_OBFUSCATION=NONE`. Baseline information
protection and release stripping are enabled together; function obfuscation and
VM remain explicit choices. The `baseline` and `stripped` comparison presets
explicitly disable information protection. Existing CMake caches retain their
saved values: use a new build directory or explicitly set both options to `ON`.

`measure.py` discovers the local `build/toolchains/xollvm23` compiler first, then
checks Clang/opt pairs on PATH. Override with `--compiler` and `--opt` if needed.
It clean-builds and tests all three releases, audits installed artifacts, and
writes full measurements plus absolute/percentage differences to
`build/measurement*.md` and `.json`. See [measurement options](docs/measurement.md).

All comparison presets use RelWithDebInfo / O2. The installed `stripped` and
`protected` ELF binaries are stripped; the original build artifacts remain
private. The [measured comparison](docs/comparison.md) records what was actually
run, including missing configurations rather than invented measurements.

`ANTI_REA_OBFUSCATION=NONE|LIGHT|MEDIUM|HEAVY|MIXED_VM` selects obfuscation separately
from information protection. See [xollvm integration](docs/xollvm.md) before
enabling it. This project does not download or replace a compiler automatically.

## Decrypt an Example Warning

The warning prints `Payload: AR1:<key-id>:<base64>`. Pass the complete token:

```bash
python tools/anti_rea.py decode --build build/protected --token 'AR1:...:...'
python tools/anti_rea.py decode --build build/protected --rtti '65R...'
```

The default key is **PUBLIC DEMO KEYS - NOT SECRET**. Anyone can decrypt the
example. Real deployments must generate their own keys:

```bash
python tools/anti_rea.py keys --out .private/keys.json
cmake --preset protected -DANTI_REA_KEYS="$PWD/.private/keys.json" \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
```

Archive the matching keys and `build/<preset>/private/` by release. Do not ship
them. See [diagnostics and recovery](docs/diagnostics.md).

## Audit Your Own Project

```bash
python tools/anti_rea.py audit --source examples \
  --binary out/protected/bin/anti-rea-demo \
  --binary out/protected/bin/libengine.so --out build/audit

# Explicit names are optional; paths are always scanned.
python tools/anti_rea.py audit --binary /path/to/program \
  --function SensitiveFunction --variable internal_budget \
  --deny 'Confidential error text' --fail-on-deny --out build/target-audit
```

Use the self-contained [cpp-leakage-audit skill](skills/cpp-leakage-audit/SKILL.md)
for an evidence-based audit and authorized repairs. Copy its directory into your
agent's skill directory; it has no dependency on this repository's Python package.
The project does not install the skill globally by itself.

For authorized protection work, the skill defaults to a **stripped and
information-protected release**, not maximum obfuscation. It adapts diagnostic,
path and RTTI protections to the target, then selects function-level obfuscation or VM by implementation value,
call frequency and performance requirements. Hot paths remain unchanged unless
measurements justify the cost. Audit-only requests remain read-only. The
three-release measurement tool still compares baseline, stripped and protected;
its comparison profiles do not prescribe a production protection policy.

## Reading Guide

| Document | Purpose |
| --- | --- |
| [Threat model](docs/threat-model.md) | What the protections do and do not protect |
| [Scenario catalog](docs/scenarios.md) | Reproduce each leak and understand its mitigation |
| [Diagnostics](docs/diagnostics.md) | Encryption, keys, maps and recovery |
| [Integration](docs/integration.md) | Build pipeline and adapting another project |
| [xollvm](docs/xollvm.md) | Toolchains, levels, reports and performance limits |
| [Windows](docs/windows.md) | clang-cl, JOM, PE and PDB handling |
| [Measurements](docs/measurement.md) | Comparison methodology and interpretation |
| [Results](docs/comparison.md) | Sanitized measured results |
| [Remaining exposure](docs/remaining-exposure.md) | What an analyst can still identify and why |

## Layout and License

`examples/` contains C++, `tools/` contains the Python entry point, `src/anti_rea/`
contains implementation, and `skills/` contains the standalone auditor. Generated
headers, private LLVM IR, maps and measurements stay in ignored build directories.

Original example code is MIT licensed. xollvm is an external project under
Apache-2.0 WITH LLVM-exception; see [NOTICE](NOTICE). No third-party toolchain,
private production key or upstream application source is bundled here.
