# Windows x64: clang-cl, JOM and Release Auditing

English | [简体中文](windows.zh-CN.md)

## Status

Windows integration is provided, but a successful Linux run is not Windows
acceptance. This repository's checked-in measurement report identifies the
platform actually executed. Run this procedure on native Windows before claiming
MSVC-ABI correctness for your toolchain and CRT configuration.

## Prerequisites

The [native validation record](windows-validation.md) reports a completed
Windows x64 demo run, its exact scope and remaining limitations.

- An x64 Visual Studio developer environment with Windows SDK and C++ runtime.
- CMake 3.24+, JOM, Python 3.10+ and the requirements in `requirements.txt`.
- clang-cl with matching opt. For xollvm use an LLVM 22/23 static-extension build.
- `llvm-undname.exe` next to the compiler or on PATH, or the native Windows
  DbgHelp undecorator (used automatically when llvm-undname is unavailable).
- libsodium headers, import library and runtime DLL, for example a vcpkg
  `libsodium:x64-windows` installation.

Ordinary `cl.exe` cannot run this LLVM IR protection pipeline. The example does
not claim loadable-pass-plugin support on Windows.

## Build and Test

For complete demo acceptance, use the native runner from a developer shell:

```powershell
python tools/validate_windows.py `
  --llvm-bin F:/Program_Professional/xollvm-windows-llvm23-Release/bin `
  --environment F:/Intel/oneAPI/setvars.bat `
  --sodium-prefix C:/deps/installed/x64-windows `
  --sodium-runtime C:/deps/installed/x64-windows/bin/libsodium.dll
```

`--environment` is optional in an initialized x64 developer shell. The prefix
must contain `include/sodium.h` and the MSVC import library under `lib`; use
`--sodium-library` for another layout, such as an official libsodium MSVC archive.
Provide the actual DLL name used by that import library. The runtime DLL is copied
into each fresh staged package, rather than masking a missing dependency with PATH.
The default generator is JOM; `--generator Ninja` is also supported. Builds use
eight jobs by default. Dependencies and compilers are supplied by the operator;
the runner does not download or replace them.

Each run creates a unique `build/windows-acceptance/<UTC-run-id>/` directory with
commands, logs, fresh keys, private IR/maps, audit reports, staged packages and
`result.json`. A failure preserves its evidence and exits nonzero. Keep this
directory internal: it deliberately contains keys and baseline original names.

The runner tests Debug/Release with protection OFF/ON and uses
`/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO` in every configuration. It verifies
39 RTTI/exception checks per executable, original binary leakage baselines,
selected-name removal, unrelated names, map recovery, all six EXE/DLL compilation
objects, same-key clean rebuilding, and incremental full key rotation. It checks
CodeView references, internal PDB retention, public exports, private-key absence
and full installed-package contents. It also executes installed resources and
RTTI tests from another working directory.

For an individual build, run from an x64 developer PowerShell with JOM available:


```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

cmake --preset windows-jom `
  -DCMAKE_CXX_COMPILER=C:/tools/xollvm/bin/clang-cl.exe `
  -DANTI_REA_OPT=C:/tools/xollvm/bin/opt.exe `
  -DCMAKE_PREFIX_PATH=C:/deps/installed/x64-windows
cmake --build --preset windows-jom
ctest --test-dir build/windows-jom --output-on-failure
cmake --install build/windows-jom
```

Add the libsodium DLL directory to PATH when testing, or package the required
runtime DLL alongside the program under your deployment policy. Do not distribute
the entire dependency installation or private SDK directories.

For mixed VM use the same generator and paths with
`-DANTI_REA_OBFUSCATION=MIXED_VM`. Use separate build directories for different
protection settings. Never use a Linux archive as a Windows-native toolchain;
that archive is usable inside WSL, not by native JOM.

## Measure Native Protection Cost

After a successful run of the current validator, measure its accepted Release
packages without rebuilding or changing them:

```powershell
python tools/measure_windows.py `
  --acceptance build/windows-acceptance/<run-id>/result.json `
  --samples 31 --warmups 5 --out build/windows-cost/<new-run-id>
```

The tool verifies accepted EXE/DLL hashes before and after measurement, retains
its runner and raw samples in a new private directory, and alternates profile
order. Each process exits before the next begins. It checks policy outputs
against an independent Python reference and checks warning behavior.

Reports separate the initial compile/link observation, EXE/DLL and whole-package
bytes, process startup, the 500,000-iteration policy loop's inner time, and a
fresh process emitting one warning. Warning timing includes loading and I/O;
it is not isolated encryption throughput. Summaries retain median, min/max,
nearest-rank p95 and population standard deviation. Do not run REA concurrently
with sampling or discard slow samples. A repeat needs a new output directory.

This compares protection OFF/ON with xollvm `NONE`, using the same Release
optimization, CRT and `/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO` flags.
There is no claim that a separate ELF-style stripped profile exists on PE.
See [native results](windows-validation.md) for measurements and limitations.

## MSVC RTTI Contract

Itanium `_ZTS` records are not MSVC RTTI records. The Windows transformer recognizes
Clang's x64 `TypeDescriptor` initializer, replaces its name buffer and adjusts the
initializer's array size without changing the runtime fields or references.
Unsupported layouts fail rather than silently leaving only some names protected.

The same HMAC naming domain, key and scope policy must cover every producer and
consumer. The `rtti-test` command checks distinct EXE/DLL descriptors, bidirectional
casts, single/multiple/virtual inheritance, failed pointer/reference casts,
`bad_typeid`, cross-TU equality, hashes, sorting and ordered/unordered lookups.
Exception tests include exact/base and unrelated catches, wrong catch rejection,
rethrow, `exception_ptr`, pointer conversions and const rejection. It does
not prove compatibility with arbitrary separately compiled C++ plugin ecosystems.

The launcher handles `--`, `-TP`, `/Fo...`, nested response files and quoted paths.
MSVC runtime settings are preserved across frontend and code-generation phases.
New build modes, modules, PCH, LTO and sanitizer combinations need separate work.

## PE/PDB Release Rules

ELF `strip --strip-all` is not the Windows release procedure. The demo emits
protected native objects without private source-level metadata and asks the linker
to use `/PDBALTPATH:<target-pdb-basename>`, so a CodeView reference uses a PDB basename rather than
the developer's directory. PDBs and private IR remain internal and are not installed.
The explicit CMake target basename also avoids JOM percent-escaping corrupting
the linker's `%_PDB%` placeholder. Protected PDBs retain linker symbols; the
launcher strips source-level metadata from native objects, so these PDBs do not
provide the same source-debugging information as an unprotected build.

```powershell
python tools/anti_rea.py audit `
  --binary out/windows-jom/bin/anti-rea-demo.exe `
  --binary out/windows-jom/bin/engine.dll `
  --deny "Invalid mesh topology" --deny "ResonantKernel" `
  --require-metadata --fail-on-deny --out build/windows-release-audit
```

Inspect public exports, imports, RTTI candidates, filenames and the CodeView PDB
reference. An import from a system DLL is not an internal algorithm leak. The
scanner inventories PE debug references but does not parse private PDB contents.
Sign release binaries only after final packaging and auditing.

The Windows workflow runs portable tool/scanner/skill tests on a GitHub-hosted
Windows runner for relevant pushes and pull requests. Manual full native
acceptance targets a self-hosted Windows x64 runner; the operator supplies installed
toolchain and dependency paths. Hosted Python success alone is not native ABI
acceptance. Full private native evidence is deliberately not uploaded as a public
workflow artifact.
