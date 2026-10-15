# Windows x64: clang-cl, JOM and Release Auditing

## Status

Windows integration is provided, but a successful Linux run is not Windows
acceptance. This repository's checked-in measurement report identifies the
platform actually executed. Run this procedure on native Windows before claiming
MSVC-ABI correctness for your toolchain and CRT configuration.

## Prerequisites

- An x64 Visual Studio developer environment with Windows SDK and C++ runtime.
- CMake 3.24+, JOM, Python 3.10+ and the requirements in `requirements.txt`.
- clang-cl with matching opt. For xollvm use an LLVM 22/23 static-extension build.
- `llvm-undname.exe` next to the compiler or on PATH.
- libsodium headers, import library and runtime DLL, for example a vcpkg
  `libsodium:x64-windows` installation.

Ordinary `cl.exe` cannot run this LLVM IR protection pipeline. The example does
not claim loadable-pass-plugin support on Windows.

## Build and Test

Run from an x64 developer PowerShell with JOM available:

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

## MSVC RTTI Contract

Itanium `_ZTS` records are not MSVC RTTI records. The Windows transformer recognizes
Clang's x64 `TypeDescriptor` initializer, replaces its name buffer and adjusts the
initializer's array size without changing the runtime fields or references.
Unsupported layouts fail rather than silently leaving only some names protected.

The same HMAC naming domain, key and scope policy must cover every producer and
consumer. The native selftest checks a library-created object, derived and sibling
casts, type equality and a custom exception crossing the DLL boundary. It does
not prove compatibility with arbitrary separately compiled C++ plugin ecosystems.

The launcher handles `--`, `-TP`, `/Fo...`, nested response files and quoted paths.
MSVC runtime settings are preserved across frontend and code-generation phases.
New build modes, modules, PCH, LTO and sanitizer combinations need separate work.

## PE/PDB Release Rules

ELF `strip --strip-all` is not the Windows release procedure. The demo emits
protected native objects without private source-level metadata and asks the linker
to use `/PDBALTPATH:%_PDB%`, so a CodeView reference uses a PDB basename rather than
the developer's directory. PDBs and private IR remain internal and are not installed.

```powershell
python tools/anti_rea.py audit `
  --binary out/windows-jom/bin/anti-rea-demo.exe `
  --binary out/windows-jom/bin/engine.dll `
  --deny "Invalid mesh topology" --deny "ResonantKernel" `
  --fail-on-deny --out build/windows-release-audit
```

Inspect public exports, imports, RTTI candidates, filenames and the CodeView PDB
reference. An import from a system DLL is not an internal algorithm leak. The
scanner inventories PE debug references but does not parse private PDB contents.
Sign release binaries only after final packaging and auditing.

The manual Windows workflow targets a self-hosted Windows x64 runner. The operator
supplies installed toolchain and dependency paths; no CI result is fabricated if
that runner is unavailable.
