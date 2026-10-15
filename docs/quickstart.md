# Quickstart

Run commands from the checked-out repository root. The example is a small
computational engine, not a protection SDK that automatically rewrites another
application.

## Linux Prerequisites

- CMake 3.24+, Ninja and Python 3.10+.
- Clang and a matching LLVM `opt` for protected builds. LLVM 18 supports the
  basic protection pipeline; xollvm requires a separately installed LLVM 22/23
  toolchain.
- `llvm-cxxfilt` next to the compiler, or GNU `c++filt` on PATH.
- libsodium headers and library, such as Debian/Ubuntu's `libsodium-dev` package.

For native Windows, follow the [clang-cl and JOM guide](windows.md) instead.
The project does not download a toolchain or replace a system compiler.

## Prepare Python

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Build the Protected Release

Replace the compiler path with your installed LLVM toolchain:

```bash
cmake --preset protected -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
cmake --build --preset protected
ctest --test-dir build/protected --output-on-failure
cmake --install build/protected

out/protected/bin/anti-rea-demo selftest
out/protected/bin/anti-rea-demo resource
out/protected/bin/anti-rea-demo warning
```

The build preset uses eight jobs. The protected release includes information
protection and installed ELF symbol stripping, but no xollvm obfuscation by
default. Build artifacts and recovery maps stay private under `build/protected`;
the installed runtime copy is under `out/protected`.

!!! note "Existing CMake caches"
    A changed default does not overwrite cached values. Use a new build directory
    or explicitly set both protection and stripping options to `ON`.

`warning` emits a sealed payload. Use [offline recovery](diagnostics.md#example)
to decode it with the matching keys and build map. The `verify` and `assert`
commands intentionally abort; `exception` intentionally exits with status 3.
Run these only in a safe test environment.

## Compare Three Versions

```bash
python tools/measure.py --compiler /path/to/llvm/bin/clang++ --jobs 8 --samples 9
```

The script builds, tests, installs and audits baseline, stripped-only and
protected releases. It writes measurements to `build/measurement.md` and
`build/measurement.json`, with pairwise changes in
`build/measurement-differences.md` and `.json`.

The compiler may be omitted when the tool can discover a suitable local
Clang/opt pair. See [measurement options and caveats](measurement.md) for
report-only operation, sample statistics and the full obfuscation matrix.

## Use Private Deployment Keys

```bash
python tools/anti_rea.py keys --out .private/keys.json
cmake --preset protected -DANTI_REA_KEYS="$PWD/.private/keys.json" \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
cmake --build --preset protected
ctest --test-dir build/protected --output-on-failure
```

The default `demo-keys/keys.json` is intentionally public. Do not use it for
confidential deployments. Archive real keys and release-specific private maps
internally; neither belongs in the installed package, a public repository or
this documentation site.

## Continue

- [Leakage scenarios](scenarios.md): inspect each channel and its mitigation.
- [Build integration](integration.md): adapt the mechanisms to another project.
- [xollvm](xollvm.md): select functions and verify actual transformations.
- [Audit skill](audit-skill.md): inspect another project's source and artifacts.
