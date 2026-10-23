# Python Protection and Recovery

English | [简体中文](python-protection.zh-CN.md)

The independent Windows Python case tests protection before describing it as a
skill capability. It has no Palace dependency and does not change the C++ builds.
See [measured results](python-results.md) for observed recovery and costs.

## Six Profiles

The same owned package contains an integer mixer, classes and errors, nested
imports, two dynamically selected plugins and a separate JSON model resource.
Its entry accepts one JSON request per stdin line and returns an `answer` and
`elapsed_ns`. Inputs use `values`, optional `seed` and `plugin`; the private
benchmark mode also returns `answer.transform_ns`.

Compare source, source-free legacy pyc, PyInstaller onefile, case-only AES-GCM
memory loading, PyArmor official trial and Nuitka standalone. Bytecode,
compression, authenticated encryption and native compilation are distinct
mechanisms. None is presented as unrecoverable encryption.

## Reproduce on Windows

Use CPython 3.12 x64 and a new private run directory outside the checkout:

```powershell
python -m venv F:/tmp/anti-rea-python/env
& F:/tmp/anti-rea-python/env/Scripts/python.exe -m pip install --index-url https://pypi.org/simple --report F:/tmp/anti-rea-python/install-report.json -r cases/python-protection/requirements.txt
& F:/tmp/anti-rea-python/env/Scripts/python.exe tools/validate_python_windows.py --out F:/tmp/anti-rea-python/new-run --llvm-bin F:/Program_Professional/xollvm-windows-llvm23-Release/bin --environment F:/Intel/oneAPI/setvars.bat --jobs 8
```

Run from the repository. Dependencies are pinned; the installation report records
download sources and distribution hashes. The current tested interpreter is
CPython 3.12.14. Intel setvars initializes the MSVC/SDK environment; its
`compiler/latest/bin/compiler` also supplies lld-link, which is absent from the
tested xollvm bin directory. The native compiler was clang-cl 23.1.2, linker LLD
19.0.0; this is a recorded combination, not a same-version LLVM toolchain claim.
No xollvm obfuscation pass is enabled by this case.

`all` runs build, behavior, bounded analysis and measurement. Retained commands,
source hashes, per-file package hashes, reports and private inputs are in the run
directory. Separate `--phase` options allow diagnosis without rebuilding, but
build/verify outputs must be fresh. Use `--phase analyze --analysis-label
analysis-r2` for a new analysis revision of unchanged packages.

The automatic phases do not invent recovered algorithms. After reviewing release
disassembly, independently write a candidate and record its evidence hashes in a
private recovery manifest; `--phase recover --recovery-manifest <file>` runs the
candidate against retained private cases. Candidate commands are trusted code,
not a sandbox. Never call the original protected function and call that a rewrite.

## Evidence and Limits

Each profile has a 15-minute maximum analysis budget, separate from build time.
Static scanners do not execute targets. Trusted runtime observations explicitly
use `--execute`, with process deadlines; code dumping is experimental and is
not used on protected PyArmor code after a recorded crash. Unknown inputs need
appropriate process isolation; the standard-library parsers are not a sandbox.

The analyst knew the case design. Release-input isolation excluded original
source, build output and private key files from recovery commands, but was not an
independent blind test. A frozen reconstruction was then compared with 256
fixed-seed random cases and nine boundary/error cases.

The AES demo deliberately ships its key in runtime material. It authenticates
before loading and rejects wrong keys, header/tag changes and truncation. Its
key and plaintext are recoverable; authentication rejection does not imply key
secrecy. Resource/plugin loading covers only the case's fixed source loader.

Private run directories contain keys, decrypted source, code captures and raw
reports. Do not publish them or copy them into staged release packages. The
offline HTML presents actual leakage locations with file filters, search,
offset/line or code-object context, baseline comparisons and explicit gaps.
Browser file-URL policy blocked automated visual preview in this run; HTML
escaping and report isolation were tested, but screenshot acceptance is pending.

## Independent Skills

- [Python Code Protection](python-protection-skill/index.md): baseline, tool choice, integration and countertests; includes a dependency doctor.
- [Python Leakage Audit](python-audit-skill/index.md): standalone static scanner, bounded archive extraction, trusted runtime observation and private HTML evidence.
- [Protection ZIP](downloads/python-code-protection.zip) and [Audit ZIP](downloads/python-leakage-audit.zip) contain reviewed public files only.

The protection ZIP is integration guidance, not the case packer or a universal
Python rewriter. The audit ZIP needs no REA, compiler or optional Python package
for its static commands. Native REA analysis uses an existing configured backend.
