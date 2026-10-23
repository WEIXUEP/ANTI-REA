# Operations

## Environment

The helper uses Python 3.10+ standard libraries; the verified native case uses
Windows x64 CPython 3.12.14. Discover the target's actual interpreter before
choosing tools or decoding bytecode.

```powershell
python <skill>/scripts/doctor.py
python <skill>/scripts/doctor.py --require cryptography --require nuitka --llvm-bin <llvm-bin>
```

Exit 0 means requested distributions are installed; exit 1 means a required
distribution is missing. Installed packages or a compiler file do not prove a
working runtime, supported license or successful compilation. `--help` works
without optional dependencies. Install selected tools in an isolated environment
only when installation is within the requested work; pin observed versions and
keep pip's installation report privately.

## Target Integration

For PyInstaller, explicitly include dynamic modules and data that static import
discovery cannot infer. For example, with a reviewed application entry:

```powershell
python -m PyInstaller --onefile --name app --hidden-import <plugin-module> --add-data "<resource-dir>;<destination>" <entry.py>
python -m pyarmor.cli gen -r -O <new-output> <entry.py> <package-dir>
python -m nuitka --standalone --clang --msvc=latest --jobs=8 --include-package=<package> --include-data-dir=<resources>=<destination> <entry.py>
```

These are integration patterns, not universally sufficient build commands. Match
the pinned tool's options, license and target layout. Build outside original
inputs; review any tool downloads. Nuitka's Windows clang mode needs `lld-link`
as well as clang-cl, MSVC libraries and the Windows SDK. The tested xollvm bin
directory lacked lld-link; Intel oneAPI's `compiler/latest/bin/compiler` supplied
it through a process-local PATH. No xollvm obfuscation passes were enabled.

## Reproduce the Repository Case

The source checkout, not the skill ZIP, supplies the fixture and validator:

```powershell
python -m venv <private-env>
& <private-env>/Scripts/python.exe -m pip install --index-url https://pypi.org/simple --report <private-install-report.json> -r cases/python-protection/requirements.txt
& <private-env>/Scripts/python.exe tools/validate_python_windows.py --out <new-private-run> --llvm-bin <llvm-bin> --environment <oneAPI-setvars.bat> --jobs 8
```

Run from the checkout with Python 3.12 on Windows. `all` builds, checks behavior,
performs bounded analysis and measures; it does not claim automatic semantic
reconstruction. Use separate `--phase build|verify|analyze|measure` only with the
appropriate fresh or retained phase outputs. Verify/analyze outputs are new,
not silently overwritten. Use a new run directory for an implementation change.

For a reviewed independently created reconstruction, `--phase recover
--recovery-manifest <file>` verifies release/analysis evidence hashes and compares
its JSON-line output against retained private cases. The manifest has a
`profiles` object whose entries carry `kind`, a command argv array, and `evidence`
entries containing absolute `path` and `sha256`. Commands are trusted executable
inputs, not a sandbox. The reconstruction must not import or call the protected
application. Retain the reviewed implementation and its input provenance.

The AES example deliberately ships local decryption material. Wrong-key and
tamper rejection demonstrate authentication, not key secrecy. The validator's
release-only countertest extracts its source with the shipped material.
