# Measurement Method

English | [简体中文](measurement.zh-CN.md)

## Reproduce

### Three-Release Tool

Run from the project root with the Python environment activated:

```bash
# Auto-detect Clang and matching opt; compare exactly three profiles.
python tools/measure.py

# Equivalent dispatcher entry, with explicit options.
python tools/anti_rea.py measure --jobs 8 --samples 15 --out build/three-release

# Use a specific toolchain. Keep the clang++ driver name, not its clang symlink target.
python tools/measure.py --compiler /path/to/llvm/bin/clang++ \
  --opt /path/to/llvm/bin/opt --jobs 8 --samples 9

# Regenerate differences from an existing report, with no compilation or execution.
python tools/measure.py --report-only build/measurement.json --out build/review
```

The default profiles are `baseline`, `stripped`, and `protected`; xollvm is not
required for this three-way comparison. Toolchain detection first checks the local
`build/toolchains/xollvm23/bin/clang++`, then Clang candidates on PATH. The compiler
and optimizer must report matching LLVM major versions. An explicitly requested
toolchain is never silently replaced. This entry point was exercised on Linux;
Windows remains subject to the platform validation steps in the Windows guide.

Defaults: eight build jobs and nine samples per workload. Each run performs clean
builds: it does not compare a cached build against a fresh build. Run it on an idle
machine, and avoid concurrent measurements sharing the same build directories.
Compilation failures, test failures or incomplete comparisons return a nonzero
exit status. Build dependencies are not installed automatically.

Output files, using the default prefix:

| File | Contents |
| --- | --- |
| `build/measurement.md` | Configuration status and measured values |
| `build/measurement.json` | Samples statistics, hashes, audit findings and artifact locations |
| `build/measurement-differences.md` | Readable pairwise absolute and percentage changes |
| `build/measurement-differences.json` | Machine-readable pairwise changes |
| `build/measurement-<profile>.log` | Configure, build, test and installation output |

`--out` is a report **prefix**, not a directory, and relative values are anchored
to the project root even when the script is invoked from elsewhere. Explicit
tool paths and `--report-only` inputs are relative to the caller's working
directory. Existing reports with the same prefix are overwritten. Builds and
installed releases use project-local compiler-specific directories recorded in
the full report.

Differences include release bytes, clean build seconds, median startup process
wall time, median benchmark inner time, and sensitive corpus finding counts.
For each metric, `delta = target - reference` and
`change = 100 * delta / reference`. A zero reference produces `N/A`, not an
invented percentage. The tool compares stripped vs baseline, protected vs baseline,
and protected vs stripped. If any required configuration is missing or unsuccessful,
the difference report is explicitly incomplete and contains no numeric deltas.
The original JSON remains the source of sample ranges and standard deviations.

### Full Matrix

```bash
python tools/anti_rea.py compare \
  --compiler /path/to/xollvm/bin/clang++ \
  --opt /path/to/xollvm/bin/opt --jobs 8 --samples 9 \
  --out build/comparison
```

Add `--publish docs/comparison` to generate a public Markdown summary and compact
JSON without raw audit findings. Full inventories and command logs remain in the
ignored build directory. Review public outputs before release.

Publishing regenerates the English summary. When replacing `docs/comparison.md`,
restore its language link and update `docs/comparison.zh-CN.md` from the same run;
do not combine fresh measurements with an older translation.

The matrix contains baseline, stripped-only, protected-only, light, medium, heavy
and mixed VM. Use `--presets baseline stripped protected` for a smaller run.
Every completed configuration uses the same compiler and RelWithDebInfo / O2.
There is no LTO. The tool uses compiler-specific build/install directories and
records those relative locations in the JSON output.

Each configuration is configured, clean-built, tested and installed. The clean
compile/link wall time is measured once; it excludes configure, tests, installation
and dependency provisioning. It is an observation, not a statistically established
build-performance ranking. OS file caches are not flushed.

## Workloads and Metrics

For native Windows use the accepted-package runner in the
[Windows guide](windows.md). It records a separate OFF/ON measurement rather than
reusing the Linux table, and retains slow samples and dispersion. The existing
Linux three-profile command above is not a substitute for native Windows data.

- `startup`: spawn a fresh process, execute one policy iteration and exit. Process
  wall time includes loader and string-decryption startup overhead.
- `bench`: execute 500,000 selected policy iterations and report the inner elapsed
  time. A separate wall-clock measurement includes process overhead.
- `selftest`: check cross-library RTTI, custom exceptions, exact hot-loop output
  consistency and condition single evaluation.
- `resource`: load the coefficient relative to the executable, including after a
  runtime-directory copy to a different location.
- Installed size: executable plus example shared library; excludes shared system
  runtimes, libsodium and private development artifacts.
- Leakage: substring matches for an explicit sensitive example corpus, plus a
  broader candidate inventory of paths, filenames, symbols and RTTI.

Timing samples report median, minimum, maximum and population standard deviation
in JSON. The Markdown table shows medians. Run on an idle machine, record CPU
policy and repeat for publication-quality performance work. WSL startup timings
are useful local observations, not direct predictions for native Windows.

Unsigned 32-bit arithmetic gives deterministic behavior. The comparison script
computes an independent Python reference rather than merely requiring protected
and baseline binaries to agree with each other. Every benchmark sample must match.

## Artifact Audit

Scan the installed copy, not only the build executable. Source scans flag possible
leakage sites; they do not evaluate C++ preprocessing or prove that a string is
reachable. Binary matches prove matching bytes exist, not why they are present.
Explicit requested-name matches are labeled confirmed; path-like strings remain
candidates until reviewed. Public import/export records can be confirmed and
intentional at the same time.

Function and variable search lists are empty by default. Path scanning is always
enabled. `--allow` accepts a JSON list of `pattern` and nonempty `reason` entries;
allowed findings stay visible rather than disappearing from the report.

```json
[
  {"pattern": "^\\$ORIGIN$", "reason": "Relocatable ELF loader path"},
  {"pattern": "^ar_create$", "reason": "Documented public C factory"}
]
```

The auditor is independently runnable from the skill directory. It scans ASCII,
UTF-16LE and UTF-16BE printable strings. Optional pyelftools and pefile add structured
metadata inspection. Missing parsers and malformed metadata appear in `not_checked`;
they never count as a passed inspection. Compressed strings, arbitrary encodings,
disassembly and complete DWARF/PDB variable enumeration are outside its scope.

## Interpreting Results Honestly

`Passed` means the configuration built, passed its tests and satisfied the declared
sensitive-text release gate. It does not mean zero recognizable strings exist.
`Not run` means a required toolchain/capability was unavailable. `Failed` means an
attempted configuration failed; logs must be investigated, not reclassified as
missing tooling to improve the table.

Private IR, maps and obfuscation reports intentionally retain original names.
Generated JSON measurements and raw logs stay under ignored build directories.
Published summaries redact developer roots. Inspect any selected raw evidence
before adding it to a public repository.
