# Independent Skill Operations

This guide is for a downloaded skill directory. None of the commands require
the example project's `tools/`, `src/`, presets or build tree. Substitute the
real skill directory and authorized target paths. Reports can contain original
names and developer paths; keep them private unless reviewed for publication.

## Setup and Capability Boundaries

Use Python 3.10 or newer. The scanner's string/source inventory, environment
inventory and workload measurements use the standard library. Optional packages
add crypto and metadata inspection:

```bash
python -m venv /path/to/private-tool-env
# Invoke that environment's Python below; activation is optional.
python -m pip install -r <skill-directory>/scripts/requirements.txt
python <skill-directory>/scripts/doctor.py
```

Use the environment's actual Python path when it differs from `python`.
Creation/installation is a setup action, not an implicit part of audit-only
work. Missing packages are reported; they must not silently become passed checks.
The requirements file contains dependency ranges, not a reproducible lockfile;
record resolved versions for a release validation environment.

The tool inventory is read-only. To require selected capabilities:

```bash
python <skill-directory>/scripts/doctor.py --require crypto --require elf
python <skill-directory>/scripts/doctor.py \
  --compiler /toolchain/bin/clang++ --opt /toolchain/bin/opt \
  --xollvm --require llvm --require xollvm
```

Windows can supply `clang-cl.exe` and `opt.exe`. A successful capability probe
does not establish compiler provenance, target ABI support, code coverage or
actual obfuscation. Use [integration.md](integration.md) for those decisions.

## Source, Binary and Package Audits

```bash
python <skill-directory>/scripts/audit.py \
  --source /authorized/source \
  --package /authorized/staged-release \
  --deny-file sensitive-corpus.json \
  --function requested_internal_function --variable requested_internal_global \
  --fail-on-deny --fail-on-private --require-metadata \
  --out /private/reports/release-audit
```

The function/variable options are optional and empty by default. The corpus is a
UTF-8 JSON array of nonempty exact strings, for example:

```json
["Private coefficient solve failed", "__internal_policy_flag", "kernel.cpp"]
```

Paths and source basenames are always inventoried. Repeatable `--package`
inventories and scans every regular staged file, including text/resource assets,
and flags suspicious private-file paths. Structured metadata checks apply to
native-looking package members and explicitly selected binaries. Archive/object
formats, PDB contents and compressed debug data are not parsed. Add individual
binary/assets with repeatable `--binary`. Empty packages and symlinks are rejected
rather than silently omitted; review targets explicitly, including legitimate
shared-library aliases, and stage a regular-file inventory for acceptance.

Capture an original-program report before repairs. After rebuilding, add
`--baseline /private/reports/original.json` with a separate `--out`, identical
binary/package ordering, filenames, corpus, allow rules and `--all-strings` mode.
Schema-2 reports fingerprint the scanner and files and list resolved, persistent
and introduced findings independently of offsets. Changed scanner versions,
scope or inventories require a new baseline or separate explicit review, not an
automatic improvement claim. Reports cannot overwrite inputs or enter a scanned
release tree. Keep these files private.

`--all-strings` adds the printable ASCII and ASCII-range UTF-16 inventory to the
JSON/Markdown reports. It is a global readable-string inventory, not a Unicode
language detector, disassembler or process memory scanner. Exact corpus checks
also look for UTF-8/UTF-16 bytes directly, including short or multiline text.
Evidence is bounded to 1024 characters per finding; offsets point to the match.
Original data is not encrypted merely because a report calls it a candidate.

The source scanner is a line-based heuristic, not a C++ parser. It does not
evaluate macros, follow includes, resolve templates or determine an effective
build configuration. Keep an explicit list of source roots and use the target's
compile database and generated headers when planning fixes. Avoid scanning
unrelated vendor/build trees as if they were owned first-party source.

Record intentional public exceptions in an explicit JSON allowlist:

```json
[{"pattern": "^public_engine_create$", "reason": "Versioned public C ABI"}]
```

Allow rules operate on evidence text across categories. Keep patterns narrow,
review each matched finding and check artifact scope; broad exceptions can hide
real leaks. Allowed findings remain in the report with their reason. Do not use
an exception merely to make an acceptance job green.

## Keys and Offline Recovery

```bash
python <skill-directory>/scripts/generate_keys.py --out /private/r17/keys.json
python <skill-directory>/scripts/decode.py \
  --build /private/r17/build --keys /private/r17/keys.json --report warning.log
python <skill-directory>/scripts/decode.py --build /private/r17/build --list-maps
python <skill-directory>/scripts/decode.py --map /private/r17/maps --rtti OPAQUE_TOKEN
```

The generation/decode format is the example's schema 1, not an importer for
arbitrary products. Generation needs PyNaCl. RTTI-only lookup and map inventory
need no crypto library or GUI. Decoding a sealed event requires an explicit
private bundle; there is no implicit production-key search or demo-key fallback.
Follow [key-management.md](key-management.md) before provisioning production.

Supported diagnostic envelopes are `AR1:<key-id>:<base64>` with the example's
sealed JSON fields and positional `{}` templates. The decoder checks the
sealing key, naming master, site and recovered template against the map. It
rejects executable formatting expressions. `--text`, `--report`, `--stdin` and
`--rtti` are mutually exclusive. Mixed text preserves repeated recognized events
and input order. Unsupported or unrecognized logs do not count as success.

`--build` discovers `private/diagnostics.json` and `private/maps/*.json`. Explicit
`--map` accepts supported files or a flat directory of JSON maps. Inventory
shows paths, map kinds and counts. An unrelated JSON file in an explicit map
directory is an error, not a silently accepted codebook. The total map data is
limited to 64 MiB, each map to 16 MiB, input to 8 MiB, maps to 1024 and recognized
events to 4096. Larger deployments need an explicit indexed adapter.

RTTI records support Itanium and MSVC ABI opaque names and their supported
display aliases. They do not require changing the program's RTTI structures.
The original maps have no independent release identity: exact-release selection
is required and global compatibility cannot be inferred from key ID alone.

JSON output goes to stdout by default; use `--output /private/recovered.json`
to create an explicit file without overwriting. Errors print stable codes without
key/ciphertext contents. Partial batch recovery keeps per-event status and fails
the process gate. Empty input, wrong material and unsupported formats are not
silently retried with another key. The CLI never imports a GUI toolkit.
GUI design and stronger format-adapter requirements are documented in
[recovery-tools.md](recovery-tools.md), not claimed as implemented here.

## Target-independent Workload Measurements

After authorized builds and release staging, write a trusted workload manifest:

```json
{
  "schema": 1,
  "profiles": [
    {"name": "baseline", "command": ["./baseline/bin/engine", "test-input.dat"],
     "cwd": ".", "artifacts": ["baseline/bin/engine", "baseline/lib/engine.so"]},
    {"name": "stripped", "command": ["./stripped/bin/engine", "test-input.dat"],
     "artifacts": ["stripped/bin/engine", "stripped/lib/engine.so"]},
    {"name": "protected", "command": ["./protected/bin/engine", "test-input.dat"],
     "artifacts": ["protected/bin/engine", "protected/lib/engine.so"]}
  ]
}
```

```bash
python <skill-directory>/scripts/measure.py --config workloads.json \
  --samples 9 --warmups 2 --timeout 60 --out /private/reports/workloads
```

Commands are argument arrays executed without a shell. Review the manifest:
it is an executable workload specification, not an untrusted log to decode.
Relative `cwd` and artifact paths are anchored to the manifest's directory;
relative command paths follow the selected `cwd`. Use `.exe`/`.dll` for Windows.
Do not put secret arguments in the manifest; commands are recorded in reports.

Reports contain per-profile process wall time (median/min/max/population standard
deviation), sample counts, output hashes and artifact sizes/hashes. Raw program
stdout/stderr is not copied to reports. Use `expected_stdout_sha256` per profile
when stable output has an independently known reference. Nonzero exits, timeouts
and expected-output mismatch fail the profile. Varying output hashes are visible
but are not automatically failures unless a reference hash was specified.

Keep inputs, compiler optimization and dependency configuration equivalent.
Separate clean-build, startup and representative repeated-workload experiments;
a whole-process measurement is not kernel time. A clean-build command can be a
separately labelled profile, but rebuild state must be reset safely between
samples. Do not automatically delete a build tree. Run functional and numerical
tests separately, and compare observed overhead against the user's budget.

## Exit Status and Delivery Contract

| Tool | `0` | `1` | `2` |
| --- | --- | --- | --- |
| Audit | Requested inventory and enabled gates passed | A requested deny/private gate failed | Invalid input/configuration/baseline or required metadata checks incomplete |
| Key generator | New private bundle persisted | Not used | Dependency, destination or write failure |
| Decoder | Inventory or all recognized events recovered | One or more recognized events failed | Setup/input failure or no supported events |
| Doctor | Inventory and requested capability requirements passed | A requested capability is unavailable/unverified | Invalid arguments |
| Measurement | All workloads passed the configured checks | A workload timed out, failed or mismatched reference output | Invalid configuration or unreadable artifacts/commands |

The tools do not rewrite C++ macros, install a compiler, strip files in place,
rename arbitrary binary bytes or perform universal RTTI transformation.
Those are agent-guided, target-specific integration tasks within authorized scope.
Conclude with actual artifact identities, changes made, successful checks,
unperformed platform checks and residual exposure. Do not replace this evidence
with a single "protected" label.
