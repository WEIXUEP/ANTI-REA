# Independent Protection Operations

This guide is for a downloaded skill directory. None of the commands require
the example project's `tools/`, `src/`, presets or build tree. Substitute the
real skill directory and authorized target paths. Reports can contain original
names and developer paths; keep them private unless reviewed for publication.

## Setup and Capability Boundaries

Use Python 3.10 or newer. Environment inventory and workload measurement use
the standard library. PyNaCl adds key generation and sealed-event recovery:

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
python <skill-directory>/scripts/doctor.py --require crypto
python <skill-directory>/scripts/doctor.py \
  --compiler /toolchain/bin/clang++ --opt /toolchain/bin/opt \
  --xollvm --require llvm --require xollvm
```

Windows can supply `clang-cl.exe` and `opt.exe`. A successful capability probe
does not establish compiler provenance, target ABI support, code coverage or
actual obfuscation. Use [integration.md](integration.md) for those decisions.

For encrypted runtime resources and persistent derived results, read
[runtime-resources.md](runtime-resources.md). That mode is integration guidance:
none of the downloaded scripts packs/decrypts resources or implements a cache.
The source checkout's separate Windows case has its own packer and validator. The key
generator emits diagnostic/naming material only; `doctor.py --require crypto`
checks PyNaCl availability, not an AES-GCM provider or resource integration.

## Audit Evidence at the Integration Boundary

This skill contains no scanner. Preserve the target's original audit report or
collect a private baseline with available target/native tooling. For ELF, inspect
symbols, debug records, RPATH/RUNPATH and strings with matching native tools.
For PE, inspect exports, CodeView references, RTTI strings and package contents
using available PE tools. Exact checks need both ASCII/UTF-8 and UTF-16 evidence.
Record tool versions, file hashes, a known-leaking positive control and the same
sensitive corpus before/after. Tools not available leave explicit unchecked
channels; a plain string search is not a complete structured binary audit.

The separate cpp-leakage-audit skill can automate these observations when
available, but is not an installation dependency. Do not call a nonexistent
local `scripts/audit.py`. Reject improvement claims when original evidence is
missing or file/corpus scope changed without review.

## Keys and Offline Recovery

```bash
python <skill-directory>/scripts/generate_keys.py --out /private/r17/keys.json
python <skill-directory>/scripts/decode.py \
  --build /private/r17/build --keys /private/r17/keys.json --report warning.log
python <skill-directory>/scripts/decode.py --build /private/r17/build --list-maps
python <skill-directory>/scripts/decode.py --map /private/r17/maps --rtti OPAQUE_TOKEN
python <skill-directory>/scripts/decode.py --map /private/r17/maps --symbol FUNCTION_ALIAS
```

The generation/decode format is the example's schema 1, not an importer for
arbitrary products. Generation needs PyNaCl. RTTI/symbol lookup and map inventory
need no crypto library or GUI. Decoding a sealed event requires an explicit
private bundle; there is no implicit production-key search or demo-key fallback.
Follow [key-management.md](key-management.md) before provisioning production.

Supported diagnostic envelopes are `AR1:<key-id>:<base64>` with the example's
sealed JSON fields and positional `{}` templates. The decoder checks the
sealing key, naming master, site and recovered template against the map. It
rejects executable formatting expressions. `--text`, `--report`, `--stdin`,
`--rtti` and `--symbol` are mutually exclusive input choices. Mixed text preserves repeated recognized events
and input order. Unsupported or unrecognized logs do not count as success.
`--symbol` performs exact private-map lookup of a common-word function alias;
it does not guess semantics from the replacement name.

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
  ],
  "comparisons": [
    {"reference": "baseline", "target": "protected", "max_slowdown": 1.25, "max_size_ratio": 2.0}
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

Reports contain per-profile raw process wall times, median/min/max/p95/population
standard deviation, sample counts, output hashes and artifact sizes/hashes. Profile
order rotates between rounds. Declared artifact hashes and sizes are rechecked
after all measurements; changed or missing files fail the profile. Raw program
stdout/stderr is not copied to reports. Use `expected_stdout_sha256` per profile
when stable output has an independently known reference. Nonzero exits, timeouts
and expected-output mismatch, including warmups, fail the profile. Varying output hashes are visible
but are not automatically failures unless a reference hash was specified.

`comparisons` is optional; omitted limits impose no implicit performance policy.
Each pair names distinct existing profiles. Limits must be finite positive
ratios; unknown fields and invalid references are rejected before any command
runs. `slowdown = target median / reference median` and
`relative_speed_percent = 100 * reference median / target median`, so 2x time
means 50% relative speed, while 1.25x time means 80%. The example limits are
illustrations, not default budgets. A size gate needs declared artifacts in both
profiles and a positive reference size. Failed profiles and unavailable
references make comparisons incomplete, never passing. Exceeded limits return
exit 1 even when every workload exits successfully. Reports retain the limits,
observed ratios and each check. Output files cannot overwrite the manifest or
declared artifacts. Keep each run's output prefix separate to preserve evidence.

Keep inputs, compiler optimization and dependency configuration equivalent.
Separate clean-build, startup and representative repeated-workload experiments;
a whole-process measurement is not kernel time. A clean-build command can be a
separately labelled profile, but rebuild state must be reset safely between
samples. Do not declare expected-to-change build outputs as immutable artifacts
in a clean-build experiment. Do not automatically delete a build tree. Run functional and numerical
tests separately, and compare observed overhead against the user's budget.

## Exit Status and Delivery Contract

| Tool | `0` | `1` | `2` |
| --- | --- | --- | --- |
| Key generator | New private bundle persisted | Not used | Dependency, destination or write failure |
| Decoder | Inventory or all recognized events recovered | One or more recognized events failed | Setup/input failure or no supported events |
| Doctor | Inventory and requested capability requirements passed | A requested capability is unavailable/unverified | Invalid arguments |
| Measurement | Workloads and requested comparisons passed | Workload/output/integrity failure, exceeded budget or incomplete comparison | Invalid configuration or unreadable artifacts/commands |

The tools do not rewrite C++ macros, install a compiler, strip files in place,
rename arbitrary binary bytes or perform universal RTTI transformation.
Those are agent-guided, target-specific integration tasks within authorized scope.
Conclude with actual artifact identities, changes made, successful checks,
unperformed platform checks and residual exposure. Do not replace this evidence
with a single "protected" label.
