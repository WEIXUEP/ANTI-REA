# Selected Runtime Constants: Integration and Acceptance

Use for explicitly selected owned policy constants. Keep numerical hot loops and
unknown-frequency functions unchanged until measured. This is reversible masking:
the linked program contains both the reconstruction data and the computation.
Use [remediation.md](remediation.md) to select controls and
[windows.md](windows.md) for the ABI/runtime contract.

## Capability Boundary

| Operation | Available from the downloaded skill alone? |
| --- | --- |
| Plan scoped C++/CMake changes and acceptance | Yes, agent-guided integration |
| Measure trusted existing releases | Yes, `scripts/measure.py` |
| Generate the demo's masked header or run its Windows validator | No, requires an existing ANTI-REA source checkout and its dependencies |
| Recover diagnostics and RTTI with `scripts/decode.py` | Yes, for supported schemas; **not** `private/constants.json` |
| Automatically mask arbitrary C++ literals or devirtualize code | No |

Do not implicitly clone a repository or install a compiler to satisfy a missing
capability. Adapt the documented contract to the authorized target instead.

## Existing Demo Checkout

The following names and switches are implemented in ANTI-REA, not universal
compiler flags. The catalog `examples/policy-constants.json` uses schema 1:

```json
{"schema": 1, "values": {"token_xor": 1518500249}}
```

The actual catalog selects five constants. Names match `[a-z][a-z0-9_]*` and
values are unsigned 32-bit integers. The generator writes
`generated/policy_constants.hpp` and private `private/constants.json`.
`AR_POLICY_VALUE(token_xor)` reads two volatile DWORD shares and XORs them when
enabled; OFF uses a direct constant expression. No accessor call is needed.
A domain-separated keyed hash derives masks; the master key stays at build time.
The map records original values and shares, so it is private recovery material,
not evidence that the binary prevents recovery. Inspect it with a private JSON
tool; `decode.py --build` does not load this map.

| Information protection | Constant protection | Result |
| --- | --- | --- |
| `ANTI_REA_CODE_PROTECTION=OFF` | Either | Plain constants; original behavior control |
| `ANTI_REA_CODE_PROTECTION=ON` | `ANTI_REA_CONSTANT_PROTECTION=OFF` | Other information controls active; masking control |
| `ANTI_REA_CODE_PROTECTION=ON` | `ANTI_REA_CONSTANT_PROTECTION=ON` | Selected constants masked; default combination |

`ANTI_REA_OBFUSCATION=NONE` and `MIXED_VM` select independent transform policies.
Do not enable VM solely because constant masking is enabled. Direct generator
users have `tools/anti_rea.py generate --root ... --build ... --keys ...
--protected ON --constants ON`; normal CMake integration supplies these options.
Use one key/configuration for all affected EXE/DLL translation units and consumers.

## Native Windows Demo Acceptance

Run from an existing checkout with Python dependencies, CMake/JOM and an installed
MSVC-compatible libsodium. Substitute the actual dependency paths. This creates
fresh private keys/evidence; it is for an authorized build/validation task.
PowerShell example using the tested LLVM and Intel environment:

```powershell
$acceptance = @(
  "--llvm-bin", "F:\Program_Professional\xollvm-windows-llvm23-Release\bin",
  "--environment", "F:\Intel\oneAPI\setvars.bat",
  "--sodium-prefix", "<libsodium-prefix>",
  "--sodium-library", "<libsodium-import-library.lib>",
  "--sodium-runtime", "<libsodium-runtime.dll>",
  "--jobs", "8"
)
python tools/validate_windows.py @acceptance --constants ON --obfuscation NONE --out build/check-constants-none-r001
if ($LASTEXITCODE -ne 0) { throw "NONE acceptance failed" }
python tools/validate_windows.py @acceptance --constants ON --obfuscation MIXED_VM --out build/check-constants-vm-r001
if ($LASTEXITCODE -ne 0) { throw "MIXED_VM acceptance failed" }
```

Use a new output directory each time; retain failed runs. Each invocation tests
Debug/Release and total protection OFF/ON, including the original positive
controls, 39 RTTI/EH checks, 1088 independent boundary/random inputs per policy
function, installed-package relocation, private PDB isolation and public exports.
Production linking uses `/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO`.
It verifies six EXE/DLL object reports, same-key clean rebuild stability and full
key-rotation rebuilds. Applied transform records are checked for VM policies.
This is Windows demo acceptance; it requires no Palace, MFEM, MPI or CUDA and
does not establish their compatibility. Read `result.json` and failed command
logs, not merely the compiler exit. Linux IR checks cannot replace this run.

## Matched Controls and Cost

The validator creates a new key per invocation and later rotates it. Its total
OFF/ON packages measure combined protection, **not** isolated masking cost.
For incremental measurements, prepare separate Release builds at each chosen
obfuscation level with total protection ON and the **same** key, compiler,
optimization, linker flags, dependencies, source and workload. Change only
`ANTI_REA_CONSTANT_PROTECTION=OFF` versus `ON`. Retain CMake caches and maps to
verify this. Stage the same DLLs/resources and test correctness before timing.

Measure total OFF versus selected full protection separately. Predeclare the
runtime and size limits; a failed gate cannot be repaired by raising it after
seeing the result. The independent runner accepts a manifest such as:

```json
{
  "schema": 1,
  "profiles": [
    {"name": "mask-off", "command": ["./mask-off/bin/anti-rea-demo.exe", "selftest"],
     "artifacts": ["mask-off/bin/anti-rea-demo.exe", "mask-off/bin/engine.dll"]},
    {"name": "mask-on", "command": ["./mask-on/bin/anti-rea-demo.exe", "selftest"],
     "artifacts": ["mask-on/bin/anti-rea-demo.exe", "mask-on/bin/engine.dll"]}
  ],
  "comparisons": [
    {"reference": "mask-off", "target": "mask-on", "max_slowdown": 1.5, "max_size_ratio": 1.1}
  ]
}
```

```bash
python <skill-directory>/scripts/measure.py --config workloads.json --samples 11 --warmups 3 --out /private/reports/masking-r001
```

These limits are examples, not defaults. This manifest measures process wall
time and the two declared binaries' combined size. Declare **every** staged
regular file to gate full-package size. Whole-process `selftest` is a smoke
workload, not a representative hot-loop benchmark. Add trusted representative
commands and independently expected output hashes where appropriate; see
[operations.md](operations.md). Program-reported loop time and process wall time
are distinct metrics; `measure.py` does not parse the former. Budget/integrity
failure returns 1 even when every process exits successfully.

## Recovery Countertest and Verdicts

Preserve an original-program audit and positive detections for all selected
constants. Re-scan fresh linked EXE/DLLs with the same corpus, inventory and
scanner. The separate audit skill's direct scanner supports
`--constant u32le:0x5a827999`; its `probe_constant_pairs.py` adds an adjacent XOR
known-corpus countertest. That tool is not included in this protection ZIP;
equivalent native inspection can supply the same evidence. Review callers,
callees and shared globals outside the transformed body, then confirm candidate
references against instructions or authorized observations.

Report four independent outcomes: runtime correctness, exact-byte disappearance,
known-corpus recoverability and the declared performance budget. Missing analysis
providers and truncated scans are incomplete, not proof of resistance.

At source revision `cdafd77` (2026-10-20 Windows demo), direct-byte and runtime
checks passed, but all five constants were reconstructed from adjacent shares
without keys/maps/PDBs and code references were independently confirmed. NONE
masking added 2.36% measured loop time; MIXED_VM masking added 54.93% versus its
matched masking-OFF control and failed a predeclared 1.5x incremental time limit.
VM plus masking versus original total OFF measured 45.76x time, failing a 2x
limit. Those local observations do not predict another application's performance.
Fresh REA decompilation was unavailable for those final binaries, so no fresh
REA resistance result was claimed. Keep older successful provider runs separate.
