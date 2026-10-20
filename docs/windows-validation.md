# Native Windows Demo Validation

English | [简体中文](windows-validation.zh-CN.md)

Measured on 2026-10-16 (Asia/Shanghai), using this repository's demo rather than
Palace or a previous standalone RTTI implementation. The complete private run is
`build/windows-acceptance/20261016T001110774585Z/result.json`. Only this sanitized
summary belongs in the public repository; keys, maps, IR, PDBs, full audits and
binaries remain internal.

## Environment and Reproduction

- Windows x64, clang-cl/opt 23.1.2 from
  `F:/Program_Professional/xollvm-windows-llvm23-Release/bin`.
- Intel oneAPI `F:/Intel/oneAPI/setvars.bat`, MSVC 14.43.34808 and Windows SDK
  10.0.22621.0; JOM 1.1.7, CMake 3.30 and Python 3.12.14.
- Official libsodium 1.0.22 MSVC archive; x64/v143/Release/dynamic import library
  and DLL, with its headers. Archive SHA-256:
  `3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279`.
- Obfuscation level `NONE`: information protection and ABI behavior were tested,
  not xollvm control-flow or VM passes.

```powershell
python tools/validate_windows.py `
  --llvm-bin F:/Program_Professional/xollvm-windows-llvm23-Release/bin `
  --environment F:/Intel/oneAPI/setvars.bat `
  --sodium-prefix <libsodium-root> `
  --sodium-library <libsodium-root>/x64/Release/v143/dynamic/libsodium.lib `
  --sodium-runtime <libsodium-root>/x64/Release/v143/dynamic/libsodium.dll
```

The operator supplies dependencies; the runner does not download compilers or
libraries. See [Windows instructions](windows.md) for developer-shell and Ninja
alternatives. Each run uses a fresh evidence directory and generates its own keys.

## Results

All four builds used `/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO`.

| Build | RTTI/exception checks | Confirmed corpus matches | Unperformed binary checks |
| --- | ---: | ---: | ---: |
| Debug, protection OFF | 39 passed | 6 | 0 |
| Debug, protection ON | 39 passed | 0 | 0 |
| Release, protection OFF | 39 passed | 6 | 0 |
| Release, protection ON | 39 passed | 0 | 0 |

The positive-control corpus contains three original diagnostic fragments and the
exact raw RTTI name for `ResonantKernel`. Both original builds detected every
corpus item. Six exact occurrences represent four unique entries across EXE/DLL.

The native suite exercised distinct EXE/DLL descriptors, cross-TU and cross-DLL
equality/inequality, hashes, ordering and type_index containers, bidirectional
casts, single/multiple/virtual inheritance, failed casts, `bad_typeid`, exact/base
and unrelated exceptions, rethrow, `exception_ptr`, pointer exception conversions
and const qualification/rejection.

Each protected configuration recorded 43 unique RTTI entries: 19 selected and
24 unchanged. Runtime names for ordinary, composite-template, local and pointer
types changed only within scope; unrelated types/templates stayed unchanged.
Runtime opaque names resolved through their private maps, and the recovery CLI
was exercised. Every selected original RTTI name from the maps was absent from
both staged protected binaries.

Same-key clean rebuilding preserved the map. Replacing the common key file
triggered regeneration and all six EXE/DLL object builds without a clean-build
request; every selected name changed and unselected names did not. The rotated
release passed runtime, package and binary gates again.

Internal PDBs existed; CodeView contained only `anti-rea-demo.pdb` and
`engine.pdb`. All seven intended C exports survived. Master/private keys were
absent from EXE/DLL in hex-text and raw-byte forms. Staged packages contained no
flagged private artifacts. Copied packages loaded their DLLs and resources from
another directory with build, toolchain and dependency-prefix paths removed from
PATH.

Python validation: 48 tests executed, 47 passed and one symlink-permission test
skipped. Coverage includes short/Unicode matches, baseline and scope checks,
package privacy, malformed PE and recovered import-parser failures, read-only
output guards, and running the downloaded skill scanner with isolated Python
imports outside the repository. Skill format and strict MkDocs checks passed.

## Corrections Found by Native Execution

- `/EHsc` treats C-linkage entry points as nonthrowing unless explicitly declared
  otherwise. The exception entry now uses `noexcept(false)`.
- JOM escaped `%_PDB%` into a reference containing `%engine.pdb%`. CMake now passes
  the target PDB filename explicitly, preserving a valid basename-only reference.
- The installed LLVM subset lacked `llvm-undname`. The launcher now supports
  DbgHelp and recognizes its local-lambda function spelling.
- Two tool tests assumed POSIX paths; expectations now preserve actual platform
  paths and executable suffixes.

## Limits

This establishes this demo's behavior with this toolchain/CRT, not Palace or
arbitrary plugin acceptance. LTO, PCH, modules, sanitizers and obfuscation/VM were
not validated. Mixed modes/keys across producers and consumers are unsupported.

The scanner is an inventory and selected-corpus gate, not proof of zero leakage.
Public exports, imports, inheritance structures and ordinary demo labels remain
visible. Sealed payloads can produce path-looking candidates requiring review.
Private-artifact classification uses filenames/package paths; renamed private
data can evade those heuristics. PDB contents are not parsed. Protected PDBs
retain linker symbols but lack source metadata removed by the launcher.

## REA Static Review (2026-10-20)

The optional [REA integration](skill/references/rea.md) was exercised on the
retained, unprotected Release demo EXE and DLL. This is a new static review;
the earlier four-configuration runtime acceptance above was not repeated.

The new baseline recorded 271 leakage/metadata findings across two artifacts,
with no unperformed structured metadata checks. Artifact SHA-256 identities:

- `anti-rea-demo.exe`: `fff3ce2196d029a09a18ad27537febb2bf56adfe0412e68c9d9d9b86b4ef5f2f`.
- `engine.dll`: `ce24efe2c4a92ccfebd226800800c146c239f1cb40ea4f47fe89704308210ee9`.

The plan identified EXE imports `memcpy`/`memmove` and DLL import `memcpy` as
review candidates. These are not confirmed vulnerabilities. Actual native
queries used the installed official REA 6.4.0 Windows package, Ghidra 12.1.4,
Node 24.19.0 and JDK 24.0.1; neither target was executed or modified.

| Query | Observed result |
| --- | --- |
| EXE procedure search for `memcpy` | External import and thunk at `0x14000c199` |
| EXE xrefs to that thunk | 38 reference addresses; reference kinds are not supplied by this operation |
| DLL function `ar_compute` | Assembly, pseudocode, references and p-code for `0x180001230` |
| DLL bounded value trace from that address | 11 nodes, 14 edges, one decompilation; no reported truncation or unknowns |

The wrapper verifies baseline size/SHA-256, backend Evidence identity and
operation, selected engine provenance, and unchanged target bytes after the
query. Composed value tracing identifies its parent as `rea-workflow` and its
constituent procedure as Ghidra. The complete raw JSON, limitations and errors
remain private under `build/rea-audit-validation/20261020/`; interrupted or failed
attempts were retained. Static flow does not establish exploitability, runtime
reachability, or freedom from memory defects.

The submodule pins upstream `bb154d1067b0fc250452b7d468d0b0523031a16f` (source
package version 6.4.0). Its clean checkout and public interfaces were inspected;
its full developer build was not performed. Native verification used the
separately installed official package via `--rea-root`, not an invented built
artifact in the submodule. IDA/Hopper, the other bridge actions and MCP client
registration were not exercised. No performance comparison is claimed; CPU
time and peak process-family memory were not measured.

Portable regression checks cover risky-import positive/negative controls,
baseline/scanner changes, package layout, preserved evidence, CLI argument
boundaries, wrong-target/operation/provider envelopes, composed provenance,
unavailable backends, and targets changed or removed during a query. The ZIP
also runs planning without REA, repository imports or Python site packages.
The full Python run completed 78 tests (four platform/permission skips); skill
format validation and the strict MkDocs build also passed.

## Paired Leakage Validation and Protection Cost (2026-10-20)

The current demo was freshly rebuilt and accepted again, using the same LLVM,
Intel/MSVC environment and libsodium described above. Private acceptance evidence:
`build/windows-acceptance/20261020T040733401395Z/result.json`.
Debug/Release OFF/ON each passed all 39 RTTI/exception checks, the original-name
and package gates, recovery, relocation, stable-key rebuilding and complete
six-object key rotation. The Release scanner recorded six exact corpus matches
before protection and zero after, with no unperformed metadata checks.

### REA Leakage Controls

The actual skill bridge used official REA 6.4.0 and Ghidra 12.1.4 on both fresh
Release packages, binding every query to its own scanner report and artifact
SHA-256. This extends the earlier unprotected-only review; it is not a mock test.

| Ghidra defined-string query | Original | Protected |
| --- | ---: | ---: |
| EXE: `Invalid mesh topology` | 1 | 0 |
| EXE: `ResonantKernel` (including composite/pointer types) | 6 | 0 |
| DLL: `ResonantKernel` | 2 | 0 |

The protected DLL's required public `ar_compute` was found at `0x180001230`;
its eight instructions and nonempty pseudocode were recovered. This is a control
that analysis still works, and also demonstrates that baseline information
protection does not conceal ordinary machine-code logic. These counts refer to
defined string records, not the scanner's exact-corpus occurrence count. Empty
Ghidra results alone cannot establish byte absence; the independent exact scan
and all selected original-RTTI checks also passed.

Eight successful static queries, Evidence envelopes and a verification script
are retained in `build/rea-leakage-validation/20261020T040733401395Z/`.
The first unavailable-provider attempt was retained, then retried with the
existing `GHIDRA_INSTALL_DIR` configured. No target execution occurred during
REA analysis. The installed official backend was used; the pinned submodule's
complete developer build remains unverified. No new vulnerability is claimed.

### Native Cost Measurements

Machine: Windows 11 build 26200, Ryzen 9 7900X (12 cores/24 threads), balanced
power plan. Builds used eight jobs, Release `/O2`, the same CRT and
`/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO`. Obfuscation was `NONE`;
these are the costs of diagnostic/location/RTTI information protection, not
Windows xollvm or VM measurements.

`tools/measure_windows.py` checked accepted artifact hashes and independent
policy results. A pilot used five warmups and 31 measured samples per workload
and profile; a separate repeat used ten warmups and 101 samples. Profiles
alternated order, no REA analysis ran concurrently, and no slow samples were
discarded. The table below uses the repeat medians; build time is the same
single initial compile/link observation, excluding configure/tests/install.

| Metric | OFF | ON | Observed change |
| --- | ---: | ---: | ---: |
| Initial compile/link (s) | 3.442 | 4.490 | +30.4% (one observation) |
| EXE + engine DLL (bytes) | 113664 | 100352 | -11.7% |
| Startup process median (ms) | 7.342 | 8.291 | +0.950 ms / +12.9% |
| 500,000 policy iterations, inner median (ms) | 2.696 | 2.623 | -2.7%; not a speedup claim |
| One-warning process median (ms) | 7.178 | 8.493 | +1.315 ms / +18.3% |

Pilot OFF/ON medians were 7.638/8.232 ms for startup, 2.686/2.624 ms for the
policy loop and 7.173/9.322 ms for the warning process. Neither experiment shows
a clear policy-loop regression. It does not measure per-cast RTTI cost or
sustained diagnostic throughput; warning timing includes process loading and I/O.

Tail latency is material and must remain visible. Repeat process-wall values:

| Workload | OFF p95 / max (ms) | ON p95 / max (ms) |
| --- | ---: | ---: |
| Startup | 8.449 / 10.505 | 110.318 / 122.676 |
| Policy benchmark process | 11.719 / 12.495 | 112.516 / 122.782 |
| One-warning process | 23.442 / 101.629 | 120.372 / 402.091 |

The pilot also had roughly 120 ms protected-process outliers. The cause of the
tail delays is unresolved; no antivirus/system setting was changed. These data
do not establish a low-overhead or latency-budget guarantee. Inner policy-loop
time stayed near 2.6 ms even when whole-process latency was much larger.

The supplied libsodium DLL is 462848 bytes and is imported only by the protected
EXE. Acceptance stages it in both packages: staged totals are 576534/563222 bytes,
but that is not a reduction in minimal deployment size. Omitting the unused DLL
from the baseline would give 113686 bytes including its resource, versus 563222
for the protected package, excluding shared system CRTs in both cases.

Raw samples, dispersion, acceptance identity and matching runner snapshots are
private under `build/windows-cost/20261020T040733401395Z/` and the sibling
`20261020T040733401395Z-repeat/`. CPU time, peak memory, real Palace and Windows
obfuscation/VM costs were not measured. Portable regressions completed 82 tests,
with four platform/permission skips.

## Windows MIXED_VM and REA Recovery (2026-10-20)

**VM was applied and runtime acceptance passed. REA recovered readable wrapper
and dispatcher representations, but did not automatically reconstruct the original
formula in this trial. This does not establish that recovery is impossible.**

This is the static-stage result. The later dynamic-assisted investigation below
recovers equivalent semantics for the same pinned function.

A separate native run used the same LLVM/Intel environment, eight build jobs and
`/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO`: OFF/NONE versus ON/MIXED_VM.
Append `--obfuscation MIXED_VM` to the native acceptance command above; the default
remains `NONE`. Private evidence is
`build/windows-acceptance/20261020T042707207675Z/result.json`.

### Applied Transforms and Behavior

Debug and Release reports both require `policy_token` VM `ran/changed` (9 to 58
IR instructions), and `policy_dispatch` MBA/split/flattening (32 to 1768 IR
instructions). These are IR counts, not final machine instruction counts or
resistance scores. All four Debug/Release OFF/ON configurations passed 39 RTTI
and exception checks each. Recovery, relocation, private-package separation,
same-key rebuild and all six objects rebuilding after key rotation passed.
Release exact-corpus occurrences fell from six to zero, with no metadata gaps.
Another 40 boundary/deterministic seeds per Release profile passed 80 independent
one-round reference checks; the 500000-round benchmark matched the Python integer
reference too. These establish runtime correctness, not recovery by REA.

### Observed REA Limits

Official REA 6.4.0/Ghidra 12.1.4 analyzed the release EXE with its scanner binding;
no private PDB, IR, maps or source were supplied. Packages contain no PDB. Searching
the original EXE for `policy` found no procedure names. PE function boundaries and
the main loop's calls located the targets in this build.

| Target | Release address | Observation |
| --- | --- | --- |
| Unprotected token control | `0x140007b00` | Eight instructions; pseudocode directly shows the original integer formula |
| Main | `0x140001000` | Readable loop and two policy calls |
| VM wrapper | `0x140008e50` | 46 analyzed instructions; readable context/call and some original constants |
| VM dispatcher | `0x140009a90` | 72 analyzed instructions; partial pseudocode, unresolved handler targets |
| Bytecode writer references | `0x14004a9c0`, `0x14004a9c7` | References found, but writer recovery remains incomplete |

The dispatcher reports `Could not recover jumptable` and `Treating indirect jump
as call`; its empty callee list is incomplete coverage, not absence of handlers.
The bytecode-writer query failed because its address is not a known procedure
entry. A nearby search hit at `0x14004a1e0` ends at `0x14004a8a5` and does not cover
the writer. That successful query is not counted as writer recovery.
No dynamic VM tracing, symbolic execution or dedicated devirtualizer was used.
Retained Evidence, failed queries, independent verification and summary are under
`build/rea-vm-validation/20261020T042707207675Z/`.

### Observed Costs

Measurements ran separately from REA with alternating profile order. The pilot
used five warmups/31 samples; the repeat used ten warmups/101 samples per workload
and profile. Repeat medians compare combined information protection plus
VM/flattening, without isolating VM alone.

| Metric | OFF/NONE | ON/MIXED_VM |
| --- | ---: | ---: |
| Initial compile/link, one observation (s) | 4.440 | 8.369 |
| EXE + engine DLL bytes | 113664 | 377856 |
| Startup process (ms) | 5.818 | 6.641 |
| 500000-round inner policy loop (ms) | 2.544 | 74.376 |
| One-warning process (ms) | 5.779 | 7.004 |

The policy loop is approximately **29.2 times** the original duration; pilot
medians were 2.552/74.622 ms. Repeat inner-loop p95 is 2.812/77.131 ms, while
whole benchmark-process p95 is 9.798/184.392 ms. Protected-process maxima are
120.138 ms startup, 196.481 ms benchmark and 119.917 ms warning; the tail cause
remains unresolved. This is not a whole-application or numerical-kernel slowdown
claim; avoid applying this configuration to numerical hotspots without a budget.

The 462848-byte libsodium DLL is staged in both packages: 576534/840726 bytes.
Removing unused sodium from the original package yields 113686 bytes; the
protected package requires it. System CRTs, CPU time and peak memory are excluded.
Raw samples and runner snapshots remain private under
`build/windows-cost/20261020T042707207675Z-mixed-vm/` and its `-repeat` sibling.

Regressions completed 83 tests with four platform/permission skips; both skill
formats, standalone ZIP tools and strict MkDocs build passed. Skill references
remain English and now distinguish VM application, algorithm recovery and
incomplete indirect-call graphs.

## Windows VM Function Recovery (Dynamic Assistance, 2026-10-20)

**The pinned VM-light `policy_token` function was recovered as equivalent C++
using REA/Frida, analyst-reviewed handlers and an artifact-specific decoder.
All 4360 distinct test inputs matched. This is not automatic static
devirtualization by REA/Ghidra.**

The original release EXE above was reused without rebuilding or modifying it:
SHA-256 `28e69edcd5fe3e231a9479fa56f78a18cc12417ec21d2a0b7fc51f480ad1611b`.
Existing REA 6.4.0/Ghidra 12.1.4 evidence was retained; new calls used REA MCP
`instrument_with_frida`, Frida 17.23.2, Windows x64 and the owned demo's `startup`
scenario.

### Recovery Evidence

The trace captured 31 runtime bytecode bytes, eight actual dispatches, register
states and handler addresses. The previously undiscovered initialization entry
was identified at RVA `0x4a8b0`. Its instructions expose masked AES round keys,
nonce and bytecode ciphertext carried by the program. An offline decoder extracts
these from the release PE and uses Node's standard AES-128-CTR implementation;
all 31 decrypted bytes match the runtime capture. These are VM-internal cipher
materials, not diagnostic private keys or the RTTI naming key.

Position masks and the dispatch mapping recover operands; actual ALU case
instructions establish XOR, multiplication, logical right shift and addition.
Recorded handler/case instruction bytes were checked against the release PE,
rather than inferring a formula from one input/output observation.

| Bytecode offset | Recovered operation |
| ---: | --- |
| 0 | `local[0] = r0` |
| 3 | `r1 = local[0]` |
| 6 | `r2 = r1 ^ r7` |
| 11 | `r3 = r2 * r8` |
| 16 | `r4 = local[0]` |
| 19 | `r5 = r4 >> r9`, logical |
| 24 | `r6 = r3 + r5` |
| 29 | `return r6` |

The wrapper supplies `r0 = input`, `r7 = 0x5a827999`, `r8 = 33`, `r9 = 7`.
Substituting the recovered program generates:

```cpp
std::uint32_t recovered_token(std::uint32_t input) {
    return ((input ^ 0x5a827999u) * 33u) + (input >> 7u);
}
```

Arithmetic is unsigned 32-bit with wraparound. Equivalent computation was
recovered, not original variable names, comments or source formatting.

### Independent Checks and Limits

REA/Frida directly invoked the initialized original VM function on 264 boundary
and deterministic inputs. Another 4096 distinct inputs, disjoint from that set,
validated the recovered model. Generated C++ was compiled with the supplied
clang-cl/Intel environment and run independently on all 4360 inputs; its outputs
matched the VM's direct-call outputs with zero differences. The uninstrumented
original startup and 39 RTTI/exception checks still pass, and file hashes are
unchanged. The entire 32-bit input domain was not exhausted or formally proved.

This was analyst-assisted, artifact-specific work, not a general devirtualizer
or blinded resistance evaluation. The analyst had previously seen source and
the unprotected control. The recovery script itself reads neither, and does not
read private PDBs, IR, maps or key files. This is VM light with anti-debug and
hardened behavior disabled, not a claim about arbitrary VMs or every function.

Frida Evidence itself lacks artifact identity. Script payloads supplement the
module path, file SHA-256, platform, architecture and Frida version, with before/
after file hashing and instruction-byte checks. This is not cryptographic
attestation of every loaded-memory byte. The initial two-byte indirect-jump hook
failed and was retained; a longer preceding instruction sequence allowed target
observation without counting the failed attempt as coverage.

Private evidence is `build/rea-vm-recovery/20261020-r002/`. `reconstruction/`
contains the offline report, generated C++ and runner snapshot;
`native-check/result.json` records compilation and all 4360 comparisons. Original
REA/Frida envelopes, scripts, failed attempts and test vectors are retained
internally and excluded from public documentation and skill ZIPs.

## IDA 9.1 Backend Integration (2026-10-20)

Windows IDA Professional `9.1.25.0226`, idalib `9.1.250226` and Hex-Rays
`9.1.0.250226` were connected to REA 6.4.0. The isolated Python 3.12 environment
uses `ida-pro-mcp` 2.0.0 at upstream commit
`c133c3853faa111a9b00ee615c013b720d0c4acd` and `idapro` 0.0.11. The headless
supervisor uses stdio and one worker. Installation files were not rewritten and
analysis targets were not executed.

The final configuration passed real CLI/MCP verification on the same release
package's `engine.dll` / `ar_compute`: positive procedure inventory/search,
pseudocode, assembly, instruction and relationship parity, known string/xref
matches, invalid-input rejection, worker absence and private-workspace release
after close, and unchanged original bytes. The string oracle was confirmed in
raw PE bytes; the xref oracle was independently checked in the PE export table.

The audit skill's `rea_audit.py --provider ida` also completed the VM EXE wrapper
query using the retained audit baseline and Evidence bound to the EXE SHA-256.
The wrapper, constants and interpreter call are readable. This integration did
not repeat algorithm recovery through IDA and does not establish automatic
devirtualization.

The initial venv-launcher configuration failed worker cleanup. Selecting the
actual Python interpreter with process-local `PYTHONPATH` for the isolated
packages passed final DLL verification. The VM EXE's complete verifier still
failed an assembly text-parity assertion: Hex-Rays type inference added
`xmmword ptr` annotations. That failure is retained and not counted as a full
pass; the successful separate skill query does not close that verification gap.

The local CLI entry is `G:\REA\rea-ida.cmd` with registration at
`G:\REA\tools\ida-mcp.json`. The existing Codex REA environment now includes
that registration path, preserving Ghidra as default. Reconnect REA to select
`open_binary.provider_id: "ida"`. The original configuration was backed up.
Private logs, failed attempts and final checks are retained in
`build/ida-integration/20261020-r001/`.
