# Reference Review and Improvements

English | [简体中文](reference-improvements.zh-CN.md)

On 2026-10-20, [chldbwnstm/ANTI-REA](https://github.com/chldbwnstm/ANTI-REA)
was reviewed at commit `84c4b87a4da583acd30d060bbf01f73ce1e30739` in a separate
clone. It did not replace this project or introduce a new build dependency.
These changes were independently implemented without copying its protection engine.

## Selected Ideas

| Reference implementation | Relevant improvement | Implemented scope |
| --- | --- | --- |
| `antirea/scope.py`: callers, callees and shared globals | Core-only VM selection can leave wrapper constants and shared tables visible | Skill neighborhood review and explicit numeric corpus scanning; no automatic IR protection-scope expansion |
| `antirea/defense_validate.py`: engineering budgets and rotating order | Functional preservation and acceptable cost need separate decisions | Native Windows and standalone measurement budgets, relative speed and failing exit codes |
| `antirea/judge.py`: boundaries, correlated and private independent cases | Distinguish reconstruction from fitting known observations | Existing boundary/holdout guidance retained; upstream results are not counted as our tests |
| `antirea/hardening.py`: constant pools, environment checks, decoys and vendor profiles | Constant pools can reduce direct byte signatures | Follow-up independently implements masking for five constants; environment checks, decoys, vendor profiles and silent key poisoning are not transplanted |

Pinned sources:
[scope review](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/scope.py),
[budget validation](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/defense_validate.py),
[behavioral judge](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/judge.py), and
[hardening](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/hardening.py).
The reference VM, commercial tools and external attack experiments were not run.
Its README's 25% indicator was not reproduced and cannot compare general defense
strength between these projects.

## Numeric Constant Scanning

The existing scanner focused on strings and metadata. Repeatable `--constant`
specifications now search explicitly encoded numeric bytes, without REA or a
disassembler, including from the independent audit skill ZIP:

```powershell
python skills/cpp-leakage-audit/scripts/audit.py `
  --binary original/app.exe --constant u32le:0x5a827999 `
  --constant f64be:0.125 --require-metadata --out build/private/original
```

Supported types are `u32le/u32be/u64le/u64be/f32le/f32be/f64le/f64be`.
Out-of-range integers and nonfinite floats are rejected. `specified-constant`
findings retain exact file offsets and participate in `--fail-on-deny` gates.
Numeric specifications join the baseline corpus identity. The scanner version
changed: capture a fresh original baseline from retained bytes, preserving old
reports rather than editing them.

Matches establish bytes, not runtime use, data type or algorithm identity.
Folded, split or encrypted constants can be missed; common values can match
incidentally. Skill guidance now includes callers, shared data and reference
review, without treating decoy function names or crypto-looking tables as proof.

## Performance Budgets

Native Windows measurements accept `--max-bench-slowdown`,
`--max-startup-slowdown` and `--max-package-ratio`. The independent protection
skill's workload manifest accepts optional `comparisons`:

```json
{"reference": "baseline", "target": "protected", "max_slowdown": 1.25, "max_size_ratio": 2}
```

These are example limits. Budgets are validated and recorded before execution;
exceeded limits return 1. Failed workloads and unavailable references cannot
pass requested comparisons. The standalone runner also rotates profile order,
retains individual samples and p95, checks warmup output, and rechecks declared
artifact sizes/SHA-256 after measurement. Relative speed is
`100 * baseline time / protected time`, reported separately from time overhead.
See the [Windows guide](windows.md) and [measurement guide](measurement.md).

## Native Windows Checks

The accepted OFF/NONE and ON/MIXED_VM packages were reused without rebuilding,
changing targets or running production Palace. Protected EXE SHA-256:
`28e69edcd5fe3e231a9479fa56f78a18cc12417ec21d2a0b7fc51f480ad1611b`.

- Both EXEs matched `u32le:0x5a827999`, at raw offsets 28419 and 33469;
  independent byte reads confirmed each finding. Negative control
  `u64le:0x0123456789abcdef` did not match. Structured metadata had no gaps.
  Protected `--fail-on-deny` returned 1, correctly identifying a still-visible
  selected constant, not a new leak or RTTI protection regression.
- Final native measurements used three warmups and eleven samples per profile.
  Inner-loop medians were 2.586 / 75.946 ms: 29.367x duration and 3.405% relative
  speed. A predeclared 2x time budget failed; a separate permissive 50x
  positive-control run passed (2.578 / 74.792 ms, ratio 29.016).
  This is not a recommended production budget.
  Functional and independent-reference checks passed in both runs.
- Complete staged packages were 576534 / 840726 bytes, a ratio of about 1.458;
  both included libsodium. The 2x package budget passed. EXE + engine DLL alone
  have a different ratio, about 3.324, and must not be conflated with package size.
- The independent ZIP runner measured real Windows `selftest` workloads against
  an independently expected output. An intentionally restrictive 0.5x size
  budget failed with exit 1. Selected EXE/DLL hashes remained unchanged.

The first directory-level baseline comparison was rejected because resource
aliases changed the file inventory; that attempt is retained. Numeric comparison
then explicitly selected the three identically named EXE/DLL files and does not
claim package-wide comparison. Size measurements still cover the complete
packages. Final checks extracted tools from both generated independent skill
ZIPs; generic measurement used `-I -S` isolation. Regression ran 92 tests with
four platform/permission skips; both skill formats and strict MkDocs passed.
Final native evidence is private at
`build/reference-improvements/20261020-r003/results/verification.json`.
Failed attempts, scripts, responses, snapshots and raw samples are also retained,
excluded from documentation and skill ZIPs. This work added no blinded attack
trial and establishes neither constant concealment nor general devirtualization.

## Follow-Up Protection Implementation

Following the constant-pool idea in `hardening.py`, five policy constants now
have independently implemented build-time masking and runtime reconstruction.
`ANTI_REA_CONSTANT_PROTECTION` defaults ON but applies only when information
protection is ON. Set it OFF at the same obfuscation level to isolate its benefit
and incremental cost. Numerical hot loops are excluded.

`examples/policy-constants.json` declares the selection. Domain-separated HMAC
derives per-entry masks for `policy_constants.hpp`; the internal map stays in
`private/constants.json`. Volatile reads and XOR prevent `/O2` folding back to
plaintext. The master key is not needed by the runtime decoder or shipped in
EXE/DLL files.

This is reversible numeric obfuscation, not the confidentiality boundary of
public-key sealed diagnostics. The binary carries its reconstruction data and
logic; adjacent XOR shares can even be recovered with a known-corpus pair scan.
Acceptance therefore separates direct plaintext-byte disappearance, runtime
behavior/cost, and analyst recoverability. The earlier retained samples still
expose their constants; fresh builds require fresh evidence, not amended old
reports.

### Fresh-Build Acceptance

Clang/LLVM 23.1.2 in the Intel environment, eight build jobs and
`/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO` passed fresh Debug/Release,
information-protection OFF/ON acceptance at both NONE and MIXED_VM.
All five constants appeared in original EXEs and disappeared as direct plaintext
bytes in protected EXE/engine DLL files. The suite passed 39 RTTI/EH boundaries,
1088 independent boundary/random inputs per policy function, diagnostic recovery,
relocation, six-object coverage, same-key rebuilds and full rotation rebuilds.
VM/flattening applied-pass reports were verified rather than assuming success.

Release controls then changed only constant masking, keeping information
protection, obfuscation level and keys equal. Three warmups and eleven rotating
samples used predeclared 1.5x incremental runtime and 1.1x package-size limits.

| Obfuscation | Masking OFF median | Masking ON median | Extra loop time | Package change | Budget |
| --- | ---: | ---: | ---: | ---: | --- |
| NONE | 2.7126 ms | 2.7765 ms | +2.36% | Equal | Passed |
| MIXED_VM | 75.9654 ms | 117.6920 ms | +54.93% | +1024 bytes (about 0.12%) | Runtime failed |

These are local demo observations, not universal costs. A separate comparison of
VM plus masking against original information-protection OFF measured 2.554 /
116.874 ms, a 45.76x ratio. It exceeded the predeclared 2x limit and the native
measurement tool correctly returned 1. The 2.36% observation cannot describe VM.

**Recovery resistance did not pass.** An independent script read only final EXE
bytes and the five known constants, without keys, generated headers, maps or PDBs.
Adjacent DWORD XOR reconstructed all five, with Capstone 5.0.7 also confirming
code references to the relevant data. For example, a pair at file offset 331744
in the final MIXED_VM EXE reconstructs `0x5a827999`. This is a known-corpus test,
not blinded algorithm recovery or complete VM devirtualization. The current chat
REA Ghidra backend lacks its Windows native manifest and IDA is unregistered;
no fresh REA decompilation was obtained or counted as protection success.

Final rotated-key NONE / MIXED_VM EXE SHA-256 values are
`11307cedb2c3f4ad792d9327bb7ae353047c38cfa211788eec06d82a6c434feb` /
`7abfbbd6362c0ddb65f15a874565d1d6c4f15622a3ddf12e4957cc425818a674`.
Private evidence in `build/constant-protection/20261020-r002/` includes
`plain/result.json`, `mixed/result.json`, `plain-cost/result.json`,
`mixed-cost/result.json`, `mixed-total-cost/result.json` and both
`*-recovery.json` files. The retained r001 accessor calls distorted VM comparisons;
the final version uses direct expressions to remove that interference.
Artifact hashes remained unchanged during checks. Python regression ran 94 tests
on both Windows and Linux with four and two platform skips respectively.

The adopted capability reduces selected direct byte signatures at low measured
cost without VM and retains a reproducible OFF control. It does not establish
resistance to REA or constant reconstruction; the VM hot-loop combination also
fails its performance gate.
