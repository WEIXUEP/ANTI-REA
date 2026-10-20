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
| `antirea/hardening.py`: environment checks, decoys and vendor profiles | Possible further experiments | Not transplanted; no silent key poisoning that changes computation |

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
