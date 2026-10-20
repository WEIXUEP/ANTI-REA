# Leakage Detection Skill

English | [简体中文](audit-skill.zh-CN.md)

`cpp-leakage-audit` is a self-contained, read-only source and native-release
auditor. It finds exposed diagnostics, conditions, paths, names, RTTI and private
package artifacts, and reports evidence-backed recommendations.
Optional REA analysis extends it to native security investigation while keeping
vulnerability candidates separate from confirmed information leaks.

For encryption, build changes, keys and recovery tooling, use the independent
[code protection skill](using-protection-skill.md). Neither skill requires the other.

## Install and Run

[Download cpp-leakage-audit](downloads/cpp-leakage-audit.zip) and extract its
directory into your agent's skill directory, or copy `skills/cpp-leakage-audit`
from the checkout. Nothing is installed globally by this project.

Basic scanning needs Python 3.10+. Optional pyelftools/pefile enable structured
native metadata inspection; install `scripts/requirements.txt` in your selected
environment. The archive does not include key generation or target rewriting.

```bash
python <skill-directory>/scripts/audit.py --source /authorized/source \
  --binary /original/app --binary /original/engine.so \
  --deny-file sensitive-corpus.json --require-metadata \
  --out /private/reports/original
python <skill-directory>/scripts/audit.py --package /staged/release \
  --fail-on-private --require-metadata --out /private/reports/package
```

Paths are always checked; specified function and variable names default to empty.
Use `--all-strings` for a private global string inventory. Baselines and reports
contain sensitive evidence and must not be installed with the application.

Select numeric bytes with repeatable specifications, for example
`--constant u32le:0x5a827999 --constant f64be:0.125`. Unsigned 32/64-bit integers
and IEEE-754 binary32/binary64 floats support explicit little/big byte order.
Exact file offsets are recorded; specifications participate in baseline scope
checks and `--fail-on-deny`. A hit proves bytes, not their computational role.
Review callers, shared tables and references beyond the virtualized function.
See [reference review and Windows checks](reference-improvements.md).

## Agent Request

```text
Use $cpp-leakage-audit to inspect this source tree, original executable,
libraries and staged release. Save a private baseline before any changes.
Report confirmed diagnostic/path/RTTI/symbol leaks with offsets or source lines,
public-name exceptions and unavailable checks. Do not modify the target.
```

An audit does not authorize rebuilding, stripping, generating keys or installing
toolchains. The skill can recommend fixes and compare a provided rebuilt release
using the same corpus and inventory, without performing those changes itself.

## Verified Windows Leakage Checks

The [native validation record](windows-validation.md) includes real REA/Ghidra
queries against original and protected demo packages. Selected diagnostic/RTTI
queries have positive controls, and a protected public function remains
decompilable. Exact byte gates remain independent of Ghidra's defined-string
inventory. The same record reports native protection costs and observed latency
tails; it does not claim a vulnerability assessment or resistance to all analysis.

## Virtualized Function Recovery

The skill also investigates equivalent logic recovery for a selected virtualized
function. Start with the original baseline and bind the protected artifact to
its own hash/report; a missing original leaves before/after improvement unverified.
Use static inspection, authorized REA/Frida observations, handler analysis and
independent compilation as needed. Report static visibility, observed execution,
partial reconstruction and validated reconstruction separately.

```text
Use $cpp-leakage-audit to investigate this Windows demo's selected VM function.
You may execute/instrument the owned demo in isolated processes; preserve its files.
Establish a baseline, then generate private equivalent C++ if recoverable.
Compile it independently and compare boundary and disjoint holdout inputs against
the original function. Report unobserved paths, analyst assistance and unknowns.
```

The [Windows validation record](windows-validation.md) includes assisted recovery
of one VM-light sample. The ZIP contains the investigation guide, not that sample's
private traces, addresses or decoder, and does not provide one-click devirtualization.

## Canonical Instructions

- [Skill instructions](skill/index.md)
- [Independent operations and exit codes](skill/references/operations.md)
- [Finding interpretation](skill/references/interpretation.md)
- [Audit validation](skill/references/validation.md)
- [Windows PE audit](skill/references/windows.md)
- [REA submodule, CLI/MCP interfaces and native security review](skill/references/rea.md)
- [Virtualized function recovery](skill/references/vm-recovery.md)

These pages and the allowlisted ZIP come from the same maintained skill sources.
Source heuristics are not a C++ parser; exact byte matches are not proof of an
executed path. Zero matches do not mean a program cannot be reverse engineered.
