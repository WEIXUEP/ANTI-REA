---
name: cpp-leakage-audit
description: Inspect C++ source and ELF/PE release packages for exposed diagnostics, paths, symbols, RTTI and private artifacts. Use for evidence-backed leakage detection and before/after audits, not protection implementation or general vulnerability scanning.
---

# C++ Leakage Audit

## Scope and Independent Operation

Audit the authorized source, original binaries, libraries and staged package.
This skill is read-only toward the target: write only requested private reports.
Do not rebuild, strip, rewrite files, generate keys or change protection policy
under an audit-only request. Recommend fixes with evidence; implementation is
a separate authorized task. The optional `cpp-code-protection` skill covers that
task, but is not required to run this skill.

The bundled `scripts/audit.py` runs with Python 3.10+ outside this repository.
Optional pyelftools/pefile add structured ELF/PE checks; see
[operations.md](references/operations.md) for commands, dependencies and limits.
For Windows artifacts read [windows.md](references/windows.md).

## Establish Evidence

Identify source ownership, actual build profile, ABI, intended public API and
release inventory. Keep first-party findings separate from dependency/runtime
text. Inspect the original artifacts before changes, assemble a small corpus
from known diagnostics, condition expressions, internal types and developer
roots, and verify those positive controls are detected.

```bash
python <skill-directory>/scripts/audit.py --source <source-root> \
  --binary <original-executable> --binary <original-library> \
  --deny-file <sensitive-corpus.json> --require-metadata \
  --out <private-baseline-prefix>
```

Paths are always scanned. Explicit function/variable searches are empty by
default; supply `--function` or `--variable` only when requested or justified by
source evidence. Use `--package` for every regular staged file, including assets,
and `--all-strings` for a confidential global readable-string inventory.
Reports themselves expose names and paths; never put them in a release package
or publish them without review.

Distinguish exact byte matches, heuristic candidates and unperformed checks.
Missing metadata parsers are gaps, not passing inspection. Use
`--require-metadata` for native binary acceptance. The source scan is not a C++
parser and does not determine which preprocessor branch was compiled.
Package symlinks and empty packages are rejected, not silently skipped.

Review source locations, runtime literals, RTTI, static/dynamic symbols, debug
records, loader paths and packaged private files as separate channels.
Read [interpretation.md](references/interpretation.md) to classify findings and
recommend a mitigation without equating stripping with encryption.
Preserve required imports and public exports; decompiler-generated variable
labels are not evidence of recovered source names.

## Runtime and Comparison Boundaries

Inspect existing logs. Execute normal or intentional-failure scenarios only
when authorized and safe in isolated processes; do not trigger production
failures. Do not execute an untrusted artifact merely to audit its bytes.
Keep build-tree and installed-release findings separate.

When the user provides a rebuilt release, re-scan with the same corpus, ordering,
allow rules and inventory. Use `--baseline <original.json>` with a different
`--out`. Scope/scanner/inventory mismatches must be reviewed explicitly, not
hidden by editing the baseline. Report resolved, persistent and new findings.
Read [validation.md](references/validation.md) for positive/negative controls.

## Report

Lead with prioritized confirmed findings, artifact identity and offset or source
line, likely origin and scoped recommendations. List intentional public names,
candidate matches needing review, unavailable checks and scanner limitations.
An allowlist requires a narrow expression and a reason; it must not erase whole
categories such as Base64-looking strings or system paths.
Zero corpus matches do not mean no leakage or resistance to reverse engineering.
If asked to implement protection, establish the authorized change scope and
switch to a protection workflow rather than silently extending the audit.
