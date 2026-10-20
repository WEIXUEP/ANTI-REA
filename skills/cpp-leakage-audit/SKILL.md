---
name: cpp-leakage-audit
description: Audit C++ source and ELF/PE releases for information leaks, probe numeric masking with known-corpus XOR pairs, investigate native vulnerability candidates, and assess virtualized-function recovery with optional REA. Use for original-program baselines, before/after audits, and evidence-backed recovery investigations.
---

# C++ Leakage Audit

## Scope and Independent Operation

Audit the authorized source, original binaries, libraries and staged package.
This skill preserves target artifacts and retained analysis. Ordinary audits
write private reports; an authorized function-recovery task may also create
private instrumentation, decoders and independently compiled reconstructions.
Do not rebuild or rewrite the target, strip it, generate keys or change
protection policy under an audit-only request. Recommend fixes with evidence; implementation is
a separate authorized task. The optional `cpp-code-protection` skill covers that
task, but is not required to run this skill.

The bundled `scripts/audit.py` runs with Python 3.10+ outside this repository.
Optional pyelftools/pefile add structured ELF/PE checks; see
[operations.md](references/operations.md) for commands, dependencies and limits.
For Windows artifacts read [windows.md](references/windows.md).
For decompiler-backed leakage checks or native vulnerability investigation read
[rea.md](references/rea.md). REA is
an optional analysis backend; the standalone leakage scanner needs no REA, Node
or decompiler installation.
For virtualized-function inspection or recovery, read
[vm-recovery.md](references/vm-recovery.md). That workflow uses REA when available;
it does not provide a generic devirtualizer.
For masked numeric constants, read
[numeric-recovery.md](references/numeric-recovery.md). The bundled
`scripts/probe_constant_pairs.py` checks known adjacent DWORD XOR pairs with
standard-library Python; it needs no key, map, REA or target execution.

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
For selected algorithm constants, add repeatable `--constant` specifications,
such as `u32le:0x5a827999` or `f64be:0.125`, to the original and follow-up scans.
Widths and byte order are explicit; a hit confirms bytes, not their semantic use.
Review the core function's callers, callees and shared tables as well as its
body. Record the reviewed neighborhood and unresolved edges; function-level VM
protection does not by itself hide constants in wrappers or global data.
If exact bytes disappear, run the numeric recovery countertest when applicable.
Record pair candidates separately from code-reference confirmation and tested
algorithm recovery; the helper only supplies the first layer. An incomplete
probe or missing REA provider cannot pass a recovery-resistance claim.
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

## Native Vulnerability Investigation

Start with the original-program baseline above, even when the main request is
security review. Bind every EXE/DLL to its own baseline artifact and SHA-256.
Use `scripts/rea_audit.py --baseline <original.json> --binary <original-executable>
--out <new-private-directory>` to derive review seeds from structured imports.
This plan requires no REA installation and never counts imports as vulnerabilities.
Leakage allow rules do not dismiss security candidates.

Use REA MCP when already connected for iterative investigation; use the bundled
bridge's explicit static actions for reproducible CLI evidence. The repository
pins an optional REA submodule; an extracted skill can select an existing REA
checkout with `--rea-root`. Consult the reference for initialization and queries.
Do not download/build dependencies, register MCP, execute targets, annotate
databases or replace retained projects as an implicit part of inspection.

Trace selected sinks to actual call sites and callers, then inspect arguments,
input origins, size arithmetic, validation and failure paths. Also review parser
and allocation/lifetime logic when imports provide no useful seeds. Separate
observed instructions, decompiler-derived flow, hypotheses and unknowns. A
static call path alone does not establish runtime reachability or exploitability.
Retain REA Evidence, unresolved indirect/alias edges and budget truncation.
Treat algorithm-looking names, crypto tables and decoy routines as hypotheses
until references and relevant control/data paths support their role.
Missing providers or failed queries are incomplete checks, never passing reviews.

## Report

Lead with prioritized confirmed findings, artifact identity and offset or source
line, likely origin and scoped recommendations. List intentional public names,
candidate matches needing review, unavailable checks and scanner limitations.
Report security candidates separately, with a CWE hypothesis, exact call address,
source-to-sink argument evidence, preconditions and remaining verification.
Label a vulnerability confirmed only when the unsafe condition and its reachable
input constraints are established; otherwise retain it as a candidate. Never
assign CVEs or claim a complete security assessment from imports or strings.
An allowlist requires a narrow expression and a reason; it must not erase whole
categories such as Base64-looking strings or system paths.
Zero corpus matches do not mean no leakage or resistance to reverse engineering.
For VM work, report transform evidence, static visibility, observed execution
and reconstructed semantics separately. State whether recovery is unattempted,
partial or validated for the tested domain, with the exact inputs, mismatches,
analyst assistance and unknown paths. A readable dispatcher is not recovery;
successful recovery of one function is not recovery of the whole application.
If asked to implement protection, establish the authorized change scope and
switch to a protection workflow rather than silently extending the audit.
