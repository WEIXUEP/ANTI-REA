---
name: python-leakage-audit
description: Inspect Python releases for exposed source names, paths, strings and code objects; extract bounded ZIP/PyInstaller members, generate offline leakage-location HTML and evaluate release-only recovery with optional native REA analysis. Use for Python baselines, before/after audits and authorized recovery research.
---

# Python Leakage Audit

Start with the unchanged original release and record artifact hashes, interpreter
version and package inventory. Derive a small known-sensitive corpus from owned
source or documented expectations and confirm positive hits in that baseline.
Preserve old evidence. Without the original, describe visibility of the supplied
release; do not claim improvement.

Read [operations.md](references/operations.md) for standalone commands, input
limits and exit codes. Read [recovery.md](references/recovery.md) for execution
boundaries, tested recovery results and optional native REA work. No REA or
third-party Python dependency is needed for the static helpers.

The audit helper scans UTF-8/UTF-16LE corpus bytes, Python AST definitions and
matching-interpreter pyc metadata/disassembly. It does not import the target.
Native code, unsupported bytecode and opaque archives remain explicit gaps.
Decompilation failure does not hide readable disassembly, names or constants.

Produce a private offline HTML leakage-location inspector with the JSON baseline:

```powershell
python <skill>/scripts/audit.py --package <original-release> --deny <sensitive-label> --out <private-baseline>
python <skill>/scripts/audit.py --package <protected-release> --deny <same-label> --baseline <private-baseline.json> --out <private-followup>
```

The interface provides file filtering, search and bounded offset/line or code
object detail, baseline corpus comparison, file hashes and unperformed checks.
It requires no server or network assets. Use distinct output prefixes outside
the release. An exact corpus hit is evidence; ordinary source/code-object names
are inventory, not automatically private. Compare profiles with their actual
inventories and interpreter dependencies; corpus comparison is not file identity.

Explicitly extract supported archives into a new private directory and rescan
their members. Preserve parent archive hashes and extraction manifests. Never
equate absent raw strings in an outer executable with protected inner bytecode.
Extracted Python/native files remain untrusted; extraction is not authorization
to run them. The bounded parsers are not an OS security sandbox.

For an authorized trusted demo, runtime capture requires explicit `--execute` in
a separate process under a deadline. Default to metadata observation. Experimental
`--dump-code` is only for reviewed ordinary CPython code; it crashed the tested
PyArmor runtime and is not a supported protected-object dumping method. Do not
patch protections or licensing as an incidental audit step.

For semantic recovery, give the recovery process only release artifacts and
retained analysis. Track analyst knowledge and all assistance; same-agent input
isolation is not blindness. Freeze the candidate, then use separate private
random/boundary tests to check it. Inspectable metadata, copied code objects,
replayed original functions, source decompilation and independently reconstructed
behavior are distinct outcomes. Do not call replay an independent rewrite.

Report behavior, direct selected-byte exposure, demonstrated recovery and cost
separately. Set an explicit effort budget, retaining actual elapsed observations,
crashes, provider gaps and unknown paths. A 15-minute upper bound is not proof
that 15 minutes were spent or that unfinished algorithms are unrecoverable.
Keep reports, captures, keys and reconstructions private. An audit-only request
does not authorize rebuilding, encrypting or publishing target artifacts.
