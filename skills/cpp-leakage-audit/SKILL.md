---
name: cpp-leakage-audit
description: Audit C++ source and native ELF/PE artifacts for exposed diagnostics, source paths, symbols and RTTI names, and implement scoped mitigations when requested. Use for reverse-engineering information-leakage reviews, not general vulnerability scanning or arbitrary binary rewriting.
---

# C++ Leakage Audit

## Establish the Target

Identify the requested source tree, build configuration, ABI, release artifacts
and public ABI. Distinguish first-party internals from dependency/runtime text and
intentional public API. Do not assume the existence of Clang, opt, ELF tools or a
Windows runner; inspect their availability and report unperformed checks.
Inspect the target's actual namespaces, types, targets and consumers before
reusing an example protector. Demo selectors and hard-coded function names are
not generic protection rules. State the helper's supported ABI and adaptations.

Read [remediation.md](references/remediation.md) when interpreting findings or
planning changes. It explains the distinctions that affect correct mitigation.

## Collect Evidence

Run the bundled standalone scanner:

```bash
python <skill-directory>/scripts/audit.py --source <source-root> \
  --binary <installed-executable> --binary <installed-library> --out <report-prefix>
```

Paths are always scanned. Add `--function`, `--variable` or `--deny` only for
requested names or an evidence-backed sensitive corpus. Preserve a confirmed
byte match separately from a candidate source/path match and an unperformed
structured-metadata check. Optional pyelftools/pefile improve inspection; without
them, disclose the gap rather than declaring the artifact clean.
Keep source, private-build and installed-release findings separate. Source macros
can remain intentionally available in an unprotected branch. Treat path-looking
ciphertext as a candidate: review the containing record and offset, not just a
slash match. Do not suppress all Base64-looking strings or all system names.

Check stdout/stderr from authorized normal and intentional-failure scenarios when
safe. Do not trigger fatal tests against production services. Compare build and
installed copies: debug separation, export policy and release stripping can differ.
Inspect package contents for PDBs, private maps, raw IR and keys.

## Propose or Implement Scoped Fixes

A request to audit is not authorization to mutate another codebase. For a review,
report prioritized findings with exact artifact offsets or source lines, their
likely origin, concrete mitigations and residual limitations. Provide a suggested
patch when useful. Apply fixes only when the user has requested changes or grants
the needed scope.

For authorized protection work, enable both release stripping and baseline
information protection by default: sealed diagnostics, opaque source locations,
internal RTTI names, path/resource hygiene and private-artifact isolation within
the authorized first-party scope. This is not the highest obfuscation preset.
Preserve the original build and private debug artifacts.
On ELF, strip the release copy; on Windows, retain private PDBs outside
the package and review PE debug records and exports rather than copying an ELF
strip command. Explicit user choices override this default. Audit-only requests
remain read-only.

Adapt baseline mechanisms to each leakage scenario and supported ABI. Missing
tooling or unsupported layouts leave baseline protection incomplete; report the
gap instead of silently producing an unprotected release.
Select additional function-level obfuscation and virtualization by function value,
frequency and performance budget. Use the selection guidance in
[remediation.md](references/remediation.md#function-value-and-performance-policy).
Diagnostics, paths and RTTI require their own mitigations; stripping does not
protect their runtime strings. Do not apply heavy transforms or virtualization
globally. With no performance evidence, leave hot or unclassified functions
unobfuscated and report the information needed to make a stronger selection.
Record selected functions, rationale, exclusions, accepted cost and actual applied
passes. Missing tooling or skipped required transformations are unmet checks,
not permission to silently downgrade an agreed protection profile.

Preserve diagnostic condition evaluation, failure/exception behavior, MPI routing
and numerical behavior. Prefer the owning project's centralized logging/error and
CMake interfaces. Do not remove RTTI or exports merely to silence a scanner.
Do not rewrite arbitrary bytes in EXE/DLL files or install an obfuscation toolchain
without authorization. Do not publish sensitive audit evidence or private keys.

After an authorized repair, rebuild affected producers and consumers, run focused
functional tests and re-scan the installed artifacts using the same corpus.
For RTTI changes include cross-library casts, type equality and exceptions. For
path/resource changes test relocation. For obfuscation verify actual applied-pass
reports and correctness, not just compiler success.
For a new integration or trial, read
[validation.md](references/validation.md) for coverage and negative controls.
Verify target selection against expected names; an empty map is not evidence of
successful protection. Test fresh staged artifacts rather than an old install.

Conclude with findings resolved, intentional exposures, checks not performed and
remaining limitations. Never equate zero string matches with inability to reverse
engineer the program.
Distinguish the scanner's automatic inventory from agent-guided fixes and any
target-specific adapter. Do not describe a successful guided trial as a universal
automatic repair engine.
