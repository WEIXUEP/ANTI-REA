# Using the Audit Skill

The self-contained `cpp-leakage-audit` skill helps a coding agent audit native
artifacts and carry out scoped repairs when authorized. Its scanner is a Python
tool; remediation still requires project-specific decisions and validation.

## Get the Skill

[Download the skill archive](downloads/cpp-leakage-audit.zip) and extract the
`cpp-leakage-audit` directory into your agent's skill directory. Alternatively,
copy `skills/cpp-leakage-audit` from a repository checkout. The project does not
install it globally or change an agent's settings automatically.

The archive contains only the canonical instructions, remediation and validation
references, standalone scanner and agent metadata. It contains no cryptographic
keys, native binaries, private mappings or LLVM toolchain.
The project license is included with the downloadable source.

Read the published [skill instructions](skill/index.md),
[remediation policy](skill/references/remediation.md) and
[validation guide](skill/references/validation.md) and
[Windows acceptance](skill/references/windows.md). These pages are generated
from the same files packaged in the archive, not separately maintained copies.

## Audit Without Changing Code

A useful agent request specifies the source root, installed artifacts and scope:

```text
Use cpp-leakage-audit to inspect this C++ project and its installed executable
and shared library. Audit only; do not modify code. Distinguish internal data
from required public exports and dependency strings. Report evidence and gaps.
```

You can also run the standalone scanner directly:

```bash
python skills/cpp-leakage-audit/scripts/audit.py \
  --source /path/to/source \
  --binary /path/to/release/program \
  --binary /path/to/release/library.so \
  --out build/target-audit
```

Paths are always inventoried. Function and variable name lists are empty by
default; add `--function`, `--variable` or `--deny` for an evidence-backed corpus.
Use `--fail-on-deny` when a confirmed sensitive match must fail an automation job.
Install `pyelftools` for ELF inspection or `pefile` for PE inspection; missing
parsers are reported as unperformed checks, not a clean result.

The skill starts by scanning the original program before repairs. Preserve that
report as the baseline; confirm it detects the known leaks. Every binary report
records artifact roles, sizes and SHA-256 fingerprints. After rebuilding, pass
`--baseline build/baseline-audit.json` and a different `--out`, with the same
binary ordering, filenames, corpus and allow rules. The JSON and Markdown reports
distinguish resolved, persistent and introduced findings independently of offsets.
The scanner rejects changed scope or inventories instead of claiming improvement
from a smaller scan. Missing original artifacts leave the comparison unverified.
Reports also fingerprint the scanner; comparisons require the same scanner
version. Outputs cannot overwrite input artifacts or be written into the scanned
release directory.

Use `--require-metadata` to fail when ELF/PE checks cannot be completed. Use
`--package <fresh-staging-directory>` to scan all installed files, including assets,
and flag private PDBs, keys, maps, object files and raw IR. Together with
`--fail-on-deny`, those private-artifact findings fail the release gate. Filename
classification is a heuristic; review the full inventory too. Package changes
such as resource aliases need a separate inventory review when the original and
protected manifests intentionally differ.

## Authorize Scoped Protection

```text
Use cpp-leakage-audit to audit and repair first-party information leaks in this
project. Enable release stripping and baseline information protection. Preserve
the public ABI, RTTI and exception behavior. Keep numerical hot loops unchanged.
Propose per-function obfuscation or VM only with a measured performance budget.
Rebuild, test and re-scan the actual installed package.
```

The default authorized policy enables stripping plus diagnostic, source-location,
internal RTTI and path/resource protection. It does not authorize arbitrary
dependency changes, blanket binary string replacement, toolchain installation or
unreviewed heavy transformations. Audit-only requests remain read-only.

## Review the Outcome

Expect resolved findings, intentional public exposures, pending decisions and
unperformed checks. Confirm coverage across producers and consumers, exercise
failure and recovery paths, and test relocation using this run's release files.
Unknown performance requirements leave expensive function transforms pending;
they do not justify silently disabling baseline information protection.

A zero selected-corpus count does not establish that every string is hidden.
See [measurement interpretation](measurement.md#interpreting-results-honestly)
and [remaining exposure](remaining-exposure.md).
