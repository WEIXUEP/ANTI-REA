# Numeric Masking: Baseline, Countertest and Evidence

Use when asked whether selected constants remain exposed or recoverable. These
are read-only static tools; neither command executes or modifies the target.
The pair probe needs standard-library Python 3.10+ only, not REA, Capstone,
private keys, PDBs, generated headers or the protection skill.

## Preserve Original Evidence First

Assemble the known sensitive corpus from authorized evidence, identifying any
original source/maps used as analyst assistance. Scan the original EXE and DLLs
before repairs; every selected constant needs an original positive control.
The example shows one value; repeat `--constant` for the complete selection:

```bash
python <skill-directory>/scripts/audit.py --binary /original/bin/app.exe --binary /original/bin/engine.dll --constant u32le:0x5a827999 --require-metadata --out /private/reports/original
python <skill-directory>/scripts/audit.py --binary /protected/bin/app.exe --binary /protected/bin/engine.dll --constant u32le:0x5a827999 --require-metadata --baseline /private/reports/original.json --fail-on-deny --out /private/reports/protected
```

Use identical ordered artifact names, corpus, allow rules and scanner version.
Scanner upgrades require re-scanning retained original artifacts into a **new**
baseline, not editing historical reports. Preserve exact hashes and failed runs.
For package-wide claims also inspect the entire staged package. Missing originals
leave before/after improvement unverified, but a supplied binary can still be
investigated for recoverability. See [operations.md](operations.md).

`audit.py --constant` checks literal byte patterns. A no-hit does not test
split immediates, transformed values or decoded runtime data.

## Adjacent XOR-Pair Probe

After the direct scan, run the independent countertest on **each** EXE/DLL:

```bash
python <skill-directory>/scripts/probe_constant_pairs.py --binary /protected/bin/app.exe --constant u32le:0x5a827999 --constant u32le:0xa341316c
```

JSON goes to stdout. Store it under a new private report path outside all release
trees using the caller's normal output capture; the helper creates no files.
For a separately requested numeric investigation, that saved JSON can optionally
use `scripts/report_html.py --view analysis`. The dedicated leakage-location
interface takes scanner audit JSON; see [html-reporting.md](html-reporting.md).
Reports contain binary/tool SHA-256, the explicit corpus, input size, unchanged
input verification, limits, coverage and file offsets. A candidate supplies
`left`, `right`, `offset`, `right_offset` and their known XOR value. Offsets are
file offsets, not VAs or RVAs. Every byte alignment is examined for two adjacent
little-endian unsigned 32-bit words; duplicate corpus entries are normalized.

The input limit defaults to 64 MiB. An empty, oversized or unreadable input is
rejected before scanning. Change `--max-bytes` explicitly for a larger artifact
with a reasonable analysis budget. `--max-findings` defaults to 1000. Reaching
the limit before the last window produces `complete=false`, retained candidates
and `status=incomplete`; rerun with an explicit larger limit when needed.
The helper rechecks input content after scanning and rejects changes.

| Exit | Meaning |
| --- | --- |
| 0 | Complete adjacent-pair search, no candidates for the supplied corpus |
| 1 | Candidates found, or coverage incomplete; inspect JSON |
| 2 | Invalid input/configuration, unreadable/oversized input or changed bytes |

This tool supports only `u32le:<integer>`; decimal and `0x` integer syntax are
accepted. The direct scanner supports additional widths, byte orders and floats.
The probe does not inspect separated shares, 64-bit pairs, arithmetic encodings,
instruction semantics, compressed data or runtime state. Even an exhaustive
no-candidate result only addresses this one representation. Random/unrelated
adjacent words can match the known corpus; candidates require review.

## Confirm Use and Scope the Conclusion

For PE candidates, use structured section metadata to map a file offset to an
RVA/VA; offsets in overlays may have no mapped VA. With an available REA backend
or instruction decoder, find references to **both** words and trace their XOR to
the selected function's computation. Record instruction addresses, artifact hash,
image base and evidence provenance. Check callers, callees, wrappers and shared
tables outside VM bodies. If no provider is configured, retain candidates and
mark reference confirmation unavailable; do not turn a backend error into a pass.
See [rea.md](rea.md) for provider use and [vm-recovery.md](vm-recovery.md) for
authorized dynamic observation and independent reconstruction validation.

| Evidence | Supported conclusion |
| --- | --- |
| Original exact bytes found, protected exact bytes absent | Selected direct-byte signature reduced |
| Adjacent pair XOR equals a supplied value | Known-corpus candidate; possible incidental match |
| Both shares referenced and XOR used by relevant code | Static known-corpus recoverability of that value |
| Independently compiled reconstruction matches held-out tests | Tested semantic recovery for the documented domain |
| Provider missing, queries fail or scan truncated | Incomplete investigation |

For the 2026-10-20 Windows demo at source revision `cdafd77`, this independent
probe was first tested outside the skill, then against retained final NONE and
MIXED_VM EXEs. It found five candidates covering all five known values in each,
with complete coverage and unchanged hashes. The separate retained Capstone
analysis confirms relevant references; the helper itself makes no such claim.
For example, offset 331744 in the MIXED_VM EXE contains
`0x93ed83e9 ^ 0xc96ffa70 = 0x5a827999`. Bind that example to SHA-256
`7abfbbd6362c0ddb65f15a874565d1d6c4f15622a3ddf12e4957cc425818a674`;
never reuse its offset against a different build. This was assisted known-corpus
recovery, not blinded algorithm recovery or complete devirtualization.
