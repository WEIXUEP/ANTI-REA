# Independent Audit Operations

Use Python 3.10+. Basic scans require only the standard library. Install optional
`scripts/requirements.txt` in a selected environment for pyelftools/pefile when
authorized; record versions. No compiler, example checkout or network is needed
to inspect existing artifacts. Do not install dependencies silently.

## Commands and Inputs

```bash
python <skill>/scripts/audit.py --source /authorized/source \
  --binary /original/app --binary /original/engine.so \
  --deny-file sensitive-corpus.json --require-metadata \
  --out /private/reports/original
python <skill>/scripts/audit.py --package /staged/release \
  --fail-on-private --require-metadata --out /private/reports/package
```

Use repeatable `--binary` and `--package`. Paths/source basenames are always
scanned; `--function` and `--variable` default to empty. Exact sensitive text can
be supplied with repeatable `--deny` or a UTF-8 JSON array:

```json
["Private coefficient solve failed", "__internal_policy_flag", "kernel.cpp"]
```

Exact corpus checks include UTF-8 and UTF-16 bytes, including short/multiline
strings. `--all-strings` adds printable ASCII and ASCII-range UTF-16 inventory,
not a full Unicode/disassembly/memory scan. Evidence is bounded to 1024 characters
per finding; the offset points to the match.

Use repeatable `--constant type:value` for a reviewed numeric corpus. Supported
types are `u32le`, `u32be`, `u64le`, `u64be`, `f32le`, `f32be`, `f64le`, `f64be`.
Unsigned integers accept decimal or `0x` notation; finite floats use decimal
notation and IEEE-754 binary32/binary64 packing. Width and byte order are never
guessed. Out-of-range values, NaN and infinity are rejected.

```bash
python <skill-directory>/scripts/audit.py --binary /original/app.exe \
  --constant u32le:0x5a827999 --constant f64be:0.125 --out /private/numeric-before
```

`specified-constant` records exact raw-file offsets, including overlapping byte
matches. It does not prove a numeric type or executing use. Small/common values
can produce many incidental hits; compiler folding, split immediates, encryption
and different representations can hide selected values. No disassembler runs.

The source scanner is line-based: it does not parse C++, evaluate macros, follow
includes or resolve effective compile options. Inspect compile commands manually
when interpreting conditional source evidence.

Package inspection inventories every regular file, including nonbinary assets.
Native metadata checks apply to native-looking members and explicit binaries.
Empty packages and symlinks are rejected; explicitly review/stage their regular
targets rather than claiming the omitted files were audited. Archive/object
formats, PDB contents and compressed debug data are not parsed.

## Baselines and Gates

`--out` writes private JSON, Markdown and offline HTML. Read
[html-reporting.md](html-reporting.md) for the final analysis deliverable,
cross-report navigation and the independent `scripts/report_html.py` renderer.

Save the original report before repairs; capture is not a clean-release gate.
For provided post-repair artifacts, use `--baseline /private/reports/original.json`
with a new `--out`, identical binary/package ordering, names, corpus, allow rules
and `--all-strings` setting. Schema-2 reports fingerprint the scanner and artifacts.
Numeric constant specifications are also part of the comparison scope. A scanner
upgrade requires a fresh original baseline; retain earlier reports unchanged.
For masked DWORD constants, follow [numeric-recovery.md](numeric-recovery.md)
after the exact-byte scan. The independent `scripts/probe_constant_pairs.py`
requires only standard-library Python and supplies known-corpus candidates,
explicit coverage and integrity checks; it does not confirm executing code use.
Comparisons ignore byte-offset shifts but reject changed scope/inventory/scanner.
Review renamed resources or added files separately; never edit the old baseline.
Reports cannot overwrite inputs or enter a scanned release tree.

`--fail-on-deny` fails on exact denied/name/numeric-constant bytes and confirmed private package
findings; `--fail-on-private` gates private findings separately.
`--require-metadata` fails when requested native checks cannot be performed.
None proves all candidate paths or possible exposures have been eliminated.

Allow intentional public names using `--allow <allowlist.json>`:

```json
[{"pattern": "^public_engine_create$", "reason": "Versioned public C ABI"}]
```

Rules apply across evidence categories. Keep them narrow, review their actual
matches and retain allowed evidence with reasons.

| Exit | Meaning |
| --- | --- |
| 0 | Inventory and enabled gates passed, not necessarily no findings |
| 1 | Requested deny/private gate failed |
| 2 | Invalid input/configuration/baseline or required metadata incomplete |

Keep raw reports private. Missing metadata, unsupported formats and incomplete
runtime coverage remain explicit limitations.
