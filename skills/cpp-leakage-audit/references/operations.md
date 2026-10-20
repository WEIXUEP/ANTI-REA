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

The source scanner is line-based: it does not parse C++, evaluate macros, follow
includes or resolve effective compile options. Inspect compile commands manually
when interpreting conditional source evidence.

Package inspection inventories every regular file, including nonbinary assets.
Native metadata checks apply to native-looking members and explicit binaries.
Empty packages and symlinks are rejected; explicitly review/stage their regular
targets rather than claiming the omitted files were audited. Archive/object
formats, PDB contents and compressed debug data are not parsed.

## Baselines and Gates

Save the original report before repairs; capture is not a clean-release gate.
For provided post-repair artifacts, use `--baseline /private/reports/original.json`
with a new `--out`, identical binary/package ordering, names, corpus, allow rules
and `--all-strings` setting. Schema-2 reports fingerprint the scanner and artifacts.
Comparisons ignore byte-offset shifts but reject changed scope/inventory/scanner.
Review renamed resources or added files separately; never edit the old baseline.
Reports cannot overwrite inputs or enter a scanned release tree.

`--fail-on-deny` fails on exact denied bytes and confirmed private package
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
