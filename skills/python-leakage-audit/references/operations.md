# Standalone Operations

Use Python 3.10+ for the helpers. pyc and PYZ decoding require the interpreter
whose magic matches the input; the verified case used CPython 3.12.14 Windows
x64. The static helpers use standard libraries only and work outside the checkout.

```powershell
python <skill>/scripts/audit.py --package <release> --deny <internal-type> --deny <resource-marker> --out <private-original>
python <skill>/scripts/audit.py --package <new-release> --deny <internal-type> --deny <resource-marker> --baseline <private-original.json> --out <private-new> --fail-on-deny
python <skill>/scripts/extract.py --input <archive-or-PyInstaller-exe> --out <new-private-members>
python <skill>/scripts/extract.py --input <members>/PYZ.pyz --out <new-private-pyz>
python <skill>/scripts/audit.py --package <members-to-review> --deny <internal-type> --out <private-member-report>
```

`audit.py` writes `.json` and `.html` using the specified report prefix. ASCII
absolute-path patterns are candidates, not automatically sensitive; code-object
filenames are also retained. It is not a universal Unicode string/secret scanner.
Existing
destinations, linked package inputs and report placement inside targets are
rejected. Baseline scanner/corpus mismatches require rescanning retained originals
into a new revision. Corpus comparisons show resolved/persistent/new labels, not
one-to-one artifact equivalence. Native binaries need a separate native analysis;
the helper records this gap even when its raw corpus scan completes.

Exit codes: 0 completed requested static inspection without recorded gaps;
1 selected corpus hits with `--fail-on-deny`; 2 invalid inputs, required metadata
gaps or failed worker inspection. A gap takes precedence over the corpus gate.
Review the saved report when code 2 accompanies usable partial observations.

The scan limits are 4096 regular files, 64 MiB per file and 512 MiB total;
source metadata parsing and pyc input are capped at 4 MiB. Corpus labels have
1..512 characters. A pyc subprocess has a 10-second deadline, with no target exec.
Code trees and inventories are bounded. These limits are not a process memory
sandbox against hostile Python runtime/marshal/parser defects.

`extract.py` supports ZIP, modern PyInstaller CArchive and matching-version PYZ.
It rejects unsafe paths, Windows device names, symlinks, case-insensitive duplicate
names, invalid bounds, oversize decompression and pre-existing destinations.
Budgets are 4096 members, 32 MiB per expanded member, 128 MiB total/input and
4 MiB marshal TOC. All members are validated before writing. Outputs include a
private `.extraction-manifest.json` binding the parent archive and member hashes.
Not every historical/future archive variant is supported. Nested archives need
explicit passes and fresh output directories.

Run extraction with an external process timeout when handling unknown inputs.
Do not deserialize unknown marshal data in the interactive analyst interpreter;
the CLI is disposable. Neither extraction nor pyc inspection executes Python
bytecode, but malformed input still reaches native standard-library parsers.

HTML escapes target strings and uses local-only assets with a restrictive CSP.
It shows bounded byte context, source lines or code-object disassembly; offsets
in extracted files refer to those files, with their parent identity retained by
the extraction manifest. Code-object lines are metadata, not proof of recovered
source. Open the HTML locally; do not upload it as a workaround for unavailable
browser previews.
