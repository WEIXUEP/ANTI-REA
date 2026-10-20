# Leakage Diagnostics Interface

For a leakage audit, deliver a dedicated offline HTML interface showing **what
leaked, in which file, and at which location**. Retain the JSON baseline and raw
evidence. The default deliverable is a leakage inspector, not an aggregate
analysis dashboard, performance report or collection of REA transcripts.
Honor an explicit user request for another format.

## Generate and Open

`audit.py --out <prefix>` writes `<prefix>.html` together with `.json` and `.md`.
Open the HTML directly. The scanner collects bounded source/byte context while
it reads the inputs; the HTML does not need to reopen binaries or source files.
Reports stay private and outside every release package.

To render an existing schema-2 audit JSON:

```bash
python <skill>/scripts/report_html.py --input /private/leakage.json --view leakage --out /private/leakage-locations.html --package-root /staged/release
```

Repeat `--input` for multiple audit snapshots, and `--package-root` for all release
roots. `--lang en` selects English; default is Chinese. Auto view selects this
interface when all inputs are leakage audits. `--title` overrides the page title.
The standalone renderer accepts at most 32 MiB per input, creates a new `.html`,
never replaces existing files and returns 0 for rendering success or 2 for errors.
Rendering success does not mean the audit passed.

The complete skill contains `report_html.py` and `leakage_html.py`; distribute
both. Standard-library Python 3.10+ is sufficient for rendering. No web server,
CDN, target execution, external font or network service is required.

## Reading and Location Behavior

- Left: the scanned file list and occurrence counts. Select a file to narrow the
  list. When combining snapshots, retain their source-report identity.
- Center: a compact list of exposed contents, categories, review status and
  source line or raw binary offset. Search and category/status filters work on
  the recorded evidence, filenames and offsets.
- Right on desktop, below the list on narrow screens: the selected occurrence's
  complete content, file, encoding, available SHA-256, exact location and context.
  Clicking a list entry selects its details. Stable fragment links reopen that
  occurrence; filtering cannot permanently hide a linked location.
- For source findings, highlight the matching line and show at most two nearby
  lines on each side, bounded to 1024 characters per line. This is captured text,
  not proof that a preprocessor branch was compiled.
- For binary findings with offsets, show a bounded hex/ASCII excerpt and highlight
  the matching bytes. Context shows at most 16 leading bytes, 32 match bytes and
  16 following bytes. Long matches can continue beyond the excerpt. Keep the
  file offset distinct from RVA/VA; never invent a source line or virtual address.
- Older JSON may have no context; state that explicitly. Metadata-only findings
  may lack precise byte positions. Do not fabricate them by searching for a
  symbol name that might occur more than once.

The visible states distinguish exact known-sensitive hits, review candidates and
allowed names. A parsed symbol or path is not automatically a confirmed leak of
owned secrets. Imports, machine type and general readable-string inventory are
ordinary metadata, hidden by default behind an explicit inventory toggle.
They remain in JSON and can be displayed; this UI separation does not alter audit
gates, allow rules or baseline comparisons. Actual denied/selected-name matches
remain visible even if the same text also occurs in metadata.

Show missing metadata/coverage checks prominently. Keep scanner scope, baseline
comparison, fingerprints and raw records expandable so users can verify a result
without making them the primary screen. A zero-result state does not mean no
leakage exists outside the scanned corpus and channels.

## Interface and Evidence Rules

Use an available frontend design skill when customizing this inspector; the
downloaded audit skill must still work without it. Use a compact work-focused
layout, restrained light colors, clear status accents and monospace only for
code/addresses/hashes. Keep sections unframed. Wrap long paths and strings and
provide visible keyboard focus. Avoid marketing composition or decorative media.

All extracted content, paths and symbols are untrusted text. Escape them instead
of rendering raw HTML, executing commands or opening arbitrary URLs/tool links.
The bundled page uses a restrictive content security policy and hash-restricted
inline assets, without external requests. Never publish private reports, extracted
secrets or target evidence with the public documentation or skill ZIP.

Validate actual selection, file/category/status filters, search, deep links,
highlighted source/hex locations, empty states and metadata visibility. Inspect
desktop/mobile screenshots and check that hostile strings remain inert. With
JavaScript disabled all recorded details must remain readable. Report any browser
behavior that could not be checked.

Scanner-code changes invalidate a current baseline comparison. Re-scan preserved
original artifacts into a new baseline; do not overwrite historical evidence.
The renderer can display older audit JSON without certifying its current validity.

## Other Analysis Modes

`rea_audit.py` still writes its own `report.html`. An explicit
`report_html.py --view analysis` can render REA triage, numeric-pair and authored
`kind=analysis` JSON for a separately requested investigation. These are optional
analysis views; do not substitute them for the leakage-location interface or
automatically combine VM/performance material into a leakage diagnosis.

## Handoff

Link the leakage HTML first. Briefly identify important leaked contents, their
files/locations and unperformed checks; link JSON/raw evidence when useful.
