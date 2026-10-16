# Offline Recovery Tools: CLI and GUI Design

Read this when a user requests diagnostic recovery tooling or improvements to
an existing decoder. These are implementation and acceptance guidelines, not a
claim that every feature below exists in the accompanying example project.
Keep the requested delivery scope: a headless script may be sufficient; an
optional GUI should not force a redesign of a working protection integration.

The bundled `scripts/decode.py` is an implemented headless decoder for the
example-compatible version-1 formats. See [operations.md](operations.md) for its
actual commands, limits and exit statuses. The broader GUI and format-adapter
guidance below must not be presented as features that script already provides.

## Contents

- [Recovery contract](#recovery-contract)
- [Shared Python architecture](#shared-python-architecture)
- [Key and map loading](#key-and-map-loading)
- [Headless interface](#headless-interface)
- [GUI workflow](#gui-workflow)
- [Security boundaries](#security-boundaries)
- [Acceptance tests and handoff](#acceptance-tests-and-handoff)

## Recovery Contract

Inspect the producer before designing the decoder. Record its envelope version,
key identifier, build/release identity, opaque location scheme, RTTI ABI and
formatting rules. Exercise real synthetic reports from that producer rather
than guessing its encoding from a screenshot. Keep fixtures free of private
paths, production keys and real customer logs.

There are separate operations with different required inputs:

| Operation | Required material | Expected result |
| --- | --- | --- |
| Sealed diagnostic recovery | Matching private key and supported ciphertext envelope | Template and captured dynamic fields |
| Source location lookup | Matching release's private location map | Original file, line and logical diagnostic site |
| Opaque RTTI lookup | Matching type maps, naming key identity and ABI | Original encoded name and readable type name |

A naming hash or opaque line identifier is not decrypted with a public-key
private key. It is resolved through a map unless the actual scheme specifies
otherwise. Likewise, a key file is not proof that a location map is loaded.
Report partial recovery explicitly: a message may be recovered while its
location remains unresolved, or a location may be known without a payload key.

Use one structured result per input event, with record index, kind, status,
recovered fields, key/build identity, map provenance and a stable error code.
Retain source order, including repeated events. Deduplicate identical map
records, not repeated log occurrences. Conflicting mappings must not produce an
arbitrary successful result.

## Shared Python Architecture

Prefer thin Python entry scripts and implementation modules under `src`:

```text
tools/decode.py                 Argument handling and frontend selection
src/recovery/
    keys.py                    Key loading, validation and public fingerprints
    discovery.py               Build-root and explicit map selection
    formats.py                 Versioned format adapters and input recognition
    decoder.py                 Recovery from a validated loaded snapshot
    cli.py                     Batch I/O, output format and exit status
    gui.py                     Optional desktop frontend
tests/                         Synthetic fixtures and frontend/backend checks
```

Adapt these responsibilities to the project's existing modules; this layout is
not a requirement to move unrelated files. Reuse the owning project's crypto
and map implementation instead of implementing a second incompatible decoder.
Keep parsing, discovery and recovery independent of widgets and `argparse` so
both frontends can use the same validated snapshot and result schema.

Import Tkinter or another GUI toolkit only when explicitly launching the GUI.
CLI import, `--help`, stdin decoding and batch jobs must work without Tkinter
or a display server. A requested GUI that cannot start should explain how to
use the CLI; it must not silently report successful decoding.

## Key and Map Loading

For generation, provisioning, backup and rotation rules, read
[key-management.md](key-management.md). Loading a decoder must not generate or
replace keys as a side effect.

Define a documented selection order: explicit input first, then trusted local
configuration, then a documented developer-only default. Anchor defaults to the
tool's installation or configuration directory, not the caller's working
directory. Never search arbitrary nearby folders for private keys. Do not fall
back to public teaching keys for an unknown production key identifier.

Allow a developer to select a build root rather than list every map file.
Discover only known private map layouts, or use a versioned build manifest.
Do not parse every JSON file below a build root: dependency metadata, input
models and compiler command databases are not recovery maps. Explicit map
files or map directories should remain available for archived releases.

For example, this project's current decoder uses `--build` and reads
`private/diagnostics.json` and `private/maps/*.json` below that build directory.
Those are example-project paths, not universal discovery rules. Another build
may produce separate diagnostic and RTTI trees; implement an adapter for the
observed layout rather than guessing or renaming it.

For each candidate, validate schema, version, field types and required identities
before admitting it into the active snapshot. Resolve and deduplicate paths;
apply file-count and size bounds. Match release/build identity, key ID and ABI
where the producer provides them. Multiple files for one identity are acceptable
only when their records merge consistently. Conflicts or ambiguous releases
require explicit selection or a clear failure, never "first file wins".

If the producer lacks a release identity or format version, disclose that
limitation and require explicit recovery-material selection. Do not invent a
compatibility check from directory names alone. For a new format, include a
versioned release manifest and map integrity metadata; hashes detect mismatches
but do not authenticate an untrusted map unless protected by a trusted signature.

Loading should return an inventory as well as usable records:

- Selected source and resolved map paths, with loaded/failed/unsupported states.
- Map kind, format version, build/key identity, ABI and usable record count.
- Duplicate/conflicting record counts and actionable validation errors.
- Key availability and public fingerprint, never private key bytes.

Archive keys and maps by release with access controls and backups. Key rotation
must preserve old recovery material for old reports. Do not overwrite an older
key/map pair or infer that a newer build's maps can decode an older log.

## Headless Interface

For new tools, a useful interface supports one token, an input report, or stdin;
explicit keys; a build root or repeatable maps; and JSON output. For example:

```bash
# Illustrative interface for a new decoder, not an existing project command.
python tools/decode.py --build /private/releases/r17 --report event.log --json
python tools/decode.py --map locations.json --map types/ --key-file key.json --stdin
```

Preserve a project's existing flags when extending it. Make input modes mutually
exclusive and never wait on stdin unexpectedly in an automated job. Accept
UTF-8 reports, optionally with a BOM, and define malformed-text behavior. Parse
mixed logs into bounded event records; do not accidentally associate a payload
with the next process's location. For concurrent or MPI logs, prefer producer
record IDs or atomic framing; reject ambiguous interleaved records.

Keep machine-readable results on stdout and operational errors on stderr. Define
stable exit statuses for complete success, invalid setup/input, and partial batch
failure. If best-effort recovery is supported, give every failed event its own
status and return nonzero for an incomplete batch. An empty result must not mean
success when a requested token was not recognized. Avoid leaking key contents
or decrypted data through exception traces.

Use file paths or an OS credential provider for keys, not secret bytes in shell
arguments. Support files/stdin for sensitive logs to avoid shell-history exposure.
Only write recovered plaintext when an output destination is explicit; document
overwrite policy and use restrictive permissions where the platform supports
them. Print concise errors for wrong keys, missing maps, unsupported versions,
map conflicts and damaged ciphertext instead of retrying unrelated keys silently.

## GUI Workflow

Choose a lightweight toolkit appropriate to the deployment. Tkinter is a useful
optional Python desktop baseline; it is not required for all projects. Keep all
labels and help in the requested interface language. Prioritize data inspection
over decorative UI, and expose three connected work areas:

| Area | Visible information and actions |
| --- | --- |
| Recovery material | Build root, key fingerprint/availability, loaded map inventory, add/remove/reload and inspect actions |
| Input | Paste protected text or open a report; explicit Decode and Clear actions |
| Results | Event summary, recovered message/dynamic fields/location or type, provenance, errors and deliberate copy/export |

Distinguish selected sources from successfully loaded maps. Show resolved paths,
map kinds, release identities, ABIs and counts in an inspectable list, not just
"Maps loaded". Permit developers to search opaque IDs and inspect original
file/type records without displaying secret key material. Show loaded rows
separately from displayed/paginated rows so truncation does not imply missing
data. Maps themselves are sensitive developer-only information.

Use the exact snapshot shown in the inventory for decoding. On a key, build or
map change, clear old results or mark them explicitly stale. A failed reload
must not leave the old inventory presented as newly loaded. Keep any previous
snapshot only with a clear indication and explicit selection. Missing optional
maps may permit partial recovery, but unrelated successful loads must not hide
the failure of a required source.

Support window resizing, scrollable long paths/messages and readable tabular
columns. Large-map loading and log decoding should not block the event loop;
use bounded background work and update widgets on the UI thread. Snapshot
generations should prevent a late result from overwriting a newer selection.
Provide progress and cancellation when processing large inputs, with explicit
limits rather than trying to render millions of rows.

No automatic plaintext saving, clipboard writes or remote telemetry. Make copy
and export intentional actions, show their destination, and warn that recovered
logs/maps may contain confidential data. Clear/reset should remove active input
and results from the UI, without promising secure memory erasure.

## Security Boundaries

Use maintained libraries such as libsodium/PyNaCl for the actual producer's
cryptosystem. Do not substitute homemade XOR, Base64 or a naming hash for
encryption. The shipped runtime needs only the public sealing key; developer
private keys and recovery maps must stay out of installation packages.

Validate envelope versions, encodings, lengths and decoded structures before
formatting. Bound nested payload depth, field count and output expansion. Use
the producer's supported placeholder grammar, not `eval`, template execution,
unpickling or imports selected by input data. Check that payload identity and
location agree with the selected map where the format supports this binding.

Sealed-box integrity does not authenticate the sender: anyone with the public
key can create a valid encrypted event. Do not treat successful decryption as
evidence that an event came from a trusted customer process. Apply separate
authentication if that is required.

Operate offline by default, with no automatic network lookup of keys, maps or
source files. Do not execute recovered text or automatically open recovered
paths. Preserve terminal/UI safety when displaying untrusted control characters.
Do not log secrets or full decrypted records in crash diagnostics. Python cannot
guarantee secure memory erasure; disclose this instead of claiming that clearing
a widget wipes every in-memory copy.

## Acceptance Tests and Handoff

Exercise observable behavior with synthetic keys and reports:

- Resolve defaults after invocation from another working directory; verify
  explicit overrides and relocated tool installation.
- Discover diagnostic and RTTI maps from one build root; show exact inventory,
  useful record counts and failures. Test multiple ABIs and duplicated maps.
- Recover original message, dynamic values, source position and type names;
  verify GUI and CLI return the same results from the same snapshot.
- Decode old/new releases after key rotation; reject wrong keys, conflicting or
  mismatched maps, damaged ciphertext, unknown versions and malformed records.
- Handle empty input, unrecognized tokens, repeated events, mixed valid/invalid
  reports, oversized input and ambiguous interleaving without false success.
- Run CLI help and batch recovery without Tkinter and without a display server;
  test requested-GUI failure separately. Test GUI loading states, filtering,
  reload invalidation and nonblocking behavior if a GUI was implemented.
- Ensure failures do not expose private key bytes, plaintext payloads or unwanted
  tracebacks; export plaintext only on request. Inspect the release package for
  accidentally included private keys, maps, IR and debug files.

Hand off supported input formats, exact launch commands, default resolution
rules, map locations, key fingerprints and tested platforms. Separate verified
behavior, design-only guidance and unsupported cases. A CLI-only implementation
is a valid deliverable when that is the requested scope; do not claim GUI
acceptance checks passed without executing the actual interface.
