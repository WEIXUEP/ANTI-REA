# Protection Integration Validation

Read this when testing the skill on a new project or validating a new protection
integration. Keep temporary fixtures outside the target repository when requested.
Do not replace production workloads with the fixture's performance assumptions.

For a downloaded-skill test, extract the allowlisted ZIP to a temporary directory
and run its scripts from a different working directory without the example's
`src` or `tools` on `PYTHONPATH`. Exercise key generation, map inventory,
decoding, environment checks and a trusted workload manifest. This tests actual
packaging independence rather than only file presence. Test standard-library-only
commands with optional dependencies unavailable; do not equate a dependency-free
string scan with a completed structured ELF/PE audit.

## Establish Evidence Before Repairs

- Use the target's existing auditor or available native inspection against the
  original program first. Preserve reports privately, with a SHA-256 inventory
  and confirmed positive controls. Baseline capture is observation, not a clean gate.
  Missing originals leave the improvement claim unverified.
- Keep a baseline and a stripped-only release using the same compiler, optimization
  and inputs. Preserve private debug builds. Record which actual installed files
  were scanned and measured.
- These are explicit comparison profiles, not deployment defaults. The default
  protected release must enable both stripping and baseline information protection;
  confirm the effective options in a fresh build cache. Do not inherit old OFF
  settings or let new defaults accidentally protect a baseline control build.
- Assemble a small, explicit sensitive corpus from real source evidence: selected
  diagnostics, condition expressions, internal types, functions, globals, source
  basenames and developer roots. Keep public ABI names on a separate required list.
- Confirm the selected auditor detects known leaks before treating their absence after
  a repair as meaningful. Check its configured failure gate; a scanner
  returning successfully by default only means the inventory ran.
- Separate confirmed byte matches, source candidates and metadata not inspected.
  A source diagnostic retained behind a disabled preprocessor branch need not be
  removed to protect the installed release.

## Verify Selection and Scope

List protected compilation targets and expected types/functions before building.
Check that all relevant producers and consumers use the same rules and key.
Adapt example namespace filters and per-function pass validators to the actual
project. Include local types, templates and compiler-generated closures when they
expose first-party names; do not rename dependency ABI types indiscriminately.

Inspect maps for expected entries, not just file existence. Zero selected records,
missing translation units or skipped required passes leave the corresponding
protection unverified even if compilation succeeds. Keep unrelated types and
required public exports functional. Report unsupported layouts explicitly.

For optional common-word names, use the per-channel gates in
[name-styles.md](name-styles.md). Validate actual final-PE alias visibility
separately from COFF renaming and map contents. Additional alias exports expose
addresses and need their own recorded selection. Preserve the original sensitive
corpus; do not count stripped private names as resolved original export leaks.

## Test Semantics and Recovery

- Exercise normal computation with an independent reference where practical.
  Include concurrency if the target uses it; do not infer thread safety from a
  single-threaded example.
- Check both passing and failing assertion conditions for single evaluation.
  Preserve warning routing, exception exit status, typed exception matching and
  abort behavior. Run intentional fatal tests only in isolated test processes;
  prevent their core dumps from leaving sensitive test data unintentionally.
- For RTTI, check cross-library downcasts, sibling casts when applicable, type
  equality, inheritance and exceptions, not only printed `typeid().name()`.
  On Windows use the [native acceptance contract](windows.md): independent
  EXE/DLL descriptors, hashes, ordering, failure casts, rethrows, exception_ptr
  and pointer exception conversions under both Debug and Release CRT settings.
- For sealed diagnostics, recover both template and dynamic fields, resolve the
  matching source map, and reject wrong keys, damaged payloads and mismatched
  release maps. Repeated logical sites need unambiguous location handling.
- For name aliases, recover emitted RTTI and exact function aliases from the
  matching release maps with the independently extracted skill. Map-only lookup
  must work without PyNaCl; the diagnostic private key is not needed for it.
- Check resource lookup and execution after copying the entire installed package
  to a new location. Inventory nonbinary assets too: aliases do not encrypt their
  contents. Private keys, IR, maps and debug files must stay outside that package.

For selected encrypted resources, run the separate acceptance workflow in
[runtime-resources.md](runtime-resources.md): authenticated metadata and payload
rejection, isolated installed consumers, complete incremental invalidation and
separate-process cache reuse. Scan any derived cache too. A deliberately embedded
resource key is recoverable runtime material; it does not relax isolation of
diagnostic private keys, naming masters or recovery maps. No resource packer/cache
runtime is bundled, so ordinary skill/package tests do not pass these gates.

## Use Fresh Artifacts and Interpret Findings

Use a clean or unique staging directory, and copy the release produced by this
run for relocation tests. Do not validate an old successful release while scanning
new build outputs. Keep artifact paths or hashes in the evidence. Repeat the same
corpus and public-name checks after repairs.
Use the selected auditor's baseline comparison, when supported, to compare findings
independently of byte offsets. Keep artifact roles and corpus unchanged. A renamed resource or
new package file requires an explicit inventory review, rather than quietly
dropping it from the post-repair scan. Scan full packages separately to catch
private PDBs, IR, maps and keys; scanning EXE/DLL alone is insufficient.

Review candidate paths in context. Sealed payloads can contain slash-separated
Base64 substrings; compiler URLs, loader paths and relative runtime paths may also
be intentional. Record a reason for each accepted exposure without hiding broad
classes of findings. Do not claim zero paths because the selected source-root
substring disappeared.

Measure build time, size, startup and representative workloads separately. Retain
sample ranges or dispersion and distinguish one clean-build observation from a
repeated statistical result. If no application performance budget exists, expensive
per-function choices remain pending; this is different from failed protection or
silently downgraded settings.

For VM targets, require applied-pass evidence for the actual function and use an
independent integer/reference oracle for runtime behavior. Separate these checks
from reverse-engineering resistance: wrapper/dispatcher pseudocode is not recovery
of the original algorithm. Preserve unresolved handler edges and require a
reconstructed computation tested on independent inputs before claiming successful
devirtualization. Compare the hot policy loop separately from startup and ordinary
numerical kernels; report combined VM/flattening costs as combined costs.

Conclude with resolved findings, intentional exposures, pending decisions,
unperformed checks and limits. Identify any project-specific adapter and manual
judgment used. A Linux guided trial does not establish Windows support or universal
automatic remediation.
