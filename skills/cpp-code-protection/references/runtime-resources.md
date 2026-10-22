# Encrypted Runtime Resources and Persistent Derived Results

Read when an authorized protection task includes resource contents that the
application must consume locally, or reusable results derived from those contents.
The source checkout includes an independent Windows case in
`cases/runtime-resources`, with a CNG packer, memory consumer and numeric-data
cache. The downloaded skill remains integration guidance and does not bundle
those binaries or source files. Its `generate_keys.py` and `decode.py` cover
diagnostics/names, not resource keys or bundles. The resource case has its own
validator; the RTTI demo validator does not validate this mechanism.

## Choose the Correct Security Boundary

Separate these modes before choosing keys or changing a producer:

| Mode | Runtime material | Protection boundary |
| --- | --- | --- |
| Offline-recoverable diagnostics | Public sealing key; private recovery key stays with developers | Runtime cannot decrypt sealed events using only its own key material |
| Locally consumed encrypted resources | Symmetric key, or access to a configured decryption service | Embedded keys and decrypted contents can be recovered by an analyst |
| Persistent derived-result cache | Derived binary output and dependency identity | Reuse and corruption detection; not automatically confidential or authenticated |

Use resource encryption to avoid distributing directly readable resource files.
Do not promise resistance to debugging, memory extraction or reverse engineering.
Do not reuse diagnostic private keys or naming secrets as resource keys. Do not
invent a remote key service, licensing workflow or new dependency unless scoped.
Public interfaces and third-party resources stay outside the selected owned scope.

Keep this mode opt-in. Before edits, inventory the original installed resources,
lookup rules and existing caches, hash the artifacts, and capture positive leaks
with the original sensitive corpus. Preserve an OFF control and independent
expected consumer results. Use the same corpus for final binaries, resources,
logs and caches; identify explicitly supported external plaintext separately.

## Build-Time Packaging

Inspect how resources are located and consumed, their nested dependencies, and
which files must remain public. Prefer a narrow resource-provider interface over
rewriting consumers. Preserve the existing behavior when protection is OFF.
Expose requested and effective protection states and disabled reasons. Preserve
the project's existing Debug/Release policy; do not infer that one policy fits all
targets or silently emit an unprotected package after a packaging failure.

Use a maintained cryptographic library or platform provider for authenticated
encryption. AES-256-GCM is one suitable choice: a 32-byte key, unique 12-byte nonce
per encryption under that key, and a 16-byte tag. Use cryptographic randomness for
new keys. For nonces, use the provider's documented uniqueness strategy and
per-key invocation limits across all builds, packer processes and retries. Random
96-bit nonces require a bounded collision budget; randomness alone does not
guarantee uniqueness. Never reuse a nonce with changed plaintext or authenticated
metadata under the same key. Never implement AES/GCM from
scratch or replace authentication with a checksum. Existing key reuse/rotation
requirements take precedence over creating fresh keys for every build.

On Windows, CNG provides AES-GCM and system randomness through `bcrypt.lib` without
another cryptographic dependency. Include `windows.h` before `bcrypt.h` and keep
that order when formatting. Other platforms should use an appropriate maintained
provider; Windows CNG is an example, not a portable requirement.

Serialize a versioned manifest of logical resource identifiers, bounded sizes and
contents. Encrypt names too if their plaintext disclosure is in scope. Normalize
internal references only as required by the consumer; preserve lookup semantics,
include resolution and caller-supplied resource precedence. Register all inputs,
the packer and effective key identity as build dependencies so incremental builds
cannot retain stale bundles. Track the resource inventory as well as file contents:
additions, deletions, renames and a changed key at the same path must invalidate
packaging. Keep the generator and generated packaging files out of installation.
Key bytes must not be printed in build logs or command lines.

Define the envelope separately from the encrypted manifest. Bound all outer lengths
before allocation or decryption; authenticate interpretation-critical version,
algorithm, bundle identity and key-selection metadata as additional authenticated
data (AAD), or place them inside the authenticated ciphertext. Treat cleartext key
IDs as untrusted selectors until authentication succeeds. Reject duplicate or
ambiguous logical identifiers under the consumer's actual lookup rules. If using
compression, enforce a bounded decompressed size after successful authentication.

Generate a private compilation unit containing the encrypted bundle and the
runtime material needed to decrypt it. If a key ships with the bundle, describe
it as recoverable material; splitting or masking it does not make it secret.
Do not imply that bundle encryption also hides archive members, symbols, debug
metadata, logical identifiers used elsewhere, or public interfaces.
GCM authenticates possession of its symmetric key, not publisher identity once
that key is recoverable. If origin authentication is required, use a separate
signature/trust design with verification material in the runtime and signing
secrets kept outside it; symmetric encryption alone does not supply that claim.

## Runtime Consumption and Installation

Authenticate before exposing any decrypted output. Check format version, counts,
sizes, offsets and string bounds before use. Authentication or parsing failure
must produce a bounded error without plaintext fallback, source snippets, keys
or sensitive paths in logs. Preserve error/abort behavior and caller contracts.
Some APIs write provisional plaintext before tag verification finishes. Quarantine
that buffer: no parsing, consumer calls or persistence until authentication has
succeeded, and wipe it after failure.

Pass decrypted buffers directly to a consumer that accepts memory resources.
Bound plaintext lifetime and wipe owned sensitive buffers on all exit paths.
Do not claim complete erasure of copies in strings, allocators, operating-system
buffers or external libraries. Reject an incompatible consumer explicitly if its
only implementation writes plaintext temporary files; do not silently downgrade.

Remove protected plaintext resources from installation and default physical
lookup roots. Retain public SDK files and explicitly supported external-resource
loading. Use a fresh staging destination: exclusion rules do not remove plaintext
left by an older installation. Scan the complete staged inventory, not only the
main library. Build trees are separate private artifacts, not deployment packages.

## Optional Persistent Cache

Cache derived results only when reuse materially helps repeated runs. Record
whether an artifact is native binary, bytecode or textual assembly: these can
still disclose names, paths and recoverable logic. Source-bundle encryption does
not encrypt the cache, and renaming its directory is not a security control.

Use a user-scoped directory, a format namespace/version and a documented override
or disable setting. Verify actual directory access controls; a user-looking path
or override does not establish trusted ownership. Honor the user's naming and
platform conventions. Missing, corrupt, incompatible or unwritable entries should
normally fall back to ordinary
computation. This differs from authentication failure of the required source
bundle, which must not fall back to a plaintext resource.

Hash all semantic inputs: resource contents, recursively resolved external
dependencies, parameters, target architecture, effective options and relevant
producer/runtime versions. Use length-prefixed or otherwise unambiguous encoding
and a versioned key domain. Prefer contents over timestamps. Decide whether
same-version tool replacements require a binary fingerprint; version numbers
alone do not identify every hotfix. Avoid using randomized ciphertext or bundle
nonces as semantic identity when unchanged plaintext should reuse results.
Compute that identity from validated, authenticated inputs; a cache hit must not
bypass validation of the selected required bundle. A resource-key rotation must
repackage the bundle and update its runtime material consistently; decide whether
derived outputs also need invalidation for a changed trust policy, even if the
plaintext semantics are unchanged.

If dependency discovery cannot prove coverage, bypass reuse. A regex is not a
complete preprocessor or dependency parser. Snapshot inputs when practical, or
recheck identity before publication and state residual concurrent-change limits.
Do not assume a before/after check makes arbitrary concurrent edits atomic.
Validate size, format and payload before use; failed loading triggers recomputation.
Keep cache paths within the intended root and handle symlinks/reparse points
according to the threat model. Use exclusive temporary-file creation in that
directory and publish through atomic replacement. Treat concurrency,
cleanup/eviction and schema migration as explicit decisions, not implied features.

An unkeyed SHA-256 payload hash detects corruption, not malicious replacement by
someone who can write the cache. If untrusted cache writers are in scope, choose
access restrictions and a verified authenticity design before loading executable
results. An integrity key shipped in the same program is not a private signing
authority. Do not add cache encryption or claim authenticity without implementing
and testing the corresponding key/trust boundary.
Verify trust and integrity before invoking a native/bytecode loader: rejecting
a bad entry after loading can be too late. Consume the verified bytes or a stable
handle/snapshot; checking a file and reopening a replaceable path leaves a race.

## Acceptance and Handoff

### Independent Windows Case

From an existing ANTI-REA checkout with Python dependencies, CMake/JOM and the
selected Windows developer environment:

```powershell
python tools/validate_resources_windows.py `
  --llvm-bin F:\Program_Professional\xollvm-windows-llvm23-Release\bin `
  --environment F:\Intel\oneAPI\setvars.bat --jobs 8 `
  --out F:\tmp\resource-acceptance-r001
if ($LASTEXITCODE -ne 0) { throw "Resource case acceptance failed" }
```

Use a fresh output directory. The validator copies the case before mutating
fixtures, builds Debug/Release protection OFF/ON, and retains logs, hashes and
`result.json`. The case's `AR_ENCRYPT_RESOURCES` switch defaults OFF;
`AR_RESOURCE_KEY_FILE` selects an explicitly generated private state file.
These are case-specific CMake options, not universal integration switches.
The build-only `resource-packer keygen <new-file>` uses exclusive creation.
The key state contains an AES key, nonce prefix, counter and corruption checksum.
Packing locks it, validates it, reserves and flushes the next counter before
encryption. Preserve the active state with its key; do not roll it back, clone it
into independent active writers, or recreate missing state for the same AES key.
Checksum failure and a conservative per-key budget of 2^20 encryptions stop
packaging (each plaintext is bounded to 4 MiB). This is not a claim of
transactional recovery from every storage/power-loss failure.

The consumer handles a small explicit three-level text-resource grammar and
derives a uint32 lookup table, checked against independent Python arithmetic.
It authenticates/parses the required bundle before a cache hit or explicit
`--external-dir` override. `--bundle` selects an alternate encrypted bundle for
validation using the same embedded key. Default lookup uses only the embedded
bundle or installed OFF resources beside the executable, never the source tree.
`--cache-dir`, `--no-cache` and `--option` exercise reuse controls. The default cache
is under `%LOCALAPPDATA%/ANTI-REA/resource-demo/v1`.

Cache identity covers all sorted resource contents/names, the numeric option,
pointer size, producer-source/compiler fingerprints and build flags. The case
invalidates even unused-resource changes conservatively. It does not fingerprint
the full EXE because that would include randomized bundle ciphertext. Unchanged
semantic data can reuse the numeric cache after repacking or resource-key rotation,
but only after authenticating the current bundle. This reuse is specific to
non-executable derived data; a target with a different trust policy may need a
separate trust-version field and mandatory invalidation.

The cache uses bounded snapshots, a versioned header and SHA-256 corruption
checks, unique exclusive temporary files and atomic publication. It does not
execute cache bytes or authenticate them against a malicious writer. The case's
countertest forges data plus its hash to demonstrate that limitation; the normal
numerical oracle must still pass for all trusted-cache scenarios. Explicitly
recorded interrupted-temp tests simulate partial files, not a storage power cut.
No compression, universal dependency resolver or resource decoder is bundled
with the skill. Embedded keys and logical names still used by the consumer
remain observable; the tested secret corpus consists of selected resource labels.

Native Windows x64/clang-cl 23.1.2 acceptance on 2026-10-22 passed Debug/Release
OFF/ON plus a rotated-key installation, with 171 recorded assertions. Selected
original labels were positive in OFF resources and absent from protected packages
and scanned caches. Seven-sample Release internal medians were 6.53 ms cold,
0.70 ms warm and 4.80 ms disabled; process medians were 14.80, 7.37 and 12.98 ms.
These are local case observations, not an accepted application budget or isolated
encryption cost. The known-key byte-location and forged-cache countertests
confirmed the stated limits; neither is evidence of blinded reverse engineering.

### Target Integration Checks

- Keep original and protection-OFF controls; verify normal results independently
  of cache-hit messages and resource names.
- Test encryption/decryption and rejection of wrong keys, altered ciphertext,
  damaged tags, changed AAD and malformed/truncated manifests. Check duplicate
  identifiers, oversized lengths and decompression limits where applicable. Verify
  rejected plaintext never reaches a consumer. Never count unrun tests as passed.
- Install to a fresh prefix without selected plaintext resources, empty the result
  cache, and exercise real consumers in an isolated copy or sandbox without source
  lookup roots; do not move/delete the working sources or
  installed dependencies to prove isolation. Test relocation and explicit external
  resource precedence separately.
- Run separate processes to verify reuse. Change a nested dependency and a
  meaningful option; verify misses and changed results where applicable. Add,
  delete and rename a resource, then rotate its key at the same configured path;
  verify incremental repackaging and behavior against a clean build.
- Test disabled reuse, unsupported dependency forms, corrupt entries, load failure
  and unwritable directories. Confirm a warm cache cannot bypass rejection of an
  invalid required bundle. Exercise concurrent writers and interrupted publication
  when sharing is supported; never load unverified executable output as a test.
- Inspect distributed files, logs and cache artifacts against an unchanged known
  sensitive corpus. Check paths, names, metadata and content as separate channels.
  Zero selected byte matches is not proof of zero leakage or recovery resistance.
- Measure first-run and warm-cache latency separately, including loading, hashing,
  decryption and memory costs; successful reuse does not prove an acceptable budget.

Report actual effective controls, installed inventory, checks performed, remaining
plaintext copies, recoverable key material, unsupported consumers/platforms and
cache limits. Keep artifact identity, behavior, direct-byte hiding, authenticity,
reverse-engineering resistance and performance verdicts separate.
Skill validation, archive tests and documentation builds validate distribution
and references only. The case's native acceptance is separate evidence. For any
other target, keep runtime acceptance pending until its implementation passes
the applicable checks; the case does not establish arbitrary application support.
