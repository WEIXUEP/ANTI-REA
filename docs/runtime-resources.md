# Windows Resource Encryption and Cache Case

[简体中文](runtime-resources.zh-CN.md)

`cases/runtime-resources` is a separate C++/CMake case using Windows CNG
AES-256-GCM. It has no application or numerical-library dependencies. It consumes
three nested text resources in memory and derives a uint32 table. Its persistent
cache contains ordinary binary numbers, never executable code.

## Run Native Acceptance

Use an existing Windows developer environment, CMake/JOM, Python requirements and
an installed clang-cl. From the repository root:

```powershell
python tools/validate_resources_windows.py `
  --llvm-bin F:\Program_Professional\xollvm-windows-llvm23-Release\bin `
  --environment F:\Intel\oneAPI\setvars.bat --jobs 8 --samples 7 `
  --out F:\tmp\resource-acceptance-r001
if ($LASTEXITCODE -ne 0) { throw "Resource acceptance failed" }
```

The output directory must be new. `--generator Ninja` is an alternative to JOM.
Without `--environment`, use an already initialized x64 developer shell. The
validator snapshots the source before changing resources and keys; original
working resources are never removed. Failed runs remain separate evidence.
Read `result.json` and `command-*.log`, not merely the build exit status.

## Build Contract

The independent case has `AR_ENCRYPT_RESOURCES=OFF` by default. OFF installs an
EXE and its plaintext resources, establishing positive controls. ON requires
`AR_RESOURCE_KEY_FILE` and installs only the consumer EXE; its authenticated
bundle and AES key are embedded. Internal PDBs, generated headers, packer, private
bundle files and key state remain outside installation.

Build `resource-packer` in an OFF build first, then explicitly run
`resource-packer.exe keygen <new-private-state-file>` before configuring ON.
Never use diagnostic private keys or naming masters for this mode. A locked,
checksummed state file holds the key, random nonce prefix and monotonic counter.
The packer flushes the reserved counter before encryption; missing/corrupt state,
counter exhaustion and duplicate key creation are errors. Keep active state with
the key and never roll back or clone it into independent writers.
The case caps each key at 2^20 encryptions and each plaintext at 4 MiB.

The envelope authenticates its version/algorithm, nonce, length and key identity
along with the encrypted manifest. Parsing checks counts, names, ordering, sizes
and exact end-of-input. Decrypted resources stay in memory; the consumer has no
automatic source-tree or temporary-plaintext fallback.

The consumer accepts `--cache-dir`, `--no-cache`, `--option`, explicit
`--external-dir` plaintext input, and an explicit encrypted `--bundle` override.
The required bundle is validated before external overrides or cache reuse.
The case grammar supports a fixed nested model/coefficients/weights relationship,
not arbitrary source includes. Default cache location is
`%LOCALAPPDATA%/ANTI-REA/resource-demo/v1`.

## Acceptance Coverage

| Check | Evidence |
| --- | --- |
| Debug/Release, OFF/ON | Independent Python uint32 oracle for the generated table; actual native EXE execution |
| AES-GCM behavior | Known NIST AES-256-GCM vector, roundtrip, wrong key, AAD, ciphertext and tag rejection |
| Manifest bounds | Authenticated duplicate/traversal/oversized/truncated/trailing manifests and unsupported includes rejected |
| Cache boundaries | Separate processes, changed options, disabled/default cache, checksum damage, ACL-denied directories, concurrent writers and ignored partial temporary files |
| Build integration | Nested dependency edits, resource add/delete/rename, incremental versus clean rebuild, same-path key rotation and no-change rebuild |
| Nonce lifecycle | Exclusive key creation, checksummed state, exhaustion rejection and concurrent packer nonce uniqueness |
| Installed artifacts | Fresh staging, relocation, original known-sensitive label positives and protected package/cache scans; leakage HTML with locations |
| Cost | Alternating cold/warm/disabled samples, program timing and subprocess wall time recorded separately |

Cache identity covers sorted resource names/contents, option, pointer size,
producer/compiler fingerprints and flags. It conservatively hashes unused
resources too. Random ciphertext is excluded from semantic identity: identical
numeric data may reuse the cache after key rotation, after authenticating the new
bundle. Different executable-cache trust requirements need a different policy.

## Native Results

On 2026-10-22, native Windows x64 with clang-cl 23.1.2 and the Intel oneAPI
developer environment passed run `20261022-r004`: all four Debug/Release OFF/ON
profiles, a freshly installed rotated-key profile, and 171 recorded assertions
(including repeated oracle checks, not 171 distinct scenarios). All three selected
labels were detected in original resources and absent from protected packages and
scanned caches. Protected installation contained only `bin/resource-demo.exe`.

Seven Release samples per mode produced these medians; internal timing includes
resource access, authentication and cache work, while process timing also includes
startup/termination. These are local case observations without a declared
performance budget, not an isolated encryption-overhead measurement.

| Mode | Program Time | Subprocess Wall Time |
| --- | --- | --- |
| Cold cache | 6.53 ms | 14.80 ms |
| Warm cache | 0.70 ms | 7.37 ms |
| Cache disabled | 4.80 ms | 12.98 ms |

Cold caching includes publishing the derived table, so it can cost more than
disabled caching. The warm result establishes reuse for this workload only.
The complete Python suite ran 114 tests with four environment-dependent skips;
the remaining checks passed. The separate native case passed without skipped checks. The public Windows
workflow now reruns the native resource case; its results remain separate from
this local LLVM 23 measurement.

## Limits

The case deliberately locates the known build-key bytes in the EXE; this is a
known-key byte-location check, not blinded key extraction. It also
replaces a cache payload and recomputes its unkeyed hash, demonstrating that such
a cache does not authenticate against a malicious writer. These are documented
limits, not passing claims of reverse-engineering resistance or publisher trust.
Ordinary trusted-cache scenarios must still match the independent numeric oracle.

Selected resource labels disappear from protected files; logical lookup names
used by the consumer can remain visible. No universal string hiding, debugger
resistance, complete erasure, compression, general dependency parser, executable
cache, power-loss recovery or application-wide compatibility is claimed.

All raw output is private: it contains AES keys, PDBs, build paths, original labels
and malformed test bundles. Do not publish it or include it in skill downloads.
The [English skill reference](protection-skill/references/runtime-resources.md)
guides integration; the skill ZIP does not contain this native implementation.
