# Remediation Decision Guide

| Evidence | Typical origin | Scoped remediation | Required validation |
| --- | --- | --- | --- |
| Message and condition strings | Error/assertion macros | Build-time stripping or sealed catalog; remove signature/stringification inputs | Failure semantics, argument evaluation and plaintext scan |
| Full signature or source path | `__FILE__`, `__FUNCSIG__`, `source_location` | Protected location interface and prefix mapping | Decode/map correctness and binary inspection |
| Internal type names after strip | Runtime RTTI initializers | ABI-aware opaque-name generation, consistent keys across consumers | Casts, equality, inheritance and cross-library exceptions |
| Local function/global names | Static symbol table | Separate private debug artifacts and strip the release copy | Release functionality and symbol audit |
| Exported internal C++ names | Public/dynamic symbols | Tighten explicit exports/visibility only after ABI review | Existing client/plugin loading |
| Source basenames with no directories | Debug records or compiler source-unit field | Remove private metadata and alias compilation-unit labels | File/symbol scan; retain internal debug artifacts separately |
| PDB developer path | PE CodeView | PDB basename linker rule; private PDB retention | PE CodeView audit, package inventory |
| Absolute library search path | RPATH/RUNPATH | Executable-relative installation policy | Relocated installed package |
| Resource/source filename | Runtime locator or JIT source metadata | Stable aliases and executable-relative resolution | Resource loading; disclose readable resource contents |
| Ordinary runtime string | Logs, labels, exception `what()` | Protect the owning interface; optional string obfuscation | Static scan and runtime behavior |
| Selected numeric constants | Instruction immediates or referenced data | Scoped runtime masking, if byte-signature reduction is useful | Positive original corpus, optimized final-byte scan, independent arithmetic tests, decoder recovery attempt and incremental cost |
| Dependency diagnostics | External runtime/library | Explicit separate dependency work if authorized | Rebuild dependency and consumers |

Diagnostic public-key sealing, opaque naming, symbol removal and obfuscation solve
different problems. A program that decrypts its own strings is observable in memory.
RTTI replacement must preserve ABI structures; disabling RTTI changes functionality.
An imported function name may be required and public. Local-variable labels in a
decompiler are not necessarily recovered source variable names.

Use established cryptography, keep private keys out of the executable and package,
and archive release-specific maps. Public demonstration keys are not production
secrets. A private audit report can itself contain confidential paths and names.

Never replace a filename substring throughout a linked binary as a general fix.
Relocations, lengths, signatures and runtime contracts can depend on those bytes.

## Runtime Constant Masking

Use [runtime-constants.md](runtime-constants.md) for the checked switches, native
Windows commands, matched-control measurements and recovery countertest.

The demo uses an explicit `examples/policy-constants.json` catalog, generated
`policy_constants.hpp`, and a private `constants.json` map. With information
protection ON, `ANTI_REA_CONSTANT_PROTECTION=ON` replaces five policy constants
with per-entry XOR shares derived at build time from a domain-separated keyed
hash. The master key is not needed at runtime. `OFF` retains ordinary constant
expressions for a matched control; information protection OFF always uses plaintext.

Volatile reads prevent the optimizer from folding the shares back to plaintext.
This is deterministic masking, not cryptographic confidentiality. The linked
program contains enough information to reconstruct every value. In particular,
adjacent shares allow a known-corpus XOR-pair scan; a failed raw-byte search is
not evidence that constants are unrecoverable. Folding, split immediates and
incidental matches also affect raw scans. Never suppress a hit to obtain a pass.

Compile Debug and optimized Release with the production linker options. Check
independent boundary/random arithmetic, casts/EH, key rotation and clean rebuilds.
Require the same constant corpus and artifact inventory for before/after audits.
Measure masking ON/OFF at each selected obfuscation level, keeping other controls
and compiler settings equal. Record any failed performance budget even when byte
hiding succeeds. Do not apply masking automatically to all constants or hot kernels.

## Function Value and Performance Policy

The default release policy enables both stripping and baseline information
protection: sealed diagnostics, opaque locations and internal RTTI names, path
and resource hygiene, and private-artifact isolation. It does not enable maximum
control-flow obfuscation or virtualization.
Treat additional mechanisms as separate decisions; a higher preset name is not
a universal measure of protection quality. Diagnostic public-key sealing protects
message confidentiality, while runtime string decryption and VM transformations
remain observable by an analyst running the program.

| Scenario | Starting policy | Evidence needed before increasing cost |
| --- | --- | --- |
| Ordinary glue or low-value utility | Stripped and information-protected release; no control-flow transformation | A specific valuable implementation or observed leakage |
| Diagnostics, locations and internal type names | Enable sealed diagnostics, location maps and ABI-aware internal RTTI protection by default | Decode correctness, exception/cast compatibility and release scans |
| Valuable frequently called function | Leave the hot path unchanged initially; consider narrowly budgeted light transforms | Representative profiling and an explicit latency/throughput budget |
| Valuable cold decision function | Consider medium/heavy transforms on selected functions | Correctness tests, applied-pass evidence and measured size/startup/runtime cost |
| Small, especially valuable cold function | Consider selective VM if supported | Supported constructs, ABI/exception tests and accepted VM overhead |
| Unknown call frequency or performance requirements | Keep stripping and baseline information protection enabled; mark additional function transforms pending | Profiling or user-provided function classification and limits |

Before applying costly transformations, create a concise per-function plan with
business value, call-frequency evidence, chosen mechanism, exclusions and the
performance budget supplied by the user. Do not invent a universal acceptable
slowdown. If a decision requires a missing budget, ask for it or leave the costly
transformation pending while completing the authorized lower-cost work.

Keep numerical kernels, tight loops, vectorized/GPU routines and public ABI
boundaries out of heavy/VM processing unless representative tests justify their
inclusion. Prefer explicit function selection. A string-encryption pass may be
module-wide even when requested through a function annotation; inspect its actual
scope and isolate selected code when necessary. Do not combine VM and flattening
on the same function when the toolchain forbids it. Disable anti-debug behavior
unless separately requested and validated.

Compare the selected policy against both baseline and stripped-only releases
using the same compiler, optimization, inputs and representative workloads.
Report build cost, size, startup, workload timings, correctness, scan evidence
and skipped passes separately. Demo microbenchmarks establish only demo costs,
not the performance of another application's functions. Exceeding the agreed
budget calls for a revised selection, not an unreported fallback.
