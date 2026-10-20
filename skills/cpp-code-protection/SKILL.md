---
name: cpp-code-protection
description: Guide and implement scoped C++ diagnostic encryption, opaque RTTI names, selected numeric masking, release stripping and selective obfuscation; validate behavior, recovery limits and performance with matched controls. Manage keys and offline recovery tools. Use for authorized protection changes, not read-only leakage detection.
---

# C++ Code Protection

## Scope and Independent Operation

Use for authorized protection design or implementation. A design-only request
does not authorize changes, key generation, tool installation or builds.
Identify the owned namespaces, central diagnostics, target/consumer graph,
compiler/ABI, platforms, public API, distribution layout and performance budget.
Preserve user edits and dependency boundaries. Do not automatically publish,
push or upload artifacts or recovery material.

This is self-contained integration guidance, not a universal C++ rewriter.
Python 3.10+ runs the bundled tools outside this repository. Read
[operations.md](references/operations.md) for setup, formats and exit codes.
The key generator and decoder support the documented example schema; inspect
other producers before adapting them. A GUI is design guidance, not bundled UI.

| Task | Tool or reference |
| --- | --- |
| Check dependencies and LLVM/xollvm readiness | `scripts/doctor.py` |
| Generate compatible private material | `scripts/generate_keys.py`; [key-management.md](references/key-management.md) |
| Recover diagnostics, locations and RTTI | `scripts/decode.py`; [recovery-tools.md](references/recovery-tools.md) |
| Implement diagnostics, RTTI, build and release protection | [integration.md](references/integration.md) |
| Choose controls and function-level obfuscation | [remediation.md](references/remediation.md) |
| Integrate selected constants and run matched-control acceptance | [runtime-constants.md](references/runtime-constants.md) |
| Test semantics, selection and fresh release artifacts | [validation.md](references/validation.md) |
| Handle clang-cl/MSVC ABI and private PDBs | [windows.md](references/windows.md) |
| Compare trusted target workloads | `scripts/measure.py` |

## Agree the Protection Contract

Preserve an immutable original build, private debug material and evidence of
known exposures. If original artifacts are missing, say improvement is unverified.
Use existing target audit tooling or native inspection; the separate
`cpp-leakage-audit` skill is convenient but not required. This package does not
bundle a scanner or claim automatic comprehensive audit coverage.

For authorized implementation, default to both a stripped release copy and
baseline information protection: sealed diagnostics, opaque source locations and
internal RTTI names, path/resource hygiene and private-artifact isolation.
Keep OFF behavior reproducible. Explicit user choices override these defaults.
Missing ABI/tool support is an unmet check, not permission to silently downgrade.

Do not enable maximum obfuscation globally. Select extra transforms/VM by function
value, call frequency and an explicit cost budget. Leave numerical hotspots and
unknown-frequency functions unchanged until justified. Record exact targets,
exclusions, required passes and applied/skipped results; compilation success
alone does not prove a transform ran. Do not install xollvm without authorization.

For ordinary C++ builds using xollvm directly, require explicit opt-in with
`-mllvm -enable-obfuscation` on each selected compilation target; selecting an
xollvm compiler or adding annotations alone does not enable its automatic
obfuscation pipeline. Keep this switch OFF by default. If a launcher already
invokes `opt -passes=obfuscation,verify`, use that single explicit invocation
instead of also adding the frontend switch. See the CMake example in
[integration.md](references/integration.md).

## Implement Incrementally

Read [integration.md](references/integration.md) before editing. Prefer dedicated
modules and central diagnostic/build interfaces over mass call-site changes.
Retain condition single evaluation, exceptions, abort behavior, MPI routing,
cross-library type identity and numerical semantics.

Encrypt retained templates at build time with a maintained public-key library;
runtime carries only sealing material, never private recovery keys. Stable
opaque naming requires release maps and is not reversible encryption. Never
fall back to plaintext on protection failure. Do not patch arbitrary linked
bytes, disable RTTI or delete exports to satisfy a string scan.

For selected numeric constants, runtime masking can reduce exact-byte signatures.
Prevent optimizer folding and inspect the final linked artifact, including shared
data and accessors outside VM bodies. Both shares and the decoder remain available
to an analyst; distinguish a successful byte-hiding check from recovery resistance.
Use an otherwise identical masking-OFF control to isolate incremental cost. Read
[runtime-constants.md](references/runtime-constants.md) for the verified demo
switches, Windows commands, control matrix and recovery countertest before using
this mechanism. The downloaded skill guides integration; it does not bundle the
demo generator. The decoder does not consume the numeric constant map.

Read the key lifecycle reference before generating or rotating secrets. Missing
keys do not authorize regeneration or public-demo fallback. Read recovery-tool
guidance before adding CLI/GUI features; use one bounded offline backend, explicit
loading/provenance, per-event failures and no implicit key creation or plaintext
exports. Keep private keys/maps/IR/PDBs out of release packages.

## Validate and Handoff

Rebuild affected producers and consumers consistently. Test ON/OFF diagnostics,
decode failures, condition evaluation, cross-library casts and exception matching,
relocation and numerical behavior. Test an actual fresh installed package with
the original sensitive corpus and required public names. Existing audit reports
or native tools can establish the comparison; name any unchecked channels.

Use `scripts/measure.py` only with reviewed command manifests and authorized
workloads. It rotates profile order, records raw times, dispersion, output hashes
and sizes, and verifies declared artifact hashes after execution. Optional
`comparisons` in the manifest declare `max_slowdown` and `max_size_ratio` gates;
choose them before sampling. Relative speed is the inverse of the time ratio,
not one minus the percentage overhead. Failed workloads or unavailable reference
sizes cannot pass a requested gate. It is not a
correctness oracle or proof that xollvm ran.
Report implemented controls, actual artifacts and checks, residual exposures,
unsupported platforms and pending performance decisions. Distinguish encryption,
opaque naming, stripping and obfuscation; none makes native code unreversible.
Keep behavior, direct-byte hiding, recovery resistance and cost verdicts separate.
A known-corpus recovery or failed budget remains a failure of that claim even
when runtime compatibility and the direct-byte gate pass.
