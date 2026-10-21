# Optional Common-Word Names

Use when the user chooses plausible replacement names instead of the existing
opaque naming/stripping policy. Keep the original mode available. Separate RTTI
naming, private function-symbol naming, and names retained in the release.

## Verified Demo Controls

| Setting | Meaning |
| --- | --- |
| `ANTI_REA_NAME_STYLE=OPAQUE` | Default; existing RTTI aliases and function release policy |
| `ANTI_REA_NAME_STYLE=DECOY` | Common-word aliases for owned RTTI and four listed functions |
| `ANTI_REA_NAME_POLICY=<path>` | Reviewed schema-1 exact function symbols for both ABIs |
| `ANTI_REA_RETAIN_DECOY_EXPORTS=OFF` | Default; no additional exports |
| `ANTI_REA_RETAIN_DECOY_EXPORTS=ON` | Windows only; expose selected EXE function aliases |

Use a fresh build directory and total protection ON. CMake GUI offers the name
style choices and export checkbox. The downloaded skill guides integration;
it does not bundle the demo launcher or a universal C++ renamer.

`examples/name-policy.json` selects `policy_dispatch`, `policy_token`, `print_rtti`
and `peer_type`. Entries record `name` (readable), `itanium` and `msvc` (exact
linker symbols). Exclude public APIs, imports, entry points, assembly/name-based
dynamic lookup, and functions with uncovered consumers. Verify definition
coverage, not just one declaration. The demo rejects DLL imports/exports,
default-visibility ELF functions, detected textual references and collisions.

Labels look like `read_buffer_<64 hex digits>` or `CacheEntry_<64 hex digits>`.
Use keyed, domain-separated identities with enough entropy to distinguish
types. Reusing the same bare word for several classes can break type identity
and exception matching. Keep names stable across related TUs/DLLs with one key;
rotate names through complete rebuilds.

Rename functions after xollvm target/report validation and debug stripping.
Rewrite complete LLVM global/comdat tokens, including calls and address
references; preserve strings/comments. Verify IR before code generation. RTTI
requires the ABI-specific name-initializer change, preserving runtime fields,
hierarchy and EH references. Not every member/debug symbol is renamed.

## Retention Is a Separate Choice

Private COFF/PDB function names normally disappear during Windows PE linking.
Report that honestly. RTTI aliases remain where the runtime uses them.
The optional retained exports make four aliases visible in the EXE; the engine
DLL's public exports stay unchanged. This exposes entry addresses and may help
analysis, so keep it OFF unless the user selects that tradeoff. Retained exports
are not implemented for ELF. Keep PDBs, original maps and keys private.

## Acceptance and Recovery

Use the existing LLVM/oneAPI/libsodium acceptance arguments:

```powershell
python tools/validate_windows.py @acceptance --name-style DECOY `
  --retain-decoy-exports ON --out build/new-name-acceptance
```

The checked NONE and MIXED_VM configurations passed Debug/Release, 39 RTTI/EH boundaries,
all six objects, numeric outputs, relocation, formal linker flags, COFF aliases,
PE export checks, original RTTI removal, same-key rebuilds, map recovery and
complete key rotation. Independent ZIP lookup recovered four functions and
19 owned RTTI names from real maps without site-packages. Re-run for other
compilers and transform policies.

Private per-object maps include `symbols` records with `original`, `decoded`,
`replacement`, `definition` and `style`, alongside `rtti` records. The standalone
decoder handles explicit function lookup and raw/demangled RTTI aliases without
PyNaCl for these map-only operations:

```bash
python <skill>/scripts/decode.py --build /private/build --symbol FUNCTION_ALIAS
python <skill>/scripts/decode.py --build /private/build --rtti RTTI_ALIAS
```

Keep original-name removal, replacement visibility and runtime behavior as
separate checks. Plausible labels do not demonstrate model misclassification.
If requested, use matched OPAQUE/DECOY artifacts with blinded analysis, record
model/version/prompts, and score conclusions against source-grounded behavior.
Keep accuracy, uncertainty, effort and performance results separate. Calls,
constants, instructions and data flow remain available regardless of labels.
