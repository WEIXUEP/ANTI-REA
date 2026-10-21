# Optional Common-Word Names

Use when the user chooses plausible replacement names instead of the existing
opaque naming/stripping policy. Keep the original mode available. Separate RTTI
naming, private function-symbol naming, and names retained in the release.

## Select the Contract and Capture the Original

Preserve choices already made in the conversation. Otherwise explain OPAQUE and
DECOY when name protection is requested and collect the original baseline while
the user chooses. General requests for obfuscation retain the OPAQUE default;
they do not select DECOY or additional exports. Record the chosen style, exact
owned types/functions, excluded APIs, release channels, key identity and build
coverage. Record export retention separately; only enable it when selected.

Inspect the original program before changing it. Preserve source/build revision,
tool versions, effective options, EXE/DLL and package hashes, original sensitive
corpus, and private object/PDB evidence. Keep public names on a separate required
list. Use the target's existing audit tools or available native inspection; the
separate audit skill is optional. Establish channel-specific positive controls:

| Original evidence | What a follow-up can establish |
| --- | --- |
| Original owned name in linked RTTI | Replacement/removal in the same final EXE/DLL channel |
| Function name in COFF/PDB only | Object renaming and private-map recovery; no claim of reduced PE leakage |
| Original internal export in the release | Export replacement/removal only after consumer/ABI review |
| No original name detected, or channel not inspected | Visibility observation only; improvement unverified for that channel |

Do not replace the original corpus with aliases or promote source-only matches
to release leaks. Keep original and follow-up reports private and immutable.

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
Use [operations.md](operations.md) for its independent recovery commands.

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
Do not extend this policy to arbitrary signature text, string literals, system
APIs or linked bytes. Missing consumers or unsupported name-based lookups leave
that target excluded until its integration is understood.

## Retention Is a Separate Choice

Private COFF/PDB function names normally disappear during Windows PE linking.
Report that honestly. RTTI aliases remain where the runtime uses them.
The optional retained exports make four aliases visible in the EXE; the engine
DLL's public exports stay unchanged. This exposes entry addresses and may help
analysis, so keep it OFF unless the user selects that tradeoff. Retained exports
are not implemented for ELF. Keep PDBs, original maps and keys private.

## Acceptance and Recovery

Run from an existing ANTI-REA checkout with Python dependencies, CMake/JOM and
MSVC-compatible libsodium. Substitute the actual libsodium paths. The following
uses the tested LLVM/oneAPI environment and keeps extra exports OFF:

```powershell
$nameAcceptance = @(
  "--llvm-bin", "F:\Program_Professional\xollvm-windows-llvm23-Release\bin",
  "--environment", "F:\Intel\oneAPI\setvars.bat",
  "--sodium-prefix", "<libsodium-prefix>",
  "--sodium-library", "<libsodium-import-library.lib>",
  "--sodium-runtime", "<libsodium-runtime.dll>",
  "--jobs", "8"
)
python tools/validate_windows.py @nameAcceptance --name-style DECOY `
  --retain-decoy-exports OFF --obfuscation NONE --out build/check-names-r001
if ($LASTEXITCODE -ne 0) { throw "Name acceptance failed" }
```

Use a new output directory for each run and retain failures. If the user selected
export retention, change OFF to ON for that run. Use MIXED_VM only when that
transform is selected. Each invocation runs original protection OFF and protected
ON in Debug and Release, then checks clean rebuilds and key rotation. Read
`result.json` and command logs; successful compilation alone is insufficient.
The OFF build is the original control, not an OPAQUE-versus-DECOY comparison.
This validates the independent demo; it does not establish Palace compatibility.

Report these gates independently:

| Gate | Required evidence |
| --- | --- |
| Original removal | Same original corpus and artifact roles; selected raw RTTI/function names absent from the intended release channels |
| Replacement visibility | Expected RTTI aliases in final binaries; function aliases in COFF, and in EXE exports only when retention is ON; an alias in a map alone is insufficient |
| Behavior and ABI | Debug/Release runtime checks, cross-TU/DLL equality/hash/order, casts and EH; required public exports and unrelated types preserved |
| Coverage and stability | Every affected definition/consumer rebuilt consistently; same-key clean builds stable; full key rotation changes aliases across all affected objects |
| Recovery | Actual emitted function and type aliases resolve through the matching private release maps; map-only commands work without crypto dependencies |
| Package isolation | No keys, maps, IR or PDBs in the relocated release; scan regular nonbinary files too; name any uninspected channel |

Additional aliases/exports are intentional exposure, not resolved original leaks.
Do not merge these gates into a claim that names prevent reverse engineering.

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
If requested, compare OPAQUE/DECOY with the same key, source, compiler, optimization,
other transforms, workload and export-retention policy; record unavoidable policy
differences separately. The demo's retained exports require DECOY, so comparing
OPAQUE/OFF to DECOY/ON measures both naming and additional address exposure.
Use blinded analysis, withhold maps/keys/PDBs, record model/version/prompts and
score conclusions against source-grounded behavior. If this experiment was not
run, label semantic misdirection as untested, including after runtime acceptance.
Keep accuracy, uncertainty, effort and performance results separate. Calls,
constants, instructions and data flow remain available regardless of labels.

Handoff the selected options, exact scope, artifact identities, baseline and
follow-up evidence, per-gate outcomes and remaining exposures. Preserve the
private release maps for recovery; do not include them in public skill examples.
