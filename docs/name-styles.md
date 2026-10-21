# Optional Name Styles

English | [简体中文](name-styles.zh-CN.md)

Select names separately from code transforms and release stripping. The default
remains `ANTI_REA_NAME_STYLE=OPAQUE`. RTTI names already use stable identifiers;
they are not deleted, because the runtime needs type identity. Ordinary private
function symbols are normally omitted or stripped.

## Choices

| Option | Result |
| --- | --- |
| `ANTI_REA_NAME_STYLE=OPAQUE` | Existing RTTI names and release-symbol policy; no new function renaming |
| `ANTI_REA_NAME_STYLE=DECOY` | Common-word RTTI aliases and explicitly selected internal function aliases |
| `ANTI_REA_RETAIN_DECOY_EXPORTS=OFF` | Default; do not add exports to retain function names |
| `ANTI_REA_RETAIN_DECOY_EXPORTS=ON` | Windows DECOY only; retain selected function aliases as EXE exports |

Example labels are `read_buffer_<64 hex digits>` and `CacheEntry_<64 hex digits>`.
The common-code words do not describe the implementation. HMAC suffixes preserve
distinct identities and stability with the same key/original name. Rotate the key
and rebuild all affected producers and consumers to change names. These labels
are not encryption. CMake GUI exposes the style choice and export checkbox.

```powershell
# Add the usual Python, matching opt, libsodium and private-key arguments.
cmake -S . -B build/decoy -DANTI_REA_CODE_PROTECTION=ON `
  -DANTI_REA_NAME_STYLE=DECOY `
  -DCMAKE_CXX_COMPILER=F:/Program_Professional/xollvm-windows-llvm23-Release/bin/clang-cl.exe

# Explicitly keep the four selected EXE function aliases visible.
cmake -S . -B build/decoy-visible -DANTI_REA_CODE_PROTECTION=ON `
  -DANTI_REA_NAME_STYLE=DECOY -DANTI_REA_RETAIN_DECOY_EXPORTS=ON `
  -DCMAKE_CXX_COMPILER=F:/Program_Professional/xollvm-windows-llvm23-Release/bin/clang-cl.exe
```

Use a fresh build directory. Both options require information protection ON;
stripping remains separate. DECOY naming supports both ABI paths; retaining
exports supports only Windows executables.

## Scope and Release Visibility

`examples/name-policy.json` lists exact Itanium/MSVC symbols for four owned
functions: `policy_dispatch`, `policy_token`, `print_rtti`, and `peer_type`.
`ANTI_REA_NAME_POLICY` selects another reviewed list. This is not an automatic
renamer for arbitrary C++. Exclude public APIs, imports, entry points, name-based
dynamic lookup and functions with uncovered consumers. Changing the policy
rebuilds the demo objects.

The launcher rewrites complete LLVM global/comdat identifier tokens, including
calls and address references. It preserves ordinary strings/comments and rejects
DLL imports/exports, default-visibility ELF functions, detected textual symbol
references and alias collisions. Function renaming follows xollvm selection and
validation; LLVM verification runs again before native code generation.

RTTI selection remains limited to owned types, composites containing them and
existing selected local types. The ABI-specific transform replaces the name and
array size, preserving runtime fields, hierarchy, vtables and EH references.
Independent third-party RTTI stays unchanged. Class member linker symbols and
debug records are not all renamed; continue the existing release hygiene.

Windows normally drops internal function symbols from the final PE. Seeing a
COFF/private-PDB alias alone does not prove an analyst sees a decoy function name.
With retained exports OFF, record which symbol channels actually retain aliases.
RTTI aliases remain in the release where the runtime uses them.

With retained exports ON, the four selected functions become EXE exports under
their aliases. Existing engine DLL exports remain unchanged. This exposes extra
entry addresses and may help analysis, so it is an optional experiment, OFF by
default. It does not ship PDBs or change calling signatures. Do not enable it on
an executable with a different export policy without reviewing that policy.

## Recovery and Acceptance

Per-object `private/maps/*.json` retains `rtti` and `symbols` records, including
original, readable and replacement function names. Keep maps, naming keys, IR
and PDBs private. Both decoders support the new labels:

```powershell
python tools/anti_rea.py decode --build build/decoy --rtti 'ENCODED_RTTI_ALIAS'
python tools/anti_rea.py decode --build build/decoy --symbol 'FUNCTION_ALIAS'
python <skill>/scripts/decode.py --build /private/build --symbol 'FUNCTION_ALIAS'

# acceptance holds the existing LLVM/environment/libsodium arguments.
python tools/validate_windows.py @acceptance --name-style DECOY `
  --retain-decoy-exports ON --out build/name-check-new-run
```

Standalone RTTI/symbol lookup needs no crypto dependency. `--symbol` matches the
entire alias. Native validation covers Debug/Release, 39 cross-TU/DLL RTTI/EH
boundaries, numeric outputs, relocation, production linker flags, private PDBs,
all six objects, COFF aliases, PE exports, maps, same-key rebuilds and key rotation.
Add `--obfuscation MIXED_VM` to check the naming/VM combination.

Native Windows validation on 2026-10-21 used LLVM 23.1.2, the Intel oneAPI
environment and eight build jobs. DECOY with no added exports passed; DECOY with
four retained EXE exports also passed the full NONE and MIXED_VM suites, including Debug,
Release, production linker settings, map recovery and six-object key rotation.
The independent ZIP decoder recovered all four selected functions and 19 owned
RTTI names without site-packages. Additional release scanning found zero hits
for the selected original function names and `ResonantKernel`. Private evidence
remains outside the published documentation and downloads.

Original-name removal and unchanged behavior are observable gates. Misleading a
language model is a separate, unverified hypothesis. A suitable experiment uses
matched OPAQUE/DECOY controls, withholds private maps/source from the analyst,
records model/version/prompts, and scores against source-grounded behavior.
Measure accuracy, uncertainty and effort. Plausible labels alone do not prove
model resistance; assembly, calls, constants and data flow remain available.
