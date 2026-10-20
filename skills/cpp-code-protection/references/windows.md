# Native Windows Evidence

Read this for Windows protection work and MSVC RTTI acceptance. A Linux
IR fixture does not establish Windows CRT behavior. Inspect the available native
compiler, matching opt, SDK/CRT and dependencies before choosing build commands.
Do not interpret an unavailable tool or runner as a passing test.

## Capture the Original Program First

Use existing target audit tooling, or native PE inspection such as
`dumpbin /headers /imports /exports` and matching LLVM read tools. Record
CodeView/PDB references and exact ASCII/UTF-16 sensitive strings, including raw
MSVC RTTI names, in a private immutable baseline. Confirm known leaks are found.
Keep artifact identities and corpus equivalent after rebuilding; do not overwrite
the original evidence. The separate cpp-leakage-audit skill is optional and
contains the standalone scanner; this protection package does not bundle it.

Inspect the whole package against its intended manifest, not only EXE/DLL.
Review PDBs, maps, IR and key files. File extensions alone do not establish
secrecy or completeness. Missing metadata/runtime checks remain unverified.

## Preserve the Windows Runtime Contract

Use separate baseline/protected Debug and Release builds, with the same compiler,
CRT and input workload. For x64 clang-cl RTTI name replacement, verify:

- Ordinary, local and template types are selected; templates containing internal
  types are selected even when the outer template is external. Independent
  third-party types remain unchanged. `name()` and `raw_name()` may change.
- EXE and DLL actually have distinct descriptors for a shared type. Compare
  equality in both directions, consistent hashes, `before`, ordered and unordered
  `type_index` lookup, and cross-TU equality/inequality.
- Single, multiple and virtual inheritance casts work across the DLL boundary
  in both directions. Wrong pointer casts return null; wrong reference casts throw
  `bad_cast`; null polymorphic `typeid` throws `bad_typeid`.
- Exact/base exception catches, wrong catch rejection, rethrow, `exception_ptr`,
  derived/base pointer exceptions, const conversion/rejection and typed null
  pointers retain their behavior. C linkage exception entry points need explicit
  `noexcept(false)` under `/EHsc`; never remove exceptions just to pass an audit.
- Same-key clean rebuilds produce the same opaque names. Replacing the common
  key rebuilds every relevant TU in both EXE and DLL and changes all selected
  names. Recover runtime names using that release's private map. Mixed protected
  and unprotected producers/consumers are unsupported without separate proof.

For release acceptance enable `/OPT:REF /OPT:ICF`, retain internal PDBs and use a
basename-only `/PDBALTPATH:%_PDB%` reference. Copy the fresh installed package,
including required runtime DLLs and resources, and run it from another directory
without relying on the build/dependency directories on PATH. Test package
relocation independently from merely changing the working directory.

Check original selected RTTI bytes disappear and opaque names remain; confirm
unrelated RTTI and required exports survive. Scan EXE/DLL for private key material
and inventory the whole package for PDBs, keys, maps and raw IR. Keep RTTI leakage
separate from ordinary public exports: opaque RTTI does not hide the hierarchy,
function bodies, normal export names or dependency diagnostics.

The ANTI-REA repository supplies `tools/validate_windows.py` to exercise its own
demo and launcher. The installed skill does not bundle that demo, compiler or
dependencies; adapt these checks to the target rather than inventing a generic
binary-rewriting step.
