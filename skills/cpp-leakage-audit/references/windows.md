# Native Windows Evidence

Read this for PE audits, Windows protection work or MSVC RTTI acceptance. A Linux
IR fixture does not establish Windows CRT behavior. Inspect the available native
compiler, matching opt, SDK/CRT and dependencies before choosing build commands.
Do not interpret an unavailable tool or runner as a passing test.

## Capture the Original Program First

Install `pefile` in the scanner's Python environment for PE metadata. No compiler
or repository package is needed to run the standalone skill scanner.

```powershell
python <skill>/scripts/audit.py `
  --binary <original>/app.exe --binary <original>/engine.dll `
  --deny 'Exact sensitive diagnostic' --deny '.?AUPrivateType@internal@@' `
  --require-metadata --out <private-evidence>/baseline

python <skill>/scripts/audit.py `
  --binary <protected>/app.exe --binary <protected>/engine.dll `
  --deny 'Exact sensitive diagnostic' --deny '.?AUPrivateType@internal@@' `
  --baseline <private-evidence>/baseline.json `
  --require-metadata --fail-on-deny --out <private-evidence>/protected

python <skill>/scripts/audit.py --package <fresh-staged-release> `
  --require-metadata --fail-on-deny --out <private-evidence>/package
```

Use real source/RTTI evidence to select the corpus. Confirm the first scan finds
the chosen leaks. Keep the same binary ordering, filenames, corpus and allow
rules when comparing. Do not overwrite the baseline. Reports include full paths
and original sensitive text and belong outside the shipped package.

The scanner inventories PE imports (including delay and ordinal imports), exports (including ordinal and forwarded
exports), x64 machine identity and CodeView PDB references. Raw RTTI matches are
candidates; explicit denied strings are confirmed byte matches in UTF-8 and
UTF-16. Optional metadata failures remain unperformed checks and must fail binary
acceptance with `--require-metadata`. Private PDB contents are not parsed.
Package suffix/key-name findings are heuristics: review public SDK import
libraries or intentionally shipped maps explicitly, with a narrow reasoned allow
rule when appropriate. A file renamed to an arbitrary extension can evade this
inventory heuristic; review the full file list and expected package manifest.

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
