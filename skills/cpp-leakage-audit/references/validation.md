# Audit Validation

Verify the scanner and the scope, not only a successful exit status.

- Establish a known-leaking positive control before interpreting a clean scan.
  Include selected diagnostics, filenames, developer roots and raw RTTI names.
- Test exact UTF-8/UTF-16 matches and offsets; verify required public names remain
  visible where the ABI requires them.
- Use the original executable, its actual libraries and the complete staged
  release. Record SHA-256 identity and keep build and installed views separate.
- With optional metadata unavailable, confirm `--require-metadata` fails native
  acceptance. Basic string scanning must not count as complete ELF/PE inspection.
- Exercise private-package and exact-corpus gates. A default zero exit is
  inventory completion, not a promise of no leakage.
- Compare provided rebuilt artifacts using the original immutable baseline.
  Verify corpus/scope changes fail rather than produce an improvement claim.
- For common-word function/type aliases, preserve original-name positive controls
  per channel. Separate COFF/PDB changes, linked RTTI and final exports; report new
  alias exports and addresses even when original findings resolve. A private map
  entry or decompiler label alone is not evidence of an alias in the release.
- Review candidate paths, required imports, public exceptions and opaque payload
  context manually. Keep explicit reasons; do not hide whole finding categories.
- Extract this skill ZIP alone and run `scripts/audit.py --help` and a synthetic
  package scan from another working directory without repository imports.

Audit-only validation does not require source changes, key generation or a
protected rebuild. If runtime tests are authorized, use isolated processes and
report untested failure scenarios. A clean corpus scan is not a disassembler,
general security assessment or guarantee against reverse engineering.

For optional REA review, validate the plan against parsed risky imports and
negative controls (ordinary strings, exports, similarly named safe functions).
Confirm that changed binaries, ambiguous baseline identities, stale scanners,
package-local reports and existing evidence directories are rejected. Backend
failure/non-JSON output must remain incomplete. Extract the ZIP alone and run
`rea_audit.py --help` and `--action plan` without REA or repository imports.
Test command/envelope handling separately from actual provider verification;
mock responses do not establish Windows Ghidra decompilation or vulnerability
reachability. See [rea.md](rea.md) for the required evidence at each stage.
