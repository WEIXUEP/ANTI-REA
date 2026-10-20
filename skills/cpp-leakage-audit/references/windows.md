# Windows PE Audit

Inspect existing EXE/DLL files without rebuilding them. Install optional
`pefile` in the selected Python environment only if authorized.

```powershell
python <skill>/scripts/audit.py `
  --binary <original>/app.exe --binary <original>/engine.dll `
  --deny 'Exact sensitive diagnostic' --deny '.?AUPrivateType@internal@@' `
  --require-metadata --out <private-evidence>/baseline
python <skill>/scripts/audit.py --package <staged-release> `
  --require-metadata --fail-on-private --out <private-evidence>/package
```

The scanner inventories imports (including delayed and ordinal), exports
(including forwarded and ordinal), machine identity and CodeView PDB references.
Raw RTTI is candidate evidence; exact corpus bytes are confirmed in UTF-8/UTF-16.
Missing/malformed native inspection fails `--require-metadata`. PDB contents are
not parsed; a basename-only PDB reference can be intentional.

Keep originals and reports private. For a provided rebuilt release use identical
artifact order, filenames, corpus and allow rules with `--baseline <original.json>`
and a separate output. Review full packages for PDBs, IR, maps and keys, not only
EXE/DLL. Private-file detection is heuristic and can miss renamed files; compare
the whole inventory against the intended package manifest.

Do not apply ELF strip commands to PE, remove required imports, or claim runtime
compatibility from opaque-name absence. Casts, exceptions, DLL boundaries, CRT
variants and relocation require separate authorized runtime validation.
