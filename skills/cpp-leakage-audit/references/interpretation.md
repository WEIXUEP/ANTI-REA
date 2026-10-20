# Finding Interpretation and Recommendations

Recommend scoped remedies; do not perform them during a read-only audit.

| Evidence channel | Likely origin | Recommendation and follow-up evidence |
| --- | --- | --- |
| Message/condition/signature literal | Diagnostic macro or logger | Central protected interface; check evaluation, failure semantics and plaintext absence |
| Path/source basename | Runtime location, compiler source unit or debug record | Location IDs, prefix mapping, separate debug files; inspect each channel separately |
| Internal RTTI name after strip | ABI type-name initializer | ABI-aware opaque names; require casts/equality/exceptions across libraries |
| Function/global symbol | Static or dynamic symbol table | Strip release copies or restrict exports only after public ABI review |
| PDB path | PE CodeView record | Basename-only reference and private PDB retention |
| Build library path | ELF RPATH/RUNPATH | Relative installed loader policy plus relocation test |
| Resource name or content | Runtime locator, text asset or embedded resource | Aliases/relative lookup; naming protection does not encrypt contents |
| Dependency/runtime text | External library or system import | Report separately; changes require separate authorized scope |
| Private files in package | Staging/configuration error | Exclude keys/maps/IR/debug files and re-inventory the actual package |

An exact corpus byte match confirms those bytes, not their executing code path.
Path and RTTI regex hits are candidates until context supports the interpretation.
Encrypted Base64 can look like a slash path; review the containing record and
offset. Do not suppress all ciphertext-looking text. Public imports and exported
API names may be necessary; mark them intentional with a narrow rationale.

Local-variable labels invented by a decompiler are not necessarily source names.
Stripping removes selected metadata, not strings needed at runtime. Opaque RTTI
does not conceal inheritance, vtables or function bodies. Runtime-decrypted
strings can be observed in memory. Public-key sealed diagnostics can keep private
recovery material outside the process but do not authenticate their sender.

Do not recommend arbitrary linked-byte replacement, disabling RTTI/exceptions or
global heavyweight obfuscation just to reduce findings. Implementation selection
must preserve behavior and respect the target's ABI/performance requirements.
