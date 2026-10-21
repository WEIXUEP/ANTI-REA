# Finding Interpretation and Recommendations

Recommend scoped remedies; do not perform them during a read-only audit.

| Evidence channel | Likely origin | Recommendation and follow-up evidence |
| --- | --- | --- |
| Message/condition/signature literal | Diagnostic macro or logger | Central protected interface; check evaluation, failure semantics and plaintext absence |
| Path/source basename | Runtime location, compiler source unit or debug record | Location IDs, prefix mapping, separate debug files; inspect each channel separately |
| Internal RTTI name after strip | ABI type-name initializer | ABI-aware opaque names; require casts/equality/exceptions across libraries |
| Function/global symbol | Static or dynamic symbol table | Strip release copies or restrict exports only after public ABI review |
| Selected numeric bytes | Instruction immediate, global table, asset or incidental bytes | Confirm the owning region and references; inspect callers and shared data before selecting protection |
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
Numeric matches and crypto-looking tables do not establish an algorithm: a
protector can insert decoys. Trace relevant data/control paths, preserve unknown
reachability and corroborate semantics independently when execution is authorized.

No raw constant match does not imply the value is hidden from analysis. Runtime
XOR-share masking can remove an immediate yet leave both shares and reachable
decoder instructions. For a known corpus, pair reconstruction plus code/data
references can establish recoverability without keys or PDBs. Label this as a
known-corpus recovery test, not blinded algorithm recovery or devirtualization;
the bundled exact-byte scanner does not perform that reconstruction automatically.

Local-variable labels invented by a decompiler are not necessarily source names.
Common-code function/class labels may also be deliberate replacements. Confirm
the actual channel (RTTI, PE export, COFF/PDB or analyst-invented label), then
derive semantics from behavior and references. Do not infer implementation from
words such as `read_buffer` or `CacheEntry` alone. Extra decoy exports can reveal
function addresses even when original names disappear; report that tradeoff.
Stripping removes selected metadata, not strings needed at runtime. Opaque RTTI
does not conceal inheritance, vtables or function bodies. Runtime-decrypted
strings can be observed in memory. Public-key sealed diagnostics can keep private
recovery material outside the process but do not authenticate their sender.

Do not recommend arbitrary linked-byte replacement, disabling RTTI/exceptions or
global heavyweight obfuscation just to reduce findings. Implementation selection
must preserve behavior and respect the target's ABI/performance requirements.
