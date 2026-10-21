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

## Original and Replacement Name Evidence

Keep the original sensitive corpus, public-name requirements, scanner settings
and artifact roles for the follow-up scan. Do not replace original names with
aliases in the baseline or broadly allowlist common words. If scanner code changed,
capture a new baseline from preserved originals without overwriting prior evidence.

| Observation | Supported conclusion |
| --- | --- |
| Original RTTI name detected before, absent after, alias present in final RTTI | Selected runtime-name replacement; casts/EH still need separate runtime evidence |
| Original function in private COFF/PDB, alias in rebuilt COFF | Object-symbol rename; neither observation proves final PE visibility |
| No original function name in baseline PE | No demonstrated PE-name reduction for that function |
| New alias in final PE export table | Additional visible name and entry address; review public ABI and export policy |
| Label appears only in a decompiler or analyst notes | Analyst-generated name, unless independent binary/debug evidence confirms otherwise |
| Exact original corpus yields no hits | No detected originals in inspected channels; not proof of semantic recovery resistance |

Use structured symbol/export evidence when available. Record binary byte offsets
only when known; keep COFF/PDB evidence separate from final-package findings and
never invent a PE location from a map entry. Maps contain the original identities
and stay private. The scanner does not validate transform coverage, alias stability
or runtime ABI correctness; those require build/runtime evidence from the owner.

In the leakage HTML, retain original and follow-up report identities. Show an
original disappearance separately from an added alias export. Ordinary alias
metadata can remain in the inventory view; a selected sensitive alias/address
finding must remain locatable in its actual file/channel. Missing metadata is
an unchecked channel, not evidence that an export is absent.

## Mechanism Limits

Stripping removes selected metadata, not strings needed at runtime. Opaque RTTI
does not conceal inheritance, vtables or function bodies. Runtime-decrypted
strings can be observed in memory. Public-key sealed diagnostics can keep private
recovery material outside the process but do not authenticate their sender.

Do not recommend arbitrary linked-byte replacement, disabling RTTI/exceptions or
global heavyweight obfuscation just to reduce findings. Implementation selection
must preserve behavior and respect the target's ABI/performance requirements.
