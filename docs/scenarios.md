# Leakage Scenarios and Mitigations

Use the baseline and protected presets to build the same sources. Run commands
from the repository root. Every scenario is an inspection exercise rather than a
claim that the entire program has become unreadable.

| ID | Trigger or inspection | Baseline disclosure | Protected behavior |
| --- | --- | --- | --- |
| D01 | `anti-rea-demo verify` | Condition, source path, line, signature, mesh message | Public severity, opaque location and sealed event; still aborts |
| D02 | `anti-rea-demo assert` | Internal invariant and assertion location | Same fatal behavior without plaintext description |
| D03 | `anti-rea-demo warning` | Internal preconditioner detail and iteration count | Offline-recoverable encrypted template and fields |
| D04 | `anti-rea-demo exception` | Internal tensor error through diagnostics and `what()` | Sealed event plus opaque exception text; exit status remains 3 |
| R01 | `anti-rea-demo rtti` | Internal class, template and lambda/function names | Opaque RTTI strings, with RTTI functionality retained |
| S01 | Audit library symbols | Internal global variable and method names | Hidden definitions and a stripped installed ELF copy |
| S02 | Audit imports and exports | Public `ar_*` API and runtime dependencies | Necessary public API still visible, explicitly not a secret |
| P01 | `anti-rea-demo location` | `__FILE__` and signature | Opaque file identifier |
| P02 | Inspect debug metadata | Source names, paths, variables and compiler details | Private IR keeps metadata; native protected objects omit it |
| P03 | `anti-rea-demo resource` | Descriptive resource basename in code | Stable opaque basename and executable-relative lookup |
| P04 | Audit ELF runtime paths | Build-directory RUNPATH in build artifacts | Installed ELF uses `$ORIGIN`; relocation remains functional |
| P05 | Inspect Windows CodeView | Potential full PDB path | Linker records only the PDB basename; PDB stays private |
| O01 | Inspect `policy_dispatch` | Straightforward branches and constants | Selected xollvm expression/CFG transformations by level |
| O02 | Inspect `policy_token` in mixed-vm | Direct arithmetic | VM transformation; separate function from CFG flattening |
| O03 | Search ordinary dispatch text | Plain string outside protected diagnostics | Remains in protected-only mode; xollvm strenc hides it at rest |

## D01-D04: Diagnostics Are Data

An assertion macro can leak more than its message: stringifying the expression
discloses variable names, `__FILE__` discloses a source path, and a function-signature
macro reveals templates and implementation types. Simply replacing the text at
runtime can leave all of it in the read-only data section.

The example uses a generated diagnostic catalog. In protected mode the C++ header
contains only public severity labels, opaque IDs, a public key and encrypted
templates. The condition expression is evaluated normally; its textual spelling
and location expansion are absent from the protected preprocessor branch.
Successful verification evaluates its condition exactly once and never formats
diagnostic arguments. Failure still aborts. `AR_ASSERT` is an explicitly always-on
example check, not the NDEBUG-controlled standard `assert` macro.

The exception example deliberately protects both the reporting path and `what()`.
Protecting only the logger while throwing the original descriptive message would
leave a second plaintext leak. Generic standard-library messages remain possible.

## R01: RTTI Is Not Just a Symbol Table

Even a stripped binary can retain type names because the runtime uses them.
`-fno-rtti` is not equivalent protection: it changes available C++ functionality.
Here a pre-codegen transformation changes selected RTTI string initializers while
leaving typeinfo records, pointers, vtables and inheritance data in place.

The tests include a derived type with virtual and multiple inheritance, a
cross-library factory, sibling conversion, `typeid` equality and a custom exception
thrown by the library and caught by the executable. A template containing an
internal type and a local lambda demonstrate names that a simple class-name list
could miss. Quoted LLVM symbol names are explicitly handled.

This is a narrow demonstration policy: `aegis::internal` types and types local to
`print_rtti` are selected. It is not a general C++ ABI transformation specification.
All producers and consumers must use consistent rules and keys. Persisted
`type_info::name()`, ordering or hash values must not be treated as a stable public
serialization format.

## S01-S02: Symbols Have Different Ownership

Local symbols are removable from a release copy. Dynamic exports and imports may
be required for loading, plugins and C++ ABI operations. The demo intentionally
keeps its small public C interface and standard runtime dependencies. Internal
classes are not an exported C++ plugin API.

Stripping does not erase diagnostic strings, RTTI initializer contents or source
paths used as runtime data. Compare `stripped` with `protected` rather than treating
both as the same protection. Local variable names generally require debug records;
the scanner does not infer original variable names from register or stack usage.

## P01-P05: Treat Each Path Channel Separately

Compiler prefix mapping changes compiler-generated paths, not arbitrary string
literals. Removing LLVM debug metadata addresses another channel, while the
`source_filename` field is replaced with an opaque compilation-unit label.
The installed ELF loader uses a relative path. Windows gets a PDB-basename rule,
not ELF stripping. The resource locator is computed from the executable location,
so renaming resources does not break relocation.

The resource file contains a harmless coefficient, not generated C++ source.
Shipping actual JIT source would expose its contents regardless of its filename.
Build directories, compiler launch logs and maps are explicitly private and can
contain information intentionally absent from the installed binary.

## O01-O03: Measure Applied Transformations

A successful compiler exit is not evidence that an obfuscation pass ran. Some
passes skip unsupported functions, especially VM on exception-handling code.
The two selected policy functions avoid those constructs. The launcher validates
the upstream per-function report and rejects missing or skipped required
transformations. The VM target is distinct from the flattened target.

The ordinary dispatch string intentionally illustrates a limit: diagnostic
protection is not whole-program string encryption. xollvm's string pass decrypts
at process initialization and cannot provide the same confidentiality as a sealed
diagnostic whose private key is absent from the process.
