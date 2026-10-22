# Scoped Protection Integration

Read this for authorized changes to a target project. The bundled Python tools
work independently, but C++ protection must be adapted to the owning build and
ABI. An integration is not complete until affected producers, consumers and the
installed release have passed the checks in [validation.md](validation.md).

## Establish an Incremental Contract

Identify first-party namespaces, private/public types, error interfaces, target
graph, ABI, compiler, generator, CPU/GPU split and distribution layout. Preserve
user changes. Inspect effective compiler commands, including response files and
existing launchers, rather than infer configuration from a CMake option name.

Use one target-level protection switch when requested and propagate it to owned
subprojects using their native `XXX_CODE_PROTECTION` options. Keep key/tool paths
in an internal integration module or documented private preset. Reuse centralized
interfaces; do not mechanically replace thousands of diagnostic call sites.
Keep OFF behavior and a reproducible unprotected reference build.

Implement as small modules or target-scoped helpers, with the original code
calling a narrow interface. Adding the helpers is a repair; designing a new GUI,
rewriting dependencies or installing xollvm needs matching task scope. Missing
tooling should produce explicit unmet checks, not a silently unprotected release.

## Diagnostic and Location Protection

For macro-based diagnostics, evaluate the condition exactly once. Only format
failure fields on the same paths that previously formatted them. Preserve abort,
exception type, return/exit code and rank-routing semantics. Message expressions
with side effects need explicit review before removing or delaying evaluation.

The protected preprocessor branch must not expand raw message literals, `#cond`,
`__FILE__` or function signatures into runtime data. Generate a sealed catalog
at build time when retaining message text is required; the runtime carries only
the public sealing key. Capture dynamic fields separately and seal them before
logging. Encryption/formatting failure must not fall back to printing plaintext.
Keep public severity/error-class labels so errors remain operationally visible.

Bind a logical diagnostic site to project-relative canonical path and an explicit
stable site name. File/line/name identifiers should use separate keyed domains.
Emit a versioned private map with original location and template; validate ID
collisions and repeated call sites. Do not claim a line hash is intrinsically
reversible. Prefer build-generated metadata to optimizer-dependent removal of a
runtime string. Test debug and optimized configurations, not just release O2.

The bundled generator manages keys, not arbitrary C++ diagnostic extraction.
Choose a catalog or compiler-aware integration for the target; a regex over
arbitrary multiline C++ is not a general AST parser. Ensure generated headers
depend on both source/catalog inputs and effective key identity so incremental
builds cannot retain old templates or stale maps after rotation.

## RTTI Without Disabling Functionality

Opaque names preserve the ABI structures used for type equality, casts and
exception matching. Name replacement alone does not hide vtables, inheritance
relationships or required symbols. Keep public ABI and dependency types outside
the private selector unless their consumers are explicitly controlled.

For an LLVM IR integration, handle Itanium `_ZTS` name constants separately from
MSVC `TypeDescriptor` names. Verify the actual record layouts, string lengths,
NUL terminators, linkage, COMDAT and references. Reject unsupported layouts rather
than silently skipping owned types. Select from demangled actual types, including
templates, local types and closures; do not hard-code a demonstration namespace.

Use consistent canonicalization and naming material across translation units,
executables and shared libraries. Validate downcasts, sibling casts, `typeid`
equality, inheritance and typed exceptions across library boundaries. Do not
disable RTTI or exceptions to hide names. Plain MSVC does not accept an arbitrary
LLVM pass launcher; Windows clang-cl can expose an IR workflow, but that requires
its own command/ABI validation. A Linux fixture is not Windows runtime evidence.

## CMake, Compiler and Superbuild Coverage

Place common helpers in a dedicated CMake module and use target-scoped options.
An interface target can propagate usage requirements, but a
`CXX_COMPILER_LAUNCHER` property is not a transitive link dependency. Apply a
launcher explicitly to every protected producer/consumer target. Compose with an
existing launcher deliberately; do not overwrite it silently.

Normalize compiler executable paths, quoting, response-file encoding, JOM `--`,
`/Fo`/`-Fo` object names and clang-cl `/TP`/`-TP` variants. Separate frontend flags
from IR-backend flags without losing target, ABI, CPU, optimization, floating
point, exception and runtime-library choices. Preserve dependency generation.
Never pass a C++ source through the frontend twice accidentally. Unsupported
LTO/PCH/modules/CUDA invocations should fail closed until specifically supported.

Use unique per-object private work/report paths for parallel builds. Track source,
catalog, key and policy inputs; write maps atomically. Validate IR after each
semantic transformation and report missing objects or unexpected zero coverage.
Pass subproject switches through superbuild cache arguments and reconfigure/
rebuild affected dependencies and consumers when their public macros change.
Do not broaden first-party work to dependency diagnostics without authorization.

## Symbols, Debug Files, Paths and Resources

On ELF, hide internal visibility and explicitly export required ABI names. Keep
private debug artifacts and strip only a fresh release copy, never the only
debuggable executable. For an authorized staging destination, typical commands
are `objcopy --only-keep-debug` followed by `strip --strip-unneeded` on the copied
release. Check the actual tool/format before choosing these flags. Symbol removal
does not remove diagnostic literals or RTTI strings.

On PE, preserve internal PDBs outside the installer. Review exports, CodeView PDB
references and compiler/linker flags that embed paths. A PDB basename-only rule
can avoid a developer root, but the basename remains public. Do not assume ELF
strip commands are safe or equivalent on Windows; never remove required imports
or runtime metadata merely to reduce a scanner count.

Compiler path-prefix mapping can remove developer roots, but residual basenames
and runtime `__FILE__` may still expose source identity. Use the protected location
interface and, where supported, neutral compilation-unit labels. Check debug,
object and final release views separately. Never rewrite arbitrary linked bytes
to change path length; relocation, signatures and runtime contracts can break.

Resolve resources relative to the executable or configured install layout, not
the developer's build root or current directory. Use opaque aliases for sensitive
resource names, test relocation and inspect resource contents. On ELF, review
RPATH/RUNPATH for build paths and use appropriate relative installation entries.
On Windows, review DLL search and deployment policy; do not add unsafe fallback
search locations. Package inspection must include configuration/text assets and
debug artifacts, not only the main executable.

When resource contents themselves are sensitive and the application needs to
consume them locally, read [runtime-resources.md](runtime-resources.md). It covers
authenticated encrypted bundles, in-memory loading, installation hygiene and
optional persistent caches of derived binary results. Renaming a resource is not
encryption, and embedding a decryption key does not prevent analyst recovery.

## xollvm and Per-function Selection

The reference integration pins xollvm `v0.11.1`, commit
`eb0850bd7cc87f551ad2948826605e518f5b8aa2`, supporting matching LLVM 22/23 tools.
Upstream: <https://github.com/und3ath/xollvm>. Do not automatically download,
replace a system compiler or assume a tool's banner proves that revision.
Record the supplied archive/plugin digest and verified provenance separately.

Use the bundled doctor for a read-only version/pass probe. Linux can use a plugin
built against the matching LLVM or a static-extension toolchain; Windows should
use a supported static-extension clang-cl/opt pair rather than assume plugin
loading works. Consult the pinned tool's actual annotation/pass/report contract
before applying flags; do not copy another version's syntax blindly.

### Explicit Enablement for Ordinary C++ Builds

When compiling ordinary C++ directly with the supported xollvm Clang toolchain,
require `-mllvm -enable-obfuscation` to opt into the compiler's automatic
obfuscation pipeline. Without that explicit enablement, do not claim the
pipeline ran merely because xollvm was selected or functions have annotations.
Use a default-OFF CMake option and apply the flags to each selected target after
it is created:

```cmake
option(PROJECT_ENABLE_OBFUSCATION "Enable xollvm obfuscation" OFF)

if(PROJECT_ENABLE_OBFUSCATION)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "Obfuscation requires the supported xollvm Clang toolchain")
    endif()
    target_compile_options(${LIB_TARGET_NAME} PRIVATE
        "$<$<COMPILE_LANGUAGE:CXX>:-mllvm>"
        "$<$<COMPILE_LANGUAGE:CXX>:-enable-obfuscation>")
    target_compile_options(${TARGET_NAME} PRIVATE
        "$<$<COMPILE_LANGUAGE:CXX>:-mllvm>"
        "$<$<COMPILE_LANGUAGE:CXX>:-enable-obfuscation>")
endif()
```

Enable it deliberately with `-DPROJECT_ENABLE_OBFUSCATION=ON`; OFF adds neither
flag through this helper. Clang identification alone does not establish xollvm
support: perform the version/pass probe first. `PRIVATE` options do not propagate
through linking, so cover every selected source-producing target, including
object libraries. Inspect verbose build commands and response files for both
flags and any flags inherited from toolchain files, environment or other helpers.
Rebuild affected objects when changing the switch. Verify selected transforms
using applied/skipped reports and ON/OFF runtime checks; the enable flag alone
does not guarantee a particular function was transformed.

For ANTI-REA's launcher workflow, `ANTI_REA_OBFUSCATION=NONE` disables its xollvm
step; a selected level such as `LIGHT` explicitly invokes
`opt -passes=obfuscation,verify`. Do not add the compiler's
`-mllvm -enable-obfuscation` in that workflow, since it would enable a second
pipeline invocation. `ANTI_REA_CODE_PROTECTION` independently controls baseline
information protection and must not be confused with this obfuscation switch.

Keep baseline diagnostics/locations/RTTI and release stripping enabled, while
selecting control-flow transforms and VM by value and measured performance:

| Function category | Default selection |
| --- | --- |
| Numerical hotspot, SIMD/GPU kernel or unknown frequency | No expensive transform without evidence and a budget |
| Valuable frequent routine | Consider narrowly budgeted light transforms after profiling |
| Valuable cold decision logic | Consider medium/heavy transforms with correctness and overhead tests |
| Small especially valuable cold routine | Consider selective VM if constructs, ABI and cost are acceptable |
| Public ABI bridge | Preserve the ABI; avoid intrusive transforms at the boundary |

Keep a function-policy manifest with actual matched names, reasons, required
passes, exclusions and accepted overhead. Verify coverage against that manifest,
not demonstration function names. Module-wide string transforms can reach more
than the annotated function; isolate code or obtain approval for the wider scope.
VM and flattening must not target the same function when prohibited by the
toolchain. Leave anti-debug behavior disabled unless separately authorized.

A typical controlled pipeline is frontend IR generation, diagnostic/RTTI
protection, IR verification, exactly one xollvm pass invocation, verification and
native-object generation. If invoking `opt -passes=obfuscation,verify`, do not also
enable a frontend automatic obfuscation pipeline. Preserve target/ABI flags at
the backend. Retain per-object applied/skipped/changed reports privately.
Missing required targets, unexpected skips or unchanged required transforms are
failures, not proof of protection because compilation succeeded.

Measure baseline, stripped-only, protected and any selected obfuscation profiles
using equivalent optimizations and representative workloads. Report build cost,
size, startup and runtime separately. IR growth and timing alone are not proof
that the required pass ran. Numerical kernels must retain numerical behavior,
not merely produce the same demo checksum.

## CPU, MPI and CUDA Boundaries

CPU-first support does not establish signal-safety, allocator safety or safe
diagnostics during process teardown. Review the existing logger's locking and
failure behavior before adding formatting or encryption. Sealing allocates and
is not automatically suitable in a fatal signal handler.

For MPI, retain rank filtering, communicator behavior and collective termination.
Use atomic records or explicit event/rank IDs so ciphertext and location cannot
be joined to a different rank's event. Do not introduce an encryption collective
inside a rank-local warning. Test multi-rank output and failing-rank behavior in
an isolated job.

For CUDA, separate host and device compilation. A CPU libsodium reporter cannot
run in device code; neither can an unvalidated CPU IR transformer safely process
the entire NVCC/Clang CUDA pipeline. Preserve device assertions or use an explicit
bounded device event record collected and sealed on the host under an approved
design. Mark device protection unsupported until tested. Do not claim CPU-only
success covers GPU strings or kernels.

## Release Acceptance

Use the same sensitive corpus before/after, scan the actual fresh installed
package and inspect any accepted exposures. Exercise normal computation,
warnings, assertion/exception paths, offline recovery, cross-library RTTI and
relocation. Test ON and OFF. Report dependency exposures separately from owned
internals and distinguish successful Linux checks from unrun Windows/GPU checks.
Protection, symbol stripping and obfuscation reduce specific information
exposures; none proves that the program cannot be reverse engineered.
