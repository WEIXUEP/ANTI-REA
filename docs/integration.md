# Build Architecture and Integration

English | [简体中文](integration.zh-CN.md)

## Ownership Boundaries

The project is intentionally standalone. CMake owns target configuration and
installation, Python owns catalog generation and IR transformation, and C++ owns
runtime behavior. The installed directory contains only runtime artifacts and
the example resource. Private maps, keys, IR and debug files have no installation
rules.

The generic API is a demonstration, not an ABI-stable protection SDK. Adapt the
policy to the target project instead of mass-replacing arbitrary logging calls.

## Compiler Pipeline

```text
C++ source + generated sealed catalog
   -> Clang frontend, original optimization intent, LLVM passes disabled
   -> ABI-aware RTTI initializer replacement
   -> LLVM verification
   -> optional xollvm obfuscation and report validation, exactly once
   -> strip private IR debug/local-name metadata and alias source_filename
   -> native object using the requested optimization level
   -> ordinary linker
   -> installed release copy with platform-specific symbol policy
```

Preserving frontend optimization intent avoids accidentally introducing O0
`noinline` attributes into an O2 comparison. Dependency generation belongs to the
source phase. The second compiler phase consumes IR and does not overwrite source
dependency records. Runtime-library, PIC and optimization settings are carried
to native code generation for the supported example invocations.

The launcher is explicitly attached to both the executable and shared-library
targets. A launcher is not a transitive CMake link usage requirement: linking an
interface library does not automatically protect every consumer translation unit.
Private reports are keyed by object path, avoiding collisions when the same
source is compiled for two targets.

The frontend command parser supports one source and explicit object output,
recursive response files, quoted paths, UTF-16 Windows response files, JOM `--`
and clang-cl `-TP`. It rejects known LTO/PCH/module modes. It is not a universal
replacement for Clang's driver; new compiler modes require new acceptance tests.
Do not mix another transformation launcher without designing the chain explicitly.

## Adapting an Existing Project

1. Audit the intended source and installed artifacts before changing them. Identify
   which records belong to first-party code, public ABI or dependencies.
2. Add the master switch at the owning CMake layer. Forward independent
   `XXX_CODE_PROTECTION` settings to dependencies only when they support the same
   contract; do not assume a parent macro rewrites dependency binaries.
3. Route confidential diagnostic templates through a small central interface.
   Preserve evaluation, fatal/throw behavior, severity and output routing. Treat
   dynamic string arguments and exception messages as separate possible leaks.
4. Define an internal type selection policy for the ABI. Rebuild all consumers
   with consistent naming rules and key material; verify cross-library RTTI.
5. Set visibility and the public export list deliberately. Keep internal C++ types
   out of a published ABI when possible. Arbitrarily renaming exports breaks clients.
6. Handle compiled paths, debug artifacts, resources and runtime-loader paths as
   separate channels. Test the installed package after relocation.
7. Introduce obfuscation only after functional protection is verified. Start with
   non-hot, well-tested functions and inspect the upstream transformation report.
8. Re-audit the actual installed executable, DLLs/shared objects and package files.
   Archive private recovery material separately from the distributable.

## Compatibility

| Configuration | Contract |
| --- | --- |
| Linux Clang, matching opt, CPU | Implemented and locally tested; see measured results |
| Linux GCC baseline | Ordinary example compilation; not the protected IR backend |
| Windows x64 clang-cl + JOM | Implemented entry points and CI; native acceptance status is separate |
| Ordinary MSVC cl.exe | Baseline only; protected compilation fails explicitly |
| LLVM 22/23 + xollvm | Required for obfuscation; other LLVM majors fail the capability gate |
| LTO, PCH, C++ modules, CUDA/HIP | Not supported by this teaching launcher |
| macOS | Not an acceptance platform for this project |

## Reproducibility and Publication

The comparison tool uses separate compiler-specific build and install directories,
so changing a compiler does not silently reuse another compiler's CMake cache.
It always passes an explicit installation prefix. It never installs demo programs
into a system directory.

Publish source, English and Chinese docs, sanitized results and explicitly public demo keys.
Keep `.private`, build directories, intermediate LLVM IR, raw audit logs and PDBs
out of Git and release packages. A scan report can itself reveal source paths or
symbols; review it before publishing. Git ignore rules are a convenience, not an
access-control system.
