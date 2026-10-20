# What Remains Discoverable

English | [简体中文](remaining-exposure.zh-CN.md)

The protected release is deliberately not a featureless opaque file. This page
explains the residual inventory observed in the Linux measurement, and what a
zero sensitive-corpus count actually means. Exact counts and timings are in
[comparison.md](comparison.md); machine-readable summaries are in
[comparison.json](comparison.json).

## Reading the Current Measurement

The declared sensitive corpus produced 71 matches in the baseline release, 23
after stripping alone, and zero after the combined protection measures. These are
match counts, not a count of unique secrets or a proof of complete confidentiality.
The protected-only policy benchmark remained near the baseline's 2.6 ms for this
workload; the small difference is not evidence of a performance improvement.

Heavy obfuscation took about 17 times the baseline policy-loop time, and the mixed
VM configuration about 30 times. Those ratios describe the deliberately targeted
500,000-iteration policy workload, not a whole scientific application. The separate
numerical loop is not obfuscated. This is why the project offers different levels
and avoids recommending VM or aggressive CFG rewriting for every function.

Protected installed artifacts were about 62.5 kB versus 54.3 kB for stripped-only;
the mixed VM example grew to about 300 kB. These sizes exclude dynamically linked
system libraries and libsodium. See the measurement guide before generalizing.

## Intentionally Visible

| Evidence | Why it remains | Does the demo hide it? |
| --- | --- | --- |
| `ar_create`, `ar_destroy`, `ar_type`, `ar_throw`, `ar_compute` | Public C interface needed by the executable | No; the protected ELF library restricts exports to these five functions |
| C++ runtime, libc and crypto imports | Dynamic loading and normal execution | No; internal source labels are a different category |
| `libengine.so`, `libsodium.so`, system DLL names | Loader/dependency identity | No; hiding these is not required for the declared acceptance corpus |
| Opaque `65R...` RTTI strings | Type identity with names replaced | Original internal names are hidden; RTTI records and layouts remain |
| Public severity labels and diagnostic IDs | Support and offline recovery | No; the descriptive template and fields are sealed |
| Compiler version and public LLVM repository URL | Compiler `.comment` metadata | Not removed by this demonstration; it does not identify the private source root |
| `/lib64/ld-linux-x86-64.so.2` | Linux loader | No; this is a system path, not a developer source path |
| `/proc/self/exe` | Executable-relative resource discovery | No; intentional runtime facility |
| `$ORIGIN` | Relocatable installed library search path | No; replaces the absolute build directory |
| Opaque `R-...dat` and coefficient content | Installed runtime resource | Filename semantics are hidden, not resource contents |
| Arithmetic, control flow and memory access | Executable functionality | Selected functions are obfuscated, not made unobservable |

## Deliberately Demonstrated Limits

The `rtti` command also prints an ordinary dispatch description. That string is
outside the diagnostic catalog: it remains plaintext in `protected`, while
xollvm's module string pass hides its static representation in obfuscated presets.
It is still printed at runtime after decryption. This is an intentional contrast
with public-key diagnostic secrecy, not a claim of whole-program log protection.

Stripping alone leaves diagnostic and RTTI contents, and it can leave an exported
global variable name. The protected build combines mechanisms instead of using
strip as a substitute for them. The current release gate scans both the executable
and the example library for the declared sensitive messages, class/function/global
names and first-party source basenames. It also rejects the actual developer
project root in installed artifacts.

The path inventory distinguishes public URLs from filesystem paths. Arbitrary
machine-code or ciphertext bytes can resemble printable paths, so path findings
are candidates rather than automatic proof of a source-path leak. Necessary system
paths should be reviewed and documented, not replaced blindly.

## Private Artifacts Are Not Releases

Unstripped build executables can still contain original mangled function and type
symbols even though runtime RTTI initializer strings have changed. Their build
RUNPATH can include the build directory. Intermediate IR retains original metadata
for developer investigation; maps retain original types and diagnostic locations.

Those files are intentionally private. The installed release copy is independently
stripped/audited and has no installation rule for private maps, keys, IR or PDBs.
Do not publish a build-directory archive as if it were the release package.

On Windows, run the native PE/PDB procedure and report the findings separately.
The Linux observations do not establish Windows release cleanliness.

## What an Analyst Can Still Do

An analyst can inspect vtables and exception machinery, identify standard-library
behavior, trace inputs and outputs, inspect plaintext ordinary strings in memory,
and reconstruct parts of an algorithm from instructions. Public demo keys let any
reader decrypt demo warnings. Even privately keyed diagnostics do not conceal
fields from a debugger observing the program before encryption.

The project reduces selected easy disclosures and gives developers a recovery
workflow. It is not DRM, an anti-debugging system or proof against reverse
engineering.
