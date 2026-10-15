# xollvm Integration and Strength Levels

External project: <https://github.com/und3ath/xollvm>

The integration targets **v0.11.1**, commit
`eb0850bd7cc87f551ad2948826605e518f5b8aa2`. Use the documentation at that revision,
not a moving main-branch guide. LLVM 22 and 23 are supported by that upstream
revision. The compiler and opt must have the same LLVM major version.

## Install the Toolchain Yourself

Follow upstream's [pinned build guide](https://github.com/und3ath/xollvm/blob/v0.11.1/docs/BUILD.md).
On Linux, use either an xollvm toolchain with built-in passes or a plugin compiled
for the matching LLVM. On Windows use the static-extension toolchain: a generic
prebuilt LLVM installation does not necessarily export the symbols required to
load a pass plugin.

The project does not download tools or replace the system compiler. It can consume
a user-extracted toolchain from any local directory. Keep downloaded tools outside
versioned source, for example under ignored `build/toolchains/`.

The local Linux validation used the operator-supplied archive
`xollvm-linux-llvm23-Release.tar.zst`, SHA-256
`5766b3a9f1342b5d2040c229dc22e586f3e65eec389fcd41e46d224fd8797a8c`.
It reports Clang/LLVM 23.1.2, LLVM commit
`ba019b7aafce09a013cf7e9139fa0c229f09b188`. These observations do not independently
prove the xollvm source revision used to produce that archive. Its available
passes and report schema were checked and the complete strength matrix was run.
The archive was extracted inside the Linux filesystem; no Windows-mounted build
directory or system compiler replacement was used.

```bash
python tools/anti_rea.py doctor \
  --compiler /path/to/xollvm/bin/clang++ \
  --opt /path/to/xollvm/bin/opt --level LIGHT

cmake --preset obfuscated-light \
  -DCMAKE_CXX_COMPILER=/path/to/xollvm/bin/clang++ \
  -DANTI_REA_OPT=/path/to/xollvm/bin/opt
cmake --build --preset obfuscated-light
ctest --test-dir build/obfuscated-light --output-on-failure
```

For a Linux plugin add `-DANTI_REA_XOLLVM_PLUGIN=/path/to/Obfuscator.so`.
The capability probe proves that the pass is available, not that a user's binary
really came from the expected source commit. Record the supplied archive digest,
compiler version, opt version and independently verified upstream provenance.

Minimal toolchain distributions may omit `llvm-cxxfilt`; Linux can use GNU
`c++filt` for RTTI selection. Windows requires `llvm-undname` on the toolchain
directory or PATH. Demanglers interpret names, not LLVM IR, and do not need the
same LLVM major as opt.

## Function Selection

| Level | `policy_dispatch` | `policy_token` | Numerical hot loop |
| --- | --- | --- | --- |
| NONE | Original | Original | Original |
| LIGHT | Low-budget MBA, substitution, splitting | Same light transforms | Original |
| MEDIUM | More MBA, substitution, splitting and bogus branches | Same medium transforms | Original |
| HEAVY | MBA, bogus branches, flattening, shield and limited adec | Same heavy transforms | Original |
| MIXED_VM | MBA, splitting and flattening | VM light preset | Original |

The policy translation unit also enables module-wide `strenc`. Its presence in a
function annotation does not mean only that function's string literals are touched.
The module is deliberately small; encrypted diagnostic templates in other units
do not depend on this pass.

VM and flattening never target the same function. VM anti-debug and hardened
timing traps are disabled. This is a reproducible obfuscation exercise, not an
anti-analysis process that interferes with the validation debugger.

## Exact Pipeline and Evidence

The Python launcher invokes `opt -passes=obfuscation,verify` exactly once, with a
fixed seed, deterministic mode, upstream verification and an instruction budget.
Do not also enable `-enable-obfuscation` in Clang: that would run the pipeline twice.

Each object gets its own upstream report. The launcher checks the known report
schema, requires evidence for both selected policy functions, and rejects a
missing/skipped required VM or flattening transform. Other passes can legitimately
be skipped and those reasons remain in the private report.

Specifically, flattening is required on `policy_dispatch` for HEAVY/MIXED_VM, and
VM is required on `policy_token` for MIXED_VM. The one-block token function can
legitimately skip flattening in HEAVY while still receiving expression transforms;
requiring CFG restructuring of that straight-line function would be a bad gate.

Inspect `build/<configuration>/private/ir/*/xollvm.json` and the corresponding
`private/maps/*.json`. Matrix builds record the actual build directory in their
JSON report. Do not publish those raw reports without checking their identifiers.

Build success is insufficient. Runtime tests check exact computation, RTTI,
exceptions, diagnostics and relocation. A post-install scan checks that sensitive
diagnostic and type-name plaintext has not reappeared. The mixed VM workload must
produce the same checksum as the unmodified integer reference.

## Costs and Limits

More complicated IR can increase compile time, size, startup work and CPU time.
Strength labels are configuration names, not measured resistance against an
analyst. Report instruction growth and performance separately from leakage counts.

`strenc` decrypts ordinary strings at process initialization. The executable carries
the machinery needed to recover them; memory inspection can reveal the plaintext.
This is materially different from diagnostic public-key sealing, whose private
key is not in the program.

VM can skip functions containing exception-handling constructs, unsupported
control flow or excessive blocks. Reports and fail-closed target checks prevent
those skips from being mistaken for successful protection of the selected target.
Keep hot numerical kernels out of heavy obfuscation unless benchmarks justify it.
