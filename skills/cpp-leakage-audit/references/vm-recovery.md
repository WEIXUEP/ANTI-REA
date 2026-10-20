# Virtualized Function Recovery

Use when asked whether a selected owned/authorized function can be understood
after virtualization. Inspect the supplied artifact; do not enable protection,
rebuild the target or broaden the task to the whole application. Recovering
equivalent computation does not restore original names, comments or formatting.

## Bind the Investigation

Start with the original-program leakage baseline and positive controls from
`SKILL.md`. For each supplied protected EXE/DLL, capture its own scanner report
and SHA-256 before analysis. Bind REA queries to the report of those actual bytes,
using [rea.md](rea.md). Never bind a protected binary to an unprotected digest.
If the unprotected original is unavailable, retain a baseline of the supplied
artifact and report that before/after improvement remains unverified; binary-only
recovery can still proceed. Reuse retained imports, projects and queries.

Record the exact function, ABI, architecture, module hash and build settings.
Use applied-pass records when supplied, and corroborate the selected function's
VM wrapper/interpreter in the release. A compiler option, annotation or large
binary alone does not establish that this function received virtualization.
Unknown preset, anti-debug or hardening settings must remain unknown.

## Choose the Required Depth

| Result | Evidence and permissible conclusion |
| --- | --- |
| Static visibility | Wrapper, dispatcher, bytecode references or handlers inspected; no recovered algorithm implied. |
| Observed execution | Bytecode/state/targets captured on specified paths; no claim about unobserved branches. |
| Partial reconstruction | Reviewed operations or code, with unresolved semantics/paths stated. |
| Validated reconstruction | Independently compiled equivalent code matches original-function observations for the documented test domain. |

These are scoped results, not a security score. Preserve a failed or incomplete
attempt. Static failure does not prove irrecoverability; successful execution of
the original program does not establish algorithm recovery.

## Static Analysis First

Locate the current function using its callers, body ranges and executable
metadata. Record symbols, maps, source or unprotected controls used as assistance.
Do not silently copy the original implementation and call it recovered.

Inspect the wrapper's argument/state initialization, dispatcher, bytecode source
and selected handlers. Record VAs together with the image base and RVAs; ASLR
makes old runtime VAs unsuitable for a new process. Never reuse another build's
RVA without binding and checking its bytes. Verify critical operations against
instructions, including operand widths, flags, shifts and memory accesses.

Unresolved indirect edges, jump-table warnings or missing function entries are
coverage gaps. Empty callees do not establish a complete call graph. A nearby
procedure search result does not identify the owner of an interior address;
check the actual body range before querying a procedure entry.

## Dynamic Assistance When Needed

Use execution/instrumentation when it is within the user's existing scope and
the target is trusted or suitably isolated. A static audit alone does not imply
target execution. If execution is unavailable, retain the static/partial result
and identify what is missing. Do not request permission again for steps already
authorized by the user's recovery/validation request.

Discover the installed REA tool schemas. On the tested Windows backend,
`instrument_with_frida` provides instrumentation; `observe_native_calls` targets
Mach-O/LLDB and is not a Windows tracing substitute. This is separate from the
read-only CLI bridge. A missing provider is an incomplete check, not a reason
to install dependencies or change client configuration implicitly.

Use a bounded workload and retain scripts, tool versions, errors and raw Evidence.
Resolve the module at runtime; record its path, base, platform and architecture.
Record file hashes before/after, script hashes and instruction bytes at selected
sites. Frida Evidence may lack a subject/digest: supplemental file identity is
not cryptographic attestation of every loaded-memory byte.

Capture the initialized bytecode, dispatcher position/opcode, selected target
and relevant register/local state. Keep hook work minimal; inspect captured
instruction bytes and observed state before trusting a trace. A hook can fail
at a short indirect jump; inspect an adequate preceding instruction sequence
instead of guessing instruction boundaries. Retain failed hooks as failures.
Detach instrumentation and check process exit separately; detachment is not exit.

Before direct calls, establish calling convention, argument/return widths,
initialization, object ownership and relevant thread/state requirements.
For stateful functions, preserve setup and compare matching execution sequences;
arbitrary calls in an uninitialized process are not a valid oracle.

## Reconstruct Semantics

Map bytecode operations through the observed dispatch mapping and reviewed
handlers; retain offsets, operand decoding and instruction evidence. A trace's
return value is an oracle, not an algorithm. Preserve unresolved operations
rather than silently treating them as no-ops.

For encrypted bytecode, inspect the initializer and recover material actually
carried by the artifact when possible. Corroborate offline decoding against
runtime bytes. Label VM-internal cipher material separately from diagnostic
private keys and RTTI naming keys. Do not assume a cipher, nonce layout, opcode
table, salt or register mapping from a previous sample.

Generate code from recovered operations or document a reviewed reconstruction.
Preserve integer widths, signedness, wraparound, logical/arithmetic shifts,
endianness and the ABI. Include observable memory/state changes, exceptions and
failure behavior when relevant; return-value agreement alone is insufficient
for such functions. Do not introduce C++ signed-overflow or shift undefined
behavior while translating defined machine operations.

## Validate Independently

Compile the reconstruction as a separate private program or harness with the
target widths/ABI. Compare it with direct original-function observations or a
verified application path that reaches the exact function. Check deterministic
outputs or relevant invariants; do not hide nondeterminism behind loose tolerances.

Use boundary cases and inputs informed by recovered branches, then a distinct
holdout set not used to infer the model. Check uniqueness/disjointness and retain
the exact vectors, seeds, outputs and mismatch details. Choose coverage for the
function, not a fixed sample count from a previous demo. A mismatch means recovery
is partial until explained. Keep failing vectors and use a new evidence revision
for a correction; select new holdouts if the old ones informed that correction.

Record unvisited paths, unmodeled state and unsupported inputs. Finite matching
tests support agreement in the tested domain, not proof over all inputs. Report
formal/exhaustive equivalence only if that work actually ran. Recheck the original
artifact hash and any relevant uninstrumented smoke tests after instrumentation.
Keep protection correctness, reconstruction correctness and performance separate;
Frida-instrumented timings do not measure normal release overhead.

## Private Handoff Record

Retain these fields in a new private revision, using an existing report format
when available; no special public schema is required:

- Target and original-control identities, scanner baseline paths, function entry
  and image base/RVA; unavailable originals or settings.
- Backend/provider/compiler versions, exact commands, scripts and hashes,
  Evidence IDs/raw envelopes, observed instructions and dispatch/state captures.
- Decoder/handler interpretation, generated source, executable hashes and
  compilation result; unresolved semantics and source/control knowledge.
- Oracle setup, exact input/output vectors, boundary/holdout counts, uniqueness,
  mismatches, state/side-effect checks and remaining coverage.
- Final scoped result from the table above, original integrity, process cleanup
  and relevant uninstrumented checks.

Keep runtime dumps, binaries, keys, maps, PDBs, IR and private reconstruction
evidence out of release packages, skill ZIPs and public reports. Publish only
reviewed summaries. Identify manual assistance and sample-specific scripts:
one recovered VM-light function is not a general automatic devirtualizer.
