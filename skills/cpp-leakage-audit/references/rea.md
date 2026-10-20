# Native Security Review with REA

## Backend and Version Boundary

REA is an optional, separately licensed backend. It supplies parsed inventory,
references, instructions, decompilation and bounded native value-flow graphs.
The bridge calls its public CLI JSON interface, never private TypeScript imports.
The repository records a Git submodule commit in `third_party/rea`; a normal
clone and the independent skill ZIP do not include a built REA installation.
The ZIP includes this guide and `scripts/rea_audit.py`, not REA or its engines.

From an ANTI-REA checkout, initialize the recorded revision explicitly:

```bash
git submodule update --init third_party/rea
```

Build only when backend preparation is within the requested scope, using the
pinned checkout's `AGENTS.md`, Node/package-manager requirements and build guide.
At the currently tested revision the commands are `npm ci` and
`npm run build:cached`. Submodule initialization alone does not install a runtime,
build the Windows native addon, install Ghidra or register an MCP server.
Windows Ghidra analysis needs the matching native addon, supported local NTFS
paths, a supported Ghidra distribution and full JDK. Preserve an unavailable
provider's actual reason; do not substitute string scanning for decompilation.

Existing builds can be selected with `--rea-root /absolute/path/to/rea`. Record
the backend commit/version and provider; an alternate installation is not proof
that the recorded submodule's build was verified. Do not use automatic `npx
@latest`, run `rea update`, or follow submodule remote HEAD during an audit.
Upgrade as a separate change: select a commit, repeat interface/native checks,
then commit the new gitlink. No REA code is copied into the Python scanner.

## Baseline, Plan, Then a Selected Query

Capture `audit.py --binary ... --require-metadata --out ...` first using the
original artifacts and known-leaking controls. The bridge verifies its sibling
scanner hash, selected artifact size and SHA-256 against that immutable report.
It checks the target again after analysis. For duplicate artifact hashes,
select the exact report label with `--artifact`. A changed binary requires a
new baseline revision; keep the old evidence. Never alter a baseline to bypass
the identity check.

```bash
python <skill>/scripts/rea_audit.py --baseline /private/original.json \
  --binary /original/app.exe --out /private/review-plan
python <skill>/scripts/rea_audit.py --baseline /private/original.json \
  --binary /original/app.exe --rea-root /tools/rea \
  --action search-procedures --selector strcpy --out /private/strcpy-search
python <skill>/scripts/rea_audit.py --baseline /private/original.json \
  --binary /original/app.exe --rea-root /tools/rea \
  --action xrefs --selector 0x140001000 --out /private/sink-references
python <skill>/scripts/rea_audit.py --baseline /private/original.json \
  --binary /original/app.exe --rea-root /tools/rea \
  --action function --selector 0x140002000 --out /private/caller
```

Addresses above are placeholders. Select actual addresses returned by REA.
For packaged inputs also supply `--package-root /original/release`; the bridge
checks the baseline's relative layout and rejects reports inside that package.
`--out` is a **new directory**, unlike the leakage scanner's output prefix.
Existing output directories are refused. Reports contain private code evidence.

The default `plan` uses only parsed import/delayed-import symbols in the baseline,
including imports accepted by leakage allow rules. It suggests conditional CWE
hypotheses for copying, formatting, command execution, library loading and
temporary-file APIs. A byte string, export or similarly named function does not
establish an imported sink. Import presence does not establish a call, argument
control or an unsafe condition. Static linking, inlining, ordinal/dynamic imports
and custom parsers require focused manual review even when the plan is empty.
No CVE lookup, version vulnerability database or automatic exploit is included.

| Bridge action | REA CLI | Question |
| --- | --- | --- |
| `search-procedures` / `search-strings` | `search --kind=... --mode=literal` | Which exact names/addresses are present? |
| `xrefs` | `xrefs --address=...` | Which locations reference the selected sink/data? |
| `function` | `function --procedure=...` | What are this caller's code, references and flow? |
| `instructions` / `decompile` | corresponding CLI command | What do the actual instructions/derived pseudocode show? |
| `values` | `trace-native-values` | How do recovered values flow through resolved calls? |
| `call-targets` | `resolve-native-call-targets` | Is this particular indirect call resolved? |

`values` and `call-targets` accept exact `0x` addresses. Value tracing bounds
depth/functions/call sites to 2/8/128; retain returned omissions and limits.
Other provider limits still apply. The bridge admits only these read-only
actions and invokes Node with an argument list, without shell interpretation.
It does not provide setup, runtime, injection, mutation or recovery operations.

Exit 0 means a plan was written or the selected REA query returned a successful
JSON envelope whose Evidence digest, operation and provider match the request.
For composed value tracing, the parent provider is `rea-workflow`; the bridge
checks the trace target digest and each constituent procedure's engine and
Evidence reference instead of pretending the parent itself is Ghidra.
It never means no vulnerabilities. Exit 2 means invalid input,
identity/output failure, unavailable backend, failed query or invalid output.
`report.json` retains candidates, binding, baseline gaps and the complete REA
envelope. `rea.stdout.txt` and `rea.stderr.txt` preserve raw query bytes when a
query ran. `completed` describes query execution; returned Evidence coverage,
unknown edges and provider limitations still determine what can be concluded.
No subprocess timeout is imposed on top of REA's provider deadlines; Ghidra
startup and owned child cleanup remain REA's responsibility.

## Reviewing Virtualized Functions

Treat applied-transform evidence, readable VM implementation and recovered
original semantics as separate results. Confirm the selected function actually
received VM before interpreting a decompilation attempt. Locate the function in
the current release through executable metadata and call sites; record any
private symbols or maps used as analyst assistance.

Inspect the wrapper, dispatcher, bytecode references and selected handlers.
Preserve unresolved indirect edges, jump-table warnings and missing procedure
entries. A successful query with empty callees does not establish a complete
call graph. Nearby search results do not establish which function contains an
interior address; check observed body ranges. The bridge's `function` selector
expects a known procedure entry, not an arbitrary instruction address.

Readable pseudocode or exposed constants are not automatic devirtualization.
Claim algorithm recovery only after reconstructing the target computation and
checking independent inputs against an authorized oracle. Source-based runtime
checks establish correctness of protection, not recovery by REA. State whether
dynamic tracing, symbolic execution or a custom devirtualizer was actually used;
a failed static recovery does not establish that recovery is impossible.

## Corroborating Leakage Before and After Protection

First capture the original scanner baseline and verify known-leaking controls.
Scan the supplied protected release with the same corpus, inventory and allow
rules using the scanner's baseline comparison. Keep both reports. For REA queries,
each binary must bind to the report of its own bytes: a protected binary cannot
use the original binary's digest as its identity.

```bash
python <skill>/scripts/rea_audit.py --baseline /private/original.json \
  --binary /original/app.exe --rea-root /tools/rea \
  --action search-strings --selector 'Exact sensitive diagnostic' \
  --out /private/original-string-query
python <skill>/scripts/rea_audit.py --baseline /private/protected.json \
  --binary /protected/app.exe --rea-root /tools/rea \
  --action search-strings --selector 'Exact sensitive diagnostic' \
  --out /private/protected-string-query
```

Repeat for selected original RTTI names in the executable and library. Preserve
positive-control matches and addresses. Search a required public function and
inspect its actual instructions/pseudocode in the protected library as a control
that analysis remains usable; obtain its address from that build, not the old one.
On Windows, set `GHIDRA_INSTALL_DIR` to the existing supported installation and
use a full JDK; an unset provider is an incomplete check, not a negative match.

Ghidra string searches cover defined string Data, not every byte in the file.
An empty REA result cannot prove plaintext absence; retain the scanner's exact
UTF-8/UTF-16 gate and metadata gaps independently. Opaque names still expose type
structure, and preserved public code can still be decompiled. Report corpus
removal, remaining analysis visibility and security candidates separately.

## MCP for Iterative Analysis

An already registered REA MCP server avoids repeating cold imports for each
CLI query. A Git submodule or skill installation does not itself register tools.
When tools exist, use their actual schemas. For registration use the selected
Node executable, args `[/absolute/rea/scripts/rea.mjs, mcp]` and the provider's
documented environment; preview and authorize client configuration separately.
Do not add mandatory MCP dependencies to this independently usable skill.

Bind the original target with `open_binary` (`path`, `provider_id: "ghidra"`);
select `search_procedures` / `search_strings`, `xrefs`, `analyze_function`,
`read_function_instructions`, `resolve_native_call_targets` and
`trace_native_values` as the specific question requires. These operate on the
active target. Check `binary_session` after a target/provider change or actual
availability failure. Do not guess addresses or call unavailable operations.
Keep the baseline artifact digest with the session/evidence identity. Preserve
inline Evidence and export it to a new private path when needed. Retained AWR
or Momentum work must use its existing projects/indexes under workspace rules;
this integration does not authorize reimporting completed investigations.

## Evidence Required for a Finding

For each candidate retain artifact digest, provider/version, exact caller and
call-site address, evidence IDs/raw query, hypothesis and review result.
Trace an entry/parser/input to the sink arguments; inspect branch constraints,
destination/source sizes, integer overflow, return handling and object lifetime.
Document whether an input is externally controlled and under which conditions.
For safe-looking calls identify the actual bound or constant that prevents the
condition, rather than clearing every call to the same API.

Use assembly to check the critical branch, size calculation or call convention;
decompiler types and p-code flow are derived evidence. Unresolved indirect calls,
aliasing, concurrency, omitted nodes and library semantics remain unknown.
An error path, dangerous import, missing mitigation flag or static connection
alone is a candidate, not a confirmed vulnerability. Keep exploitability and
severity provisional until preconditions and the unsafe reachable condition are
established. Runtime reproducers/fuzzing require their own authorized isolated
workflow; never execute an audited target simply to obtain an audit result.
