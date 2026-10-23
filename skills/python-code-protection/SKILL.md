---
name: python-code-protection
description: Evaluate and implement scoped Python distribution protection using authenticated loading, PyArmor or native compilation. Establish the original baseline, test imports/resources and behavior, measure costs, and countertest recovery. Use for authorized Python protection changes, not read-only leakage diagnosis.
---

# Python Code Protection

Preserve an original release, file hashes, its interpreter/environment and working
inputs before changing protection. Confirm known-sensitive source names, paths,
diagnostics and resources are found in that baseline. Missing original artifacts
leave improvement unverified. The optional `python-leakage-audit` skill can help;
this package is usable without it.

Read [operations.md](references/operations.md) for tool setup and selection and
[verified-results.md](references/verified-results.md) before interpreting the
tested Windows case. `scripts/doctor.py` inspects installed distributions without
installing, activating licenses or building anything. This skill guides target
integration; it does not bundle a universal encryptor or the repository's case.

Agree the supported Python version, native dependencies, public interfaces,
plugins, resource layout, traceback policy, source-map retention and performance
budget. Keep unchanged behavior as an acceptance gate. Public module names used
by dynamic imports cannot be renamed blindly.

Choose a control for the actual goal:

- pyc is executable bytecode, not encryption. Names, paths, constants and control
  flow can remain inspectable without a working source decompiler.
- PyInstaller is distribution packaging. Inspect extracted members and onefile
  runtime dependencies; compressed bytes alone can defeat a superficial scan.
- AES-GCM provides payload authentication and storage confidentiality relative
  to the key. A client carrying its key and loader exposes plaintext at runtime.
  Use a maintained crypto library, unique random nonces and authenticated format
  metadata; reject authentication failures before compilation or execution.
- PyArmor requires its actual runtime, license and version compatibility. Test
  the permitted configuration; trial results do not verify commercial modes.
- Nuitka compiles Python behavior into native code with Python runtime support.
  Compilation does not guarantee removal of names, diagnostics or data files.

Keep baseline and each optional profile separate. Do not introduce anti-debugging,
global import hooks, runtime patches or maximum obfuscation into another project
as an incidental change. The case-only memory loader is not a general importer.
Keep its use explicit and preserve import/resource/exception contracts.

Test installed and relocated releases from an unrelated working directory,
including nested imports, dynamic plugins, data files, errors and integer edge
cases. Test wrong keys, ciphertext/header changes and truncation for authenticated
loaders. Retain internal build outputs separately from the release inventory.

Countertest release-carried material, extracted archives, inspectable bytecode
and observable loading boundaries in reviewed isolated processes. Use only the
release as recovery input, then verify the reconstruction against private tests.
Disclose prior source knowledge: input isolation is not an independent blind test.
Set an analysis budget; incomplete recovery never establishes impossibility.

Measure build time, complete package size, external runtime requirements,
startup and core work separately. Use repeated samples and raw observations;
do not compare a standalone executable's size with scripts while concealing the
scripts' external interpreter or crypto dependencies. First measurement is not a
cold-cache measurement unless caches were controlled.

Deliver four separate verdicts: behavior, selected plaintext hiding, demonstrated
recovery and cost. Keep raw keys, code captures, private tests, build files and
recovery evidence out of public skill/download packages. Report unavailable
checks and failures alongside successful ones. No tested technique makes Python
software unrecoverable.
