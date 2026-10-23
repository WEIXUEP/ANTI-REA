# Recovery Research

## Trusted Runtime Observation

Static audit never executes the target. For a reviewed local owned program, run
runtime observation separately with a process deadline and package-only inputs:

```powershell
python <skill>/scripts/capture.py --entry <release/main.py> --module-prefix <owned-package> --out <new-private-capture> --execute
```

The target reads its normal stdin. Metadata mode records observed exec/call names
and filenames; it neither reconstructs algorithms nor proves all paths executed.
It is not a security sandbox. Do not use this command on unknown artifacts.
The supervisor must terminate the process tree on timeout and retain exit status.

For ordinary owned CPython source/pyc or the specific tested AES demo,
`--dump-code` additionally retains compile inputs and serialized code objects.
Do not use it on modified/protected objects: an exploratory PyArmor 9.2.8 trial
capture crashed with Windows 0xc0000005. Metadata-only capture subsequently
worked. A crash is an unsuccessful observation, not evidence of recovery or
protection strength. Serialized bytecode is not independent source reconstruction.

## Observed Case Results

In the 2026-10-23 Windows CPython 3.12.14 case:

- pyc preserved inspectable names, constants and disassembly. A manually written
  independent algorithm from those observations matched 265 private test cases.
- PyInstaller 6.22.3 onefile had zero selected outer-byte hits. CArchive/PYZ
  extraction exposed the bytecode; independently checked extracted evidence
  supported the same rewrite, which passed the same private cases.
- The case's AES-GCM loader carried its decryption key. Using only that release
  recovered complete source; the recovered app passed the private cases. Compile
  observations also exposed source. This was not an AES cryptanalytic attack.
- PyArmor 9.2.8 official trial/core 8.1.2 left the separate resource plaintext and
  exposed original class/function names to metadata observation. No core algorithm
  reconstruction was validated, and paid modes were not tested.
- Nuitka 4.3.1 standalone retained selected names/diagnostics/resources. REA/IDA
  observed strings and decompiled a runtime initialization function; that did not
  identify or reconstruct the core transform.

The analyst knew the synthetic design. Commands excluded original source, private
keys and test vectors during recovery; they were not an independent blind trial.
The 256 fixed-seed random cases plus nine boundary/error cases establish only
that tested domain. One rewrite served both bytecode-bearing profiles. Report
actual effort and an upper bound separately; each profile had a 15-minute cap.

## Optional Native REA Analysis

Use an existing configured REA installation for Nuitka executables or extension
modules; the skill ZIP does not bundle REA, IDA, Ghidra or a native decompiler.
Bind input SHA-256, provider, actual function addresses and Evidence before
decompiling. Read the workspace's REA research context where present. Preserve
existing databases; do not substitute a build-tree PDB or generated C file into
a release-only recovery trial.

Search returned names/strings, follow supported references and inspect observed
functions. Provider-generated labels and a runtime wrapper's pseudocode do not
establish recovery of Python semantics. The tested IDA adapter reported incomplete
body-range/CFG/reference capabilities. Retain those limitations and the Evidence
bundle; close owned sessions and verify cleanup. Do not infer another backend's
capabilities from a successful IDA query.
