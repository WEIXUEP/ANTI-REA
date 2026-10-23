# Verified Windows Boundary

The 2026-10-23 owned case compared source, pyc, PyInstaller 6.22.3 onefile,
cryptography 50.0.2 AES-GCM loading, PyArmor 9.2.8 official trial/core 8.1.2,
and Nuitka 4.3.1 standalone on CPython 3.12.14 x64. Native compilation used
clang-cl 23.1.2 and Intel's installed lld-link, with 8 build jobs and no xollvm
obfuscation passes. Exact installed dependencies are retained in the run evidence.

All six preserved the tested behavior and relocation across 256 fixed-seed
random cases plus nine boundary/error cases. This covers the synthetic integer
workload, nested imports, dynamic plugins and its specific resource interface;
it does not establish arbitrary application compatibility.

| Profile | Raw selected corpus | Demonstrated recovery |
| --- | --- | --- |
| Source | All four markers visible | Source directly available |
| pyc | All four visible | Disassembly-guided independent rewrite passed 265 cases |
| PyInstaller | No selected raw hits in outer EXE | CArchive/PYZ extraction exposes bytecode; the same rewrite, with separately checked evidence, passed 265 cases |
| AES loader | No selected raw hits | Shipped key decrypted complete source; recovered app passed 265 cases; compile observations also exposed source |
| PyArmor trial | Resource marker remains | Metadata-only runtime observation exposes class/function names; no validated algorithm reconstruction |
| Nuitka | All four remain | REA/IDA found names and decompiled a runtime function; no validated core reconstruction |

The analyst designed the case. Recovery commands excluded source/build/private
inputs, but this was not an independent blind trial. The independent rewrite was
shared by the pyc and PyInstaller checks, not two separate analyst recoveries.
Each profile's analysis was limited to at most 15 minutes, with actual command
times retained; unfinished work is not resistance proof.

An exploratory PyArmor code-object serialization crashed the process with
0xc0000005. It was retained as a failed observation. Metadata-only capture then
completed without patching the runtime or changing its license. Do not prescribe
code dumping for protected or modified code objects.

The corpus had four synthetic labels, not every possible secret. AES ciphertext,
compression, executable packing and absence of direct byte hits establish
different things. The tests do not show cryptanalytic breaks of AES-GCM or defeat
of a commercial protection configuration. Private HTML reports and raw evidence
are not bundled in this skill.
