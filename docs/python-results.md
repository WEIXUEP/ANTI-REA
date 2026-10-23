# Python Windows Results

English | [简体中文](python-results.zh-CN.md)

Local acceptance on 2026-10-23 used CPython 3.12.14 x64, PyInstaller 6.22.3,
cryptography 50.0.2, PyArmor 9.2.8 trial/core 8.1.2 and Nuitka 4.3.1. Native
builds used clang-cl 23.1.2 plus Intel LLD 19.0.0, with eight jobs and no xollvm
obfuscation transforms. See [commands and limits](python-protection.md).

## Observed Protection and Recovery

All six profiles passed the same 265 behavior cases and relocation checks.
The corpus contains four selected synthetic markers; absence is not a complete
leakage audit or proof of recovery resistance.

| Profile | Direct selected raw-byte markers | Recovery observed |
| --- | --- | --- |
| Source | 4/4 | Plain source available |
| pyc | 4/4 | Names/constants/disassembly visible; independent rewrite passed 265 cases |
| PyInstaller onefile | 0/4 in outer EXE | CArchive/PYZ extraction exposed bytecode; same rewrite with separately checked evidence passed 265 cases |
| AES-GCM loader | 0/4 | Release-carried key recovered complete source; recovered app passed 265 cases; compile capture also exposed source |
| PyArmor official trial | 1/4, separate model resource | Metadata observation exposed class/function names; no validated algorithm reconstruction |
| Nuitka standalone | 4/4 | Names/diagnostics/resources remained; native core not reconstructed |

The reconstruction used release disassembly and its model JSON, without importing
or invoking the protected algorithm. One rewrite served pyc and PyInstaller; they
were not two independent recoveries. The analyst knew the design. Release-only
command inputs do not establish blindness. The 256 fixed-seed random inputs and
nine boundary/error inputs establish only the tested domain.

AES wrong-key, changed header/tag and truncation tests rejected the program before
target output. This verifies authentication behavior, not secrecy against the
holder of the client and key. No cryptanalytic break of AES-GCM is claimed.

PyArmor code-object serialization caused Windows 0xc0000005 in an exploratory
run. Its failure was retained; metadata-only capture then completed. No runtime
or license patch was used; commercial modes were not tested.

REA's configured IDA provider inspected the final Nuitka EXE
`3bcd02972d7b65710cf0adc1e62f939265692837b37e5da397aa4c471db5227c`.
It observed `MeridianMixer` strings and decompiled runtime initialization at
`0x140001000`, not the core transform. Provider body-range, CFG and reference
limitations remained. The Evidence bundle was retained privately and the owned
session closed. Each profile had at most a 15-minute analysis allowance; work
stopped after the documented observations. No incomplete recovery is treated as
proof that the profile cannot be cracked.

## Local Cost

Each mode had one first recorded startup, three warmups and eleven measured
subprocesses, processing 4096 integers. Values are medians in milliseconds.

| Profile | Package bytes | Build s | First recorded wall ms | Repeated wall ms | Request internal ms | Core transform ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Source | 2,530 | 0.004 | 63.527 | 64.193 | 2.464 | 1.190 |
| pyc | 5,941 | 0.014 | 81.829 | 64.642 | 2.840 | 1.154 |
| AES | 4,571 | 0.006 | 112.117 | 116.102 | 1.762 | 1.163 |
| PyInstaller | 8,621,633 | 5.987 | 530.747 | 521.872 | 2.078 | 1.163 |
| PyArmor | 669,615 | 0.255 | 82.059 | 72.584 | 4.913 | 3.534 |
| Nuitka | 13,669,001 | 8.417 | 31.263 | 33.226 | 1.718 | 1.066 |

Core transform excludes resource reads and the plugin; request time includes
both, but startup/decryption are outside it. PyInstaller onefile extraction is
included in wall time. Raw samples and min/max are retained. These runs did not
flush OS or compiler caches, did not randomize profile order and do not isolate
incremental cryptographic overhead. No business performance gate was chosen.

Package bytes are not total deployment costs: source, pyc, AES and PyArmor require
external Python; AES also needs cryptography. PyInstaller and Nuitka bundle
runtime components. Builds used retained compiler caches, so their times are
not cold-build benchmarks. Do not extrapolate this small workload to an application.

## Evidence Revisions

Private runs are retained under `F:/tmp/anti-rea-python`:

- r001: compiler succeeded, missing lld-link prevented linking.
- r002: six behavior profiles passed; exploratory PyArmor serialization crashed.
- r003/r004: bounded observations and initial reconstruction checks.
- r005: final core timing, six profiles, 265 cases per profile, four AES rejection scenarios and three reconstruction checks; final scanner reports are in `analysis-complete` (earlier analysis revisions retained).

The standalone audit also tests traversal/duplicate/symlink rejection, bounded
decompression, pyc non-execution, mismatched magic, baseline mismatch, report
escaping and explicit runtime-execution opt-in. Reports/captures, private test
inputs, keys and decrypted output are excluded from Git and skill downloads.
Windows acceptance was local; the repository's manually disabled Windows workflow
was left unchanged.
