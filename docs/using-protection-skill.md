# Code Protection Skill

English | [简体中文](using-protection-skill.zh-CN.md)

`cpp-code-protection` guides scoped C++ protection implementation, key lifecycle,
offline recovery and workload measurements. It is separate from the read-only
[leakage detection skill](audit-skill.md) and does not bundle a scanner.

## Install and Capabilities

[Download cpp-code-protection](downloads/cpp-code-protection.zip) and extract its
directory into your agent's skill directory, or copy `skills/cpp-code-protection`.
Python 3.10+ runs the independent helpers; PyNaCl enables compatible key generation
and sealed-event recovery. No example checkout is required.

| Capability | Entry point |
| --- | --- |
| Dependency and LLVM/xollvm inventory | `scripts/doctor.py` |
| Generate fresh private recovery material | `scripts/generate_keys.py` |
| Recover supported diagnostics, locations and RTTI | `scripts/decode.py` |
| Measure trusted arbitrary target workloads | `scripts/measure.py` |
| Integrate C++ protection and selective obfuscation | Agent-guided target changes using the integration references |
| Mask selected policy constants and test the tradeoff | [Runtime constants workflow](protection-skill/references/runtime-constants.md); demo generation requires a source checkout |
| Design a decoder GUI | Guidance for an optional frontend over the shared backend; no GUI bundled |

```bash
python <skill-directory>/scripts/doctor.py
python <skill-directory>/scripts/generate_keys.py --out /private/r17/keys.json
python <skill-directory>/scripts/decode.py --build /private/r17/build \
  --keys /private/r17/keys.json --report warning.log
python <skill-directory>/scripts/decode.py --build /private/r17/build --list-maps
python <skill-directory>/scripts/measure.py --config workloads.json \
  --samples 9 --warmups 2 --out /private/reports/workloads
```

The generator/decoder support the documented example schema, not arbitrary
products. Original-name maps are not encrypted payloads; successful map lookup
is not decryption. The runtime carries only the diagnostic public sealing key.
Keep private keys, naming material, maps, IR and debug files outside deployment.

## Agent Requests

```text
Use $cpp-code-protection to plan protection for this C++ engine. Do not edit yet.
Preserve public ABI, exceptions and RTTI behavior. Identify central diagnostics,
target/consumer coverage, key storage and acceptance tests.
```

```text
Use $cpp-code-protection to implement the approved first-party scope.
Enable release stripping and baseline diagnostic/location/RTTI protection.
Select extra obfuscation by function value and measured performance budget;
leave numerical hotspots unchanged. Rebuild, test recovery and re-inspect a
fresh installed package using the original sensitive corpus.
```

Implementation requires user authorization. Design-only work does not authorize
key generation or builds. Existing native/target audit tools can provide baseline
and final evidence, so the detection skill is optional.

## Selected Constants and Windows Acceptance

The skill now includes the [checked constants workflow](protection-skill/references/runtime-constants.md):
the `ANTI_REA_CONSTANT_PROTECTION` switch, private maps, native Windows validator
commands using LLVM 23/Intel oneAPI, matched masking-OFF/ON controls, and
independent measurement manifests. Demo generation and native acceptance require
the source checkout; the downloaded skill still measures existing trusted targets
independently. `decode.py` does not load the numeric constant map.

```text
Use $cpp-code-protection on this owned Windows demo. Preserve an original baseline.
Mask only the selected policy constants. Validate Debug/Release behavior, RTTI/EH,
DLL identity, production linker options, relocation and complete key rotation.
Measure masking OFF/ON at the same transform level with the same key and settings.
Report direct-byte hiding, recoverability and the agreed runtime/size budgets separately.
```

The tested demo hid five direct signatures while all five values remained
recoverable from adjacent XOR shares. NONE masking added 2.36% loop time;
MIXED_VM masking added 54.93% against its matched control, failing the 1.5x limit.
These are demo measurements, not a default performance promise. See the
[fresh-build evidence](reference-improvements.md#fresh-build-acceptance).

## Canonical Instructions

The optional [name-style workflow](name-styles.md) adds common-code function/type
aliases with private maps. Opaque mode remains the default. Windows can retain
selected EXE aliases as exports, exposing additional addresses; this is OFF by
default. See the [checked skill workflow](protection-skill/references/name-styles.md).
No model-misclassification result is claimed.

The [runtime-resource reference](protection-skill/references/runtime-resources.md)
adds opt-in design guidance for AES-GCM bundles, in-memory consumption and
persistent derived-result caches. Embedded keys remain recoverable. It requires
an original-program baseline and separate target acceptance; the skill includes
no resource packer, resource-key generator or cache runtime. Documentation and
ZIP checks do not establish working resource encryption or caching.

- [Skill instructions](protection-skill/index.md)
- [Independent operations](protection-skill/references/operations.md)
- [Integration contract](protection-skill/references/integration.md)
- [Remediation and function-selection policy](protection-skill/references/remediation.md)
- [Runtime constants, controls and native acceptance](protection-skill/references/runtime-constants.md)
- [Encrypted runtime resources and cache design](protection-skill/references/runtime-resources.md)
- [Key generation and lifecycle](protection-skill/references/key-management.md)
- [Offline recovery and GUI design](protection-skill/references/recovery-tools.md)
- [Validation](protection-skill/references/validation.md)
- [Windows runtime acceptance](protection-skill/references/windows.md)

The archive is explicitly allowlisted and tested outside the checkout.
Encryption, opaque naming, stripping and obfuscation address different channels;
none guarantees that native code cannot be reverse engineered.
