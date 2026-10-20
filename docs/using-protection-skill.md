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

## Canonical Instructions

- [Skill instructions](protection-skill/index.md)
- [Independent operations](protection-skill/references/operations.md)
- [Integration contract](protection-skill/references/integration.md)
- [Remediation and function-selection policy](protection-skill/references/remediation.md)
- [Key generation and lifecycle](protection-skill/references/key-management.md)
- [Offline recovery and GUI design](protection-skill/references/recovery-tools.md)
- [Validation](protection-skill/references/validation.md)
- [Windows runtime acceptance](protection-skill/references/windows.md)

The archive is explicitly allowlisted and tested outside the checkout.
Encryption, opaque naming, stripping and obfuscation address different channels;
none guarantees that native code cannot be reverse engineered.
