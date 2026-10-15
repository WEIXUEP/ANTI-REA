# ANTI-REA

Technical documentation for a runnable C++ information-leakage laboratory.
Build the example, inspect its release artifacts, apply targeted protections,
and compare the results using reproducible tools.

!!! warning "Protection has limits"
    Diagnostic confidentiality, opaque RTTI names, symbol stripping and
    obfuscation address different information channels. None makes a native
    program impossible to reverse engineer. The checked-in example keys are
    public teaching material, not production secrets.

## Start Here

| Goal | Read |
| --- | --- |
| Build and run the C++ example | [Quickstart](quickstart.md) |
| Understand what each protection addresses | [Threat model](threat-model.md) and [scenario catalog](scenarios.md) |
| Recover an encrypted warning | [Diagnostics and recovery](diagnostics.md) |
| Compare baseline, stripped and protected releases | [Measurement tools](measurement.md) |
| Audit another C++ project | [Using the audit skill](audit-skill.md) |
| Publish this documentation | [GitHub Pages setup](github-pages.md) |

## Default Policy

Fresh configurations enable both `ANTI_REA_CODE_PROTECTION=ON` and
`ANTI_REA_STRIP_RELEASE=ON`. These protect diagnostic templates, source locations,
internal RTTI names and release metadata, while keeping private recovery material
outside the installed package.

`ANTI_REA_OBFUSCATION=NONE` is the default. Choose function-level obfuscation or
virtualization using implementation value, call frequency and performance
requirements. Do not apply the most expensive preset to every function.
The baseline and stripped-only presets deliberately disable information
protection to provide useful experimental controls.

## Implementation and Evidence

The example contains an executable and a shared library, with runtime checks for
cross-library RTTI, exceptions, condition evaluation and relocated resource
loading. Python handles build-time generation, LLVM IR transformation, audits and
offline decoding; CMake controls builds and installation.

Linux results are [measured, not simulated](comparison.md). Native Windows
instructions and CI are provided, but Linux success is not native Windows
acceptance. Review [remaining exposure](remaining-exposure.md) before interpreting
a zero sensitive-text match count.
