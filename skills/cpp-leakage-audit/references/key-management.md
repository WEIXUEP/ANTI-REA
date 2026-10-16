# Key Generation and Lifecycle Rules

Read this for authorized key setup, build provisioning or rotation. An audit
does not authorize creating keys, changing the active release identity or
modifying another project's credential storage. Do not regenerate a key merely
because an existing key is missing or a report fails to decode.

## Separate Key Roles

| Material | Role | Where it belongs |
| --- | --- | --- |
| Diagnostic public sealing key | Encrypt templates and runtime diagnostic fields | Build generator and shipped reporter |
| Diagnostic private key | Recover sealed diagnostics offline | Restricted developer/recovery environment only |
| Naming master or derived naming keys | Generate stable opaque RTTI, file and line identifiers | Authorized build tools only |
| Public key fingerprint/key ID | Select compatible recovery material | Logs, release manifest, maps and decoder UI |
| Original-name/location maps | Resolve opaque identifiers to source data | Restricted release archive and recovery environment |

The private decryption key must not be a compiler definition or a C++ runtime
constant. The naming master is also secret, but serves a different purpose from
the decryption key. Share compatible naming material across related compilation
units and libraries; use separate domains for RTTI, file, line and other IDs.
Do not reuse raw key bytes for unrelated encryption, signing and naming roles.

Opaque HMAC identifiers are not reversible encryption. Recovery normally needs
the matching original-name map; a private sealing key alone cannot restore them.
An identifier's stability depends on the naming key, canonical input, ABI and
algorithm version, not just keeping a file at the same path.

## Available Generation Commands

From the example project checkout, the existing command is:

```bash
python tools/anti_rea.py keys --out .private/releases/r17/keys.json
```

The downloaded skill also contains a standalone generator with the same version-1
key schema. It does not require the example project checkout:

```bash
# Install only in the Python environment selected for this task.
python -m pip install PyNaCl
python <skill-directory>/scripts/generate_keys.py --out /private/releases/r17/keys.json
```

Choose a real developer-only destination for the placeholder path. The helper
uses PyNaCl's Curve25519 private-key generator and an independent 32-byte
OS-random naming master. The JSON fields are `schema`, `master`, `public`,
`private` and a private-material warning. Its stdout contains only the resolved
destination and a public-key fingerprint, not secret key values. Existing files
and symlinks are rejected through exclusive creation; there is no force flag.

This file is a plaintext secret bundle, not a password-encrypted keystore. Treat
it accordingly. The helper requests mode `0600` at file creation on POSIX;
Windows protection depends on destination ACLs and must be verified separately.
Parent directory permissions also matter. A failed write may leave an incomplete
file; do not consume it or silently replace it. Inspect the failure and select a
new destination or explicitly authorize cleanup.

This is a specific supported schema, not a universal key importer. Before
adapting it elsewhere, inspect that producer's algorithm, key lengths, encoding,
derivation domains and IDs. Do not copy the example schema into an incompatible
tool or automatically convert existing production keys.

## Provisioning and Build Rules

1. Identify the authorized output path, expected format and release identity.
   Reuse an existing compatible key when stable names are required. Check
   ignore rules and access controls before writing inside a source checkout.
2. Generate new secrets with an OS-backed cryptographic generator or maintained
   library. Do not derive production keys from a timestamp, hostname, path,
   repository commit, user-chosen short password or deterministic demo seed.
3. Validate lengths, encoding, schema and private/public correspondence. Confirm
   a synthetic seal/open round trip and compute a public fingerprint without
   printing private material. Reject unknown versions and malformed bundles.
4. Explicitly configure the build with the selected key file. The example
   project's CMake input is `ANTI_REA_KEYS`; inspect another target's actual
   option rather than inventing a common name. Avoid secret values in command
   lines, CMake caches, environment dumps and generated headers.
5. Give the runtime only the public sealing material. Build-only naming exports
   and generated original-name maps remain private. Archive the effective key
   identity, naming algorithm/version, ABI and maps with the matching release.
6. Decode a report from that actual protected release and scan its fresh install
   package for private keys, maps, IR and debug artifacts before distribution.

Automatic reuse is appropriate when a compatible key is explicitly configured.
Automatic creation is appropriate only for a documented, authorized initialization
workflow with exclusive creation and visible status. A normal production build
should fail on a missing/mismatched key rather than invent a new one or fall back
to a public demo key. The example project's public teaching defaults are not a
production policy.

Keep production secrets out of version control, documentation, skill downloads,
CI logs and ordinary build artifacts. An ignore rule does not remove already
tracked secrets or history. If a key was committed, treat it as exposed and plan
rotation; do not claim deleting the current file restores secrecy. Public demo
keys are the deliberate exception: label them **PUBLIC DEMO KEYS - NOT SECRET**
and never reuse them for confidential data.

## Rotation, Backups and Recovery UI

Rotate into a new release namespace rather than overwrite the old file. Retain
old recovery material under appropriate access controls for the required support
period. Verify backups by restoring into an isolated environment and recovering
a synthetic archived event, not merely checking that files exist.

A sealing-key change requires regenerating templates and updating runtime public
keys. A naming-key change requires rebuilding all affected producers/consumers
and regenerating their maps consistently. A full protected rebuild is a safe
default when both roles share one bundle. Do not mix old objects, DLLs and new
maps and then assert identity stability. Record which role changed: the short
public-key fingerprint alone does not identify the naming master.

For a new key-management GUI, provide a deliberate Generate action and explicit
destination separate from Decode. Show algorithm/version, public fingerprint,
destination and validation status, never private bytes by default. Confirm a
rotation choice without implying that it can recover old reports. Do not create
keys simply by opening a decoder or clicking Reload. Headless generation should
return stable nonzero failures without tracebacks containing secret values.
Follow [recovery-tools.md](recovery-tools.md) for loading and decode UI behavior.

No tool can recover a genuinely lost private key from its public key. Losing the
only original-name map may also prevent source lookup even when decryption still
works. Explain these distinct failure modes before enabling protection.

## Acceptance Checks

- Generate two independent bundles and confirm both public keys and naming
  masters differ; verify compatibility with the intended producer and decoder.
- Validate round-trip sealing, wrong-key rejection and separate naming domains.
- Refuse existing files, dangling symlinks and concurrent same-path creation
  without changing the existing contents. Report permission/storage errors.
- Confirm stdout/stderr and normal GUI status never contain private key bytes.
- Verify POSIX file permissions or Windows ACLs on the actual environment;
  do not infer Windows ACL safety from a Linux mode check.
- Reuse a key across clean builds for stable IDs; change the appropriate key
  role and confirm that old reports still recover using archived material.
- Inspect version control and the installed package for unintended secrets.

Use temporary synthetic keys for tests, not production secrets. State separately
which checks ran, which are design requirements and which need platform access.
