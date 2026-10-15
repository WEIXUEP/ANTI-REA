# Threat Model

## Objective

Reduce the information available through ordinary native-binary string searches,
symbol inspection and program diagnostics, while keeping a useful developer
recovery path. The acceptance target is the installed release executable and
example shared library, not a developer's entire build directory.

The observer has the EXE/DLL or ELF files and can run them, search printable
strings, inspect exports, open a disassembler and read output. Stronger observers
can trace execution, patch instructions and inspect memory; those capabilities
are not defeated by these techniques.

## Four Separate Mechanisms

1. **Sealed diagnostics.** Message templates are encrypted before compilation with
   a public key. The runtime receives no private decryption key. Dynamic fields are
   sealed when an event occurs. Offline tools use a private key and a release map.
2. **Opaque identifiers.** HMAC-derived RTTI and source-location identifiers reduce
   semantic labels. Their purpose is not to make code or layout mathematically
   secret. Stable IDs also reveal equality across builds using the same key.
3. **Release hygiene.** Visibility, export policy, debug separation, source metadata
   handling and symbol stripping remove information unnecessary for execution.
4. **Obfuscation.** xollvm changes selected expressions, control flow, constants or
   interpreter structure. It increases analysis effort but is not a security
   boundary. Runtime-decrypted strings can be read from memory.

## Important Limits

- Public demo keys provide no confidentiality. Generating a private key is necessary
  for real diagnostic secrecy, but cannot hide observable algorithm behavior.
- Sealed boxes provide confidentiality and ciphertext integrity, not sender identity.
  Anyone holding the public key can generate a plausible encrypted message.
- A debugger can observe warning arguments before encryption. The sender owns them.
- Public C exports, standard-library imports, loader names and public resource
  content remain discoverable by design.
- RTTI structure, inheritance relationships and vtables remain. Opaque names do not
  hide object layout, dispatch targets or exception mechanics.
- Public-symbol names cannot be removed indiscriminately without breaking linking.
- Third-party diagnostic text and runtime assertions need separate ownership-aware
  treatment. This project does not promise whole-program string removal.
- Native values are not made secret by deleting a source variable's name.
- Path-shaped random bytes can produce scanner false positives. Conversely, an
  encoded, compressed or split string can evade a plaintext search.

Do not publish PDBs, private IR, maps, keys or raw debug artifacts. Windows ACLs and
artifact-store permissions must be managed by the developer; Python chmod alone
does not establish a Windows security boundary.

## Why Not Rewrite Every Binary String?

Arbitrary post-link replacement can corrupt relocations, RTTI layouts, exception
records, string lengths, checksums and digital signatures. Equal-length replacement
still does not establish semantic safety. The example transforms well-defined
compiler records or eliminates sensitive input before object generation, then
validates program behavior. It does not offer a universal EXE patcher.
