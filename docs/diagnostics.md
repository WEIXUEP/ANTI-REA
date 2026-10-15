# Diagnostic Confidentiality and Recovery

## Data Flow

```text
Private keys + source catalog                 Developer environment only
                |
                v
Build generator -> sealed C++ header -> compiler -> executable + public key
        |
        +-> private location map                         |
                                                         v
                                       runtime fields -> sealed event -> log
                                                         |
Private key + matching release map -> offline decoder <---+
```

The generator runs during CMake configuration. It reads a small JSON diagnostic
catalog and finds its named call sites. Protected generated headers never contain
the plaintext message templates. This is intentionally simpler than finding and
encrypting arbitrary formatted C++ expressions after compilation.

At runtime the reporter stores the already sealed template, the site ID and
formatted dynamic fields in an envelope. It seals the envelope using libsodium's
`crypto_box_seal`, then prints Base64 ciphertext. Only public severity labels,
opaque location identifiers and payload framing remain plaintext.

The offline decoder first opens the envelope, then opens its embedded template,
checks the key and build map, and substitutes the fields. Sealed boxes are
randomized: identical messages need not produce identical ciphertext. They are
not digital signatures and do not authenticate the sender.

## Example

Ordinary output includes:

```text
Engine warning
Diagnostic ID: E-<stable-site-id>
Internal spectral preconditioner stalled after 37 iterations
File: examples/main.cpp
Line: <source-line>
```

Protected output has this shape; placeholders are not executable test vectors:

```text
Engine warning
Diagnostic ID: E-<stable-site-id>
File: F-<opaque-file-id>
Line: L-<opaque-line-id>
Payload: AR1:<public-key-id>:<randomized-base64-ciphertext>
```

Generate a real token and recover it without manually copying ciphertext:

```bash
python - <<'PY'
from pathlib import Path
import subprocess
program = 'build/protected/bin/anti-rea-demo'
log = subprocess.run([program, 'warning'], capture_output=True, text=True, check=True).stderr
token = next(line.split('Payload: ', 1)[1] for line in log.splitlines() if line.startswith('Payload: '))
subprocess.run(['python', 'tools/anti_rea.py', 'decode', '--build', 'build/protected', '--token', token], check=True)
PY
```

The recovered result includes the original message with `37`, source file, line,
site name and public error kind. Use the build directory recorded in a matrix
result if building through `compare`, rather than `build/protected`.

## Keys and Maps

`demo-keys/keys.json` is deliberately public and contains deterministic teaching
keys. It must never be treated as a production secret. The warning is printed in
the file itself. There is no confidentiality against another repository reader.

`keys --out .private/keys.json` generates a random master key and a separate
Curve25519 keypair. Existing key files are never overwritten. RTTI, file and line
identifiers use separate HMAC domains, not one untyped shared digest space.

The generated `private/compiler-keys.json` contains the public encryption key and
the build-time identifier master, **not** the private decryption key. Neither file
is installed. The identifier master is used by build tools; it is not embedded in
the executable. The C++ runtime only needs public encryption material.

The private directory contains:

| Artifact | Purpose |
| --- | --- |
| `diagnostics.json` | Site-to-source map and original templates |
| `compiler-keys.json` | Build-time naming key and public encryption key |
| `maps/*.json` | Per-object original/opaque RTTI names and obfuscation evidence |
| `ir/*/*.ll` | Private compiler intermediates, including original identifiers |
| `config.json` | Protection and resource configuration |

Site IDs use a logical site name and normalized project-relative source path,
not absolute build paths. They survive unrelated line insertions. Line IDs change
when their source line changes. Moving a site to another file changes its ID.
Treat a catalog name as one logical location; create another entry for another
call site. IDs are opaque keyed identifiers, not independently decryptable line
numbers. Recovery requires the matching map.

Archive keys and maps by release. Changing keys requires rebuilding all related
objects and shared libraries. Old logs require old recovery material. Maps contain
sensitive information even when keys are already stored securely.

## Formatting, Failure and Boundaries

The example catalog supports positional `{}` fields only. C++ formats each field
through a stream; Python substitutes fields when recovering the message. It is
not a drop-in replacement for the complete fmt formatting language. Keep literal
secrets in the catalog, not in a separately formatted string argument.

Encryption failure prints only `Payload: <unavailable>`; there is no plaintext
fallback. Fatal reporting still aborts, and the exception example throws an
opaque diagnostic ID rather than repeating its secret template in `what()`.

Plain baseline diagnostics intentionally retain location expansions. A protected
success path evaluates the verification condition once and does not evaluate
failure-only fields. Source-to-object verification and binary scans complement
runtime checks: merely seeing ciphertext on stderr is insufficient evidence.

This reporter is CPU-only. It makes no async-signal-safety guarantee and does not
implement CUDA device exceptions, MPI communicator routing or thread-safe log
record aggregation. Those integrations need their own semantic tests.
