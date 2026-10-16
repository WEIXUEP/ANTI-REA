"""Generate example-compatible private recovery keys; never overwrite a file."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def generate_keys(path):
    from nacl.public import PrivateKey

    path = Path(path).expanduser().absolute()
    key = PrivateKey.generate()
    public = bytes(key.public_key).hex()
    value = {
        "schema": 1,
        "master": os.urandom(32).hex(),
        "public": public,
        "private": bytes(key).hex(),
        "warning": "PRIVATE DEVELOPMENT KEYS - DO NOT DISTRIBUTE",
    }
    content = json.dumps(value, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation rejects existing files, including dangling symlinks.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return {"key_id": hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16],
            "path": str(path)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path,
                        help="Developer-only destination; existing files are rejected")
    args = parser.parse_args(argv)
    try:
        result = generate_keys(args.out)
    except ImportError:
        print("Error: PyNaCl is required; install it in the selected Python environment.",
              file=sys.stderr)
        return 2
    except FileExistsError:
        print("Error: Destination exists; refusing overwrite or silent key rotation.",
              file=sys.stderr)
        return 2
    except OSError:
        print("Error: Cannot create or persist the key file; check destination permissions "
              "and storage. Do not use a partially written file.", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
