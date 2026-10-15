"""Sealed diagnostics, stable opaque identifiers, and developer-only recovery."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile


def write_private(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing to replace a symbolic link")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".private-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_keys(path):
    from nacl.public import PrivateKey
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("schema") != 1:
        raise ValueError("Unsupported key schema")
    for field in ("master", "public"):
        if len(bytes.fromhex(value[field])) != 32:
            raise ValueError("Invalid key length")
    if "private" in value:
        if bytes(PrivateKey(bytes.fromhex(value["private"])).public_key).hex() != value["public"]:
            raise ValueError("Private/public key mismatch")
    return value


def key_id(public):
    return hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16]


def opaque(master, domain, text, length=32):
    return hmac.new(bytes.fromhex(master), (domain + "\0" + text).encode(), hashlib.sha256).hexdigest()[:length]


def seal(public, text):
    from nacl.public import PublicKey, SealedBox
    return base64.b64encode(SealedBox(PublicKey(bytes.fromhex(public))).encrypt(text.encode())).decode()


def open_sealed(private, text):
    from nacl.public import PrivateKey, SealedBox
    return SealedBox(PrivateKey(bytes.fromhex(private))).decrypt(base64.b64decode(text, validate=True)).decode()


def generate_keys(path):
    from nacl.public import PrivateKey
    path = Path(path)
    if path.exists():
        raise ValueError("Key file already exists; refusing silent rotation")
    key = PrivateKey.generate()
    value = dict(schema=1, master=os.urandom(32).hex(), public=bytes(key.public_key).hex(),
                 private=bytes(key).hex(), warning="PRIVATE DEVELOPMENT KEYS - DO NOT DISTRIBUTE")
    # Exclusive creation avoids overwriting a concurrent key generator.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    return dict(key_id=key_id(value["public"]), path=str(path))


def decode(token, keys, build):
    if "private" not in keys:
        raise ValueError("Offline recovery requires a private key")
    prefix, identity, ciphertext = token.removeprefix("Payload: ").strip().split(":", 2)
    if prefix != "AR1" or identity != key_id(keys["public"]):
        raise ValueError("Payload key ID mismatch")
    body = json.loads(open_sealed(keys["private"], ciphertext))
    if body.get("schema") != 1:
        raise ValueError("Unsupported payload schema")
    template = open_sealed(keys["private"], body["template"])
    mapping = json.loads((Path(build) / "private/diagnostics.json").read_text())
    if mapping["key_id"] != identity or mapping["master_id"] != opaque(keys["master"], "master-id", "v1"):
        raise ValueError("Build map key mismatch")
    location = mapping["sites"][body["id"]]
    if location["message"] != template:
        raise ValueError("Payload template does not match its diagnostic site")
    return {**location, "id": body["id"], "message": template.format(*body["fields"])}
