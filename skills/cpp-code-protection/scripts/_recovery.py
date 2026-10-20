"""Bounded, offline recovery for the example's version-1 diagnostic/RTTI maps."""

import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import string

MAX_INPUT = 8 * 1024 * 1024
MAX_MAP = 16 * 1024 * 1024
TOKEN = re.compile(r"(?<![\w])AR\d+:[^:\s]+:[^\s]+")
RTTI = re.compile(r"(?<![\w])(?:\*?65R[a-f0-9]{64}|\.\?AVR_[a-f0-9]{64}@@)(?![\w])")


class RecoveryError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def read_json(path, limit=MAX_MAP):
    path = Path(path)
    if path.stat().st_size > limit:
        raise RecoveryError("input_too_large")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise RecoveryError("input_too_large")
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeError):
        raise RecoveryError("invalid_json") from None
    if not isinstance(value, dict):
        raise RecoveryError("invalid_schema")
    return value


def load_key(path):
    from nacl.public import PrivateKey

    value = read_json(path, 65536)
    try:
        if value["schema"] != 1:
            raise ValueError()
        for name in ("master", "public", "private"):
            if len(bytes.fromhex(value[name])) != 32:
                raise ValueError()
        key = PrivateKey(bytes.fromhex(value["private"]))
        if bytes(key.public_key).hex() != value["public"].lower():
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise RecoveryError("invalid_key") from None
    return value


def identity(key):
    return hashlib.sha256(bytes.fromhex(key["public"])).hexdigest()[:16]


def load_maps(build=None, maps=()):
    selected = []
    if build is not None:
        root = Path(build)
        selected.append(root / "private/diagnostics.json")
        selected.extend(sorted((root / "private/maps").glob("*.json")))
    for item in maps:
        path = Path(item)
        if path.is_dir():
            selected.extend(sorted(path.glob("*.json")))
        else:
            selected.append(path)
    selected = sorted({path.resolve() for path in selected})
    if not selected:
        raise RecoveryError("no_maps_selected")
    if len(selected) > 1024:
        raise RecoveryError("too_many_maps")
    books, inventory, sites = [], [], {}
    total_bytes = 0
    for path in selected:
        total_bytes += path.stat().st_size
        if total_bytes > 64 * 1024 * 1024:
            raise RecoveryError("maps_too_large")
        book = read_json(path)
        if book.get("schema") != 1:
            raise RecoveryError("unsupported_map_version")
        if "sites" in book:
            if not isinstance(book["sites"], dict) or not all(isinstance(book.get(name), str) for name in ("key_id", "master_id")):
                raise RecoveryError("invalid_location_map")
            for code, entry in book["sites"].items():
                if (not isinstance(entry, dict) or not isinstance(entry.get("message"), str)
                        or not isinstance(entry.get("path"), str) or type(entry.get("line")) is not int
                        or entry["line"] < 1):
                    raise RecoveryError("invalid_location_record")
                marker = book["key_id"], book["master_id"], code
                if marker in sites and sites[marker] != entry:
                    raise RecoveryError("conflicting_location_maps")
                sites[marker] = entry
            kind, count = "diagnostics", len(book["sites"])
        elif "rtti" in book:
            if not isinstance(book["rtti"], list):
                raise RecoveryError("invalid_rtti_map")
            for row in book["rtti"]:
                if (not isinstance(row, dict) or row.get("abi") not in {"itanium", "msvc"}
                        or not all(isinstance(row.get(name), str) for name in ("original", "opaque", "decoded"))
                        or type(row.get("protected")) is not bool):
                    raise RecoveryError("invalid_rtti_record")
            kind, count = "rtti", sum(row["protected"] for row in book["rtti"])
        else:
            raise RecoveryError("unsupported_map_format")
        books.append((path, book))
        inventory.append(dict(path=str(path), kind=kind, schema=book["schema"], records=count,
                              key_id=book.get("key_id"), abi=book.get("abi")))
    return books, inventory


def open_sealed(key, ciphertext):
    from nacl.exceptions import CryptoError
    from nacl.public import PrivateKey, SealedBox

    try:
        raw = base64.b64decode(ciphertext, validate=True)
        text = SealedBox(PrivateKey(bytes.fromhex(key["private"]))).decrypt(raw)
        return text.decode("utf-8")
    except (CryptoError, ValueError, UnicodeError):
        raise RecoveryError("ciphertext_rejected") from None


def decode_token(token, key, books):
    if key is None:
        raise RecoveryError("private_key_required")
    parts = token.split(":", 2)
    if len(parts) != 3 or parts[0] != "AR1":
        raise RecoveryError("unsupported_payload_version")
    if parts[1] != identity(key):
        raise RecoveryError("payload_key_mismatch")
    try:
        body = json.loads(open_sealed(key, parts[2]))
    except json.JSONDecodeError:
        raise RecoveryError("invalid_payload_json") from None
    if not isinstance(body, dict) or body.get("schema") != 1:
        raise RecoveryError("unsupported_payload_schema")
    if (not isinstance(body.get("id"), str) or not isinstance(body.get("template"), str)
            or not isinstance(body.get("fields"), list) or len(body["fields"]) > 4096
            or not all(isinstance(field, str) for field in body["fields"])):
        raise RecoveryError("invalid_payload_fields")
    template = open_sealed(key, body["template"])
    master_id = hmac.new(bytes.fromhex(key["master"]), b"master-id\0v1", hashlib.sha256).hexdigest()[:32]
    matches = [(path, book["sites"][body["id"]]) for path, book in books
               if "sites" in book and book["key_id"] == parts[1]
               and book["master_id"] == master_id and body["id"] in book["sites"]]
    if not matches:
        raise RecoveryError("matching_location_not_found")
    if any(row != matches[0][1] for _, row in matches):
        raise RecoveryError("ambiguous_location")
    row = matches[0][1]
    if template != row["message"]:
        raise RecoveryError("template_location_mismatch")
    # The supported producer has positional {} fields, not executable templates.
    try:
        placeholders = list(string.Formatter().parse(template))
        fields = [field for _, field, _, _ in placeholders if field is not None]
        if any(field != "" or spec or conversion for _, field, spec, conversion in placeholders if field is not None):
            raise ValueError()
        if len(fields) != len(body["fields"]):
            raise ValueError()
        message = template.format(*body["fields"])
    except (ValueError, IndexError, KeyError):
        raise RecoveryError("unsupported_template_grammar") from None
    if len(message) > MAX_INPUT:
        raise RecoveryError("output_too_large")
    return dict(kind="diagnostic", id=body["id"], message=message, fields=body["fields"],
                path=row["path"], line=row["line"], site=row.get("site"), key_id=parts[1],
                maps=[str(path) for path, _ in matches])


def aliases(name):
    normalized = name.lstrip("*")
    return {name, normalized, normalized.removeprefix("65"),
            normalized.removeprefix(".?AV").removesuffix("@@")}


def decode_rtti(query, books):
    query = query.removeprefix("class ").removeprefix("struct ").strip()
    matches = [(path, row) for path, book in books for row in book.get("rtti", [])
               if row["protected"] and query in aliases(row["opaque"])]
    if not matches:
        raise RecoveryError("rtti_not_found")
    unique = {(row["abi"], row["original"], row["decoded"]) for _, row in matches}
    if len(unique) != 1:
        raise RecoveryError("ambiguous_rtti")
    return dict(kind="rtti", **matches[0][1], maps=[str(path) for path, _ in matches])


def decode_text(text, key, books, rtti=False):
    if len(text.encode("utf-8")) > MAX_INPUT:
        raise RecoveryError("input_too_large")
    events = [(0, text, True)] if rtti else sorted(
        [(match.start(), match[0], False) for match in TOKEN.finditer(text)]
        + [(match.start(), match[0], True) for match in RTTI.finditer(text)])
    if not events:
        raise RecoveryError("no_supported_events")
    if len(events) > 4096:
        raise RecoveryError("too_many_events")
    results = []
    for offset, value, is_rtti in events:
        try:
            recovered = decode_rtti(value, books) if is_rtti else decode_token(value, key, books)
            results.append(dict(index=len(results), offset=offset, status="recovered", **recovered))
        except RecoveryError as error:
            results.append(dict(index=len(results), offset=offset, status="failed", code=error.code))
    return results
