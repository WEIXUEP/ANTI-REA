"""Bounded static ZIP/PyInstaller extraction. Never imports target modules."""
import argparse
import hashlib
import importlib.util
import io
import json
import marshal
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import zipfile
import zlib

MAX_MEMBER = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILES = 4096
COOKIE = b"MEI\014\013\012\013\016"


def safe_name(name):
    name = name.replace("\\", "/")
    parts = PurePosixPath(name).parts
    if (not parts or name.startswith("/") or len(name) > 1024
            or any(p in {"..", "."} or any(ord(c) < 32 or c in '<>:"|?*' for c in p) for p in parts)
            or any(p.endswith((".", " ")) for p in parts)
            or any(p.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(10)],
                                              *[f"LPT{i}" for i in range(10)]} for p in parts)):
        raise ValueError("unsafe archive member: " + repr(name))
    return PurePosixPath(*parts).as_posix()


def inflate(data, limit=MAX_MEMBER):
    decoder = zlib.decompressobj()
    value = decoder.decompress(data, limit + 1)
    if len(value) > limit or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("invalid or oversized compressed member")
    return value


def entries(data):
    if data.startswith(b"PYZ\0"):
        if data[4:8] != importlib.util.MAGIC_NUMBER:
            raise ValueError("PYZ Python magic differs from this interpreter")
        toc_offset = struct.unpack("!I", data[8:12])[0]
        if not 12 <= toc_offset <= len(data) or len(data) - toc_offset > 4 * 1024 * 1024:
            raise ValueError("invalid PYZ TOC")
        toc = marshal.loads(data[toc_offset:])
        if not isinstance(toc, (dict, list, tuple)) or len(toc) > MAX_FILES:
            raise ValueError("invalid PYZ entries")
        pairs = toc.items() if isinstance(toc, dict) else toc
        for name, (kind, offset, size) in pairs:
            if not isinstance(name, str) or not 12 <= offset <= offset + size <= toc_offset:
                raise ValueError("invalid PYZ member bounds")
            clear = inflate(data[offset:offset + size])
            if kind in (0, 1):
                suffix = "/__init__.pyc" if kind == 1 else ".pyc"
                yield name.replace(".", "/") + suffix, importlib.util.MAGIC_NUMBER + bytes(12) + clear
            elif kind == 2:
                yield name, clear
        return
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_FILES:
                raise ValueError("too many archive members")
            for info in infos:
                safe_name(info.filename)
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise ValueError("archive symlink rejected")
                if info.is_dir():
                    continue
                if info.file_size > MAX_MEMBER:
                    raise ValueError("oversized archive member")
                with archive.open(info) as stream:
                    body = stream.read(MAX_MEMBER + 1)
                if len(body) > MAX_MEMBER:
                    raise ValueError("oversized archive member")
                yield info.filename, body
        return
    cookie = data.rfind(COOKIE)
    if cookie < 0 or cookie + 88 > len(data):
        raise ValueError("not a supported archive")
    magic, length, offset, size, version, library = struct.unpack("!8sIIII64s", data[cookie:cookie + 88])
    start = cookie + 88 - length
    if start < 0 or not 0 <= offset <= offset + size <= length - 88 or size > 4 * 1024 * 1024:
        raise ValueError("invalid CArchive TOC bounds")
    cursor, end, count = start + offset, start + offset + size, 0
    while cursor < end:
        if cursor + 18 > end:
            raise ValueError("truncated CArchive entry")
        entry_size, position, compressed, uncompressed, flag, kind = struct.unpack("!IIIIBc", data[cursor:cursor + 18])
        if entry_size < 19 or cursor + entry_size > end or position + compressed > offset:
            raise ValueError("invalid CArchive entry bounds")
        if uncompressed > MAX_MEMBER:
            raise ValueError("oversized CArchive member")
        name = data[cursor + 18:cursor + entry_size].rstrip(b"\0").decode("utf-8")
        count += 1
        if count > MAX_FILES or flag not in (0, 1):
            raise ValueError("invalid CArchive entry")
        body = data[start + position:start + position + compressed]
        body = inflate(body) if flag else body
        if len(body) != uncompressed:
            raise ValueError("CArchive size mismatch")
        if kind in {b"s", b"m", b"M"}:
            if version != sys.version_info.major * 100 + sys.version_info.minor:
                raise ValueError("CArchive Python version differs")
            name += ".pyc"
            body = importlib.util.MAGIC_NUMBER + bytes(12) + body
        if kind == b"n":
            raise ValueError("CArchive symlink rejected")
        if kind not in {b"o", b"d"}:
            yield name, body
        cursor += entry_size


def extract(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if source.stat().st_size > MAX_TOTAL:
        raise ValueError("archive exceeds input limit")
    if destination.exists():
        raise ValueError("output must be a new directory")
    # Validate all names and budgets before publishing any member.
    material, seen, total = [], set(), 0
    for name, body in entries(source.read_bytes()):
        name = safe_name(name)
        if name.casefold() == ".extraction-manifest.json":
            raise ValueError("reserved extraction metadata name")
        if name.casefold() in seen:
            raise ValueError("duplicate archive member")
        folded = name.casefold()
        if any(folded.startswith(other + "/") or other.startswith(folded + "/") for other in seen):
            raise ValueError("archive file/directory conflict")
        seen.add(name.casefold())
        total += len(body)
        if len(body) > MAX_MEMBER or total > MAX_TOTAL or len(material) >= MAX_FILES:
            raise ValueError("archive extraction budget exceeded")
        material.append((name, body))
    if not material:
        raise ValueError("empty archive")
    destination.mkdir(parents=True)
    for name, body in material:
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as stream:
            stream.write(body)
    (destination / ".extraction-manifest.json").write_text(json.dumps(dict(
        source=str(source), sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        members=[dict(name=n, bytes=len(b), sha256=hashlib.sha256(b).hexdigest()) for n,b in material]), indent=2), encoding="utf-8")
    return {"members": len(material), "bytes": total, "output": str(destination)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(extract(args.input, args.out)))
    except (ValueError, OSError, EOFError, TypeError, struct.error, zipfile.BadZipFile) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
