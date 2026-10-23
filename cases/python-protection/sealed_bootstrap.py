"""Case-only authenticated source loader; the shipped key is recoverable."""
import base64
import importlib.abc
import importlib.util
import io
import json
from pathlib import Path
import runpy
import sys
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER = b"ANTI-REA-PY-AES1\0"


class MemorySources(importlib.abc.SourceLoader, importlib.abc.MetaPathFinder):
    def __init__(self, entries):
        self.entries = entries

    def find_spec(self, fullname, path=None, target=None):
        stem = fullname.replace(".", "/")
        for candidate in (stem + "/__init__.py", stem + ".py"):
            if candidate in self.entries:
                return importlib.util.spec_from_loader(fullname, self,
                                                       is_package=candidate.endswith("/__init__.py"))
        return None

    def get_filename(self, fullname):
        stem = fullname.replace(".", "/")
        candidate = stem + "/__init__.py"
        return "<sealed/" + (candidate if candidate in self.entries else stem + ".py")

    def get_data(self, path):
        name = path.removeprefix("<sealed/").replace("\\", "/")
        if name not in self.entries:
            raise OSError("unknown resource")
        return self.entries[name]


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    envelope = (root / "payload.aes").read_bytes()
    if not envelope.startswith(HEADER) or len(envelope) < len(HEADER) + 28:
        raise ValueError("invalid authenticated envelope")
    key = base64.b64decode(json.loads((root / "runtime.json").read_text())["key"])
    clear = AESGCM(key).decrypt(envelope[len(HEADER):len(HEADER) + 12],
                                envelope[len(HEADER) + 12:], HEADER)
    with zipfile.ZipFile(io.BytesIO(clear)) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    sys.meta_path.insert(0, MemorySources(entries))
    exec(compile(entries["main.py"], "<sealed/main.py", "exec"), {"__name__": "__main__"})
