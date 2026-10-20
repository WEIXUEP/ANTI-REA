"""Generate sealed C++ catalogs before the compiler sees diagnostic templates."""
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
from .crypto import load_keys, key_id, opaque, seal, write_private
from .constants import generate_constants


def enabled(value):
    return str(value).upper() in {"ON", "1", "TRUE", "YES"}


def generate(root, build, key_path, protected, constants=True):
    root, build = Path(root), Path(build)
    keys = load_keys(key_path)
    fingerprint = hashlib.sha256(json.dumps(dict(keys=keys, protected=protected, constants=constants), sort_keys=True).encode())
    for path in [Path(__file__), Path(__file__).with_name("constants.py"), root / "examples/diagnostics.json",
                 root / "examples/policy-constants.json", *sorted((root / "examples").glob("*.cpp"))]:
        fingerprint.update(path.read_bytes())
    fingerprint = fingerprint.hexdigest()
    cache = build / "private/generation.json"
    if (cache.exists() and json.loads(cache.read_text()).get("fingerprint") == fingerprint
            and (build / "generated/diagnostic_catalog.hpp").exists()
            and (build / "generated/policy_constants.hpp").exists()
            and (build / "private/constants.json").exists()
            and (build / "generated/resource-name.txt").exists()):
        return dict(cached=True, protected=protected)
    catalog = json.loads((root / "examples/diagnostics.json").read_text())
    locations = {}
    pattern = re.compile(r"sites::(\w+)|AR_(?:VERIFY|ASSERT)\([^,\n]+,\s*(\w+)")
    for source in sorted((root / "examples").glob("*.cpp")):
        for number, line in enumerate(source.read_text().splitlines(), 1):
            for match in pattern.finditer(line):
                name = match[1] or match[2]
                locations.setdefault(name, (source.relative_to(root).as_posix(), number))
    header = ["#pragma once", "namespace aegis {",
              "struct Site { const char *id; const char *kind; const char *file; const char *line; const char *message; };",
              "namespace sites {"]
    rows = {}
    for name, entry in catalog.items():
        if name not in locations:
            raise ValueError("Diagnostic catalog entry has no call site: " + name)
        path, line = locations[name]
        identity = "E-" + opaque(keys["master"], "diagnostic-v1", path + ":" + name)
        file_id = "F-" + opaque(keys["master"], "file-v1", path)
        line_id = "L-" + opaque(keys["master"], "line-v1", path + ":" + str(line))
        message = seal(keys["public"], entry["message"]) if protected else entry["message"]
        values = [identity, entry["kind"], file_id if protected else path,
                  line_id if protected else str(line), message]
        header.append("inline constexpr Site " + name + "{" + ", ".join(json.dumps(v) for v in values) + "};")
        rows[identity] = dict(site=name, path=path, line=line, file_id=file_id, line_id=line_id, **entry)
    header.extend(["}", "inline constexpr unsigned char public_key[] = {" +
                   ",".join(str(b) for b in bytes.fromhex(keys["public"])) + "};",
                   "inline constexpr const char *public_key_id = " + json.dumps(key_id(keys["public"])) + ";"])
    resource = "R-" + opaque(keys["master"], "resource-v1", "basis-weights") + ".dat" if protected else "proprietary_basis_weights.dat"
    header.extend(["inline constexpr const char *resource_name = " + json.dumps(resource) + ";", "}"])
    generated = build / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    generate_constants(root / "examples/policy-constants.json", generated, build / "private",
                       keys["master"], protected and constants)
    (generated / "resource-name.txt").write_text(resource, encoding="ascii")
    text = "\n".join(header) + "\n"
    destination = generated / "diagnostic_catalog.hpp"
    if not destination.exists() or destination.read_text() != text:
        destination.write_text(text, encoding="ascii")
    resources = generated / "resources"
    resources.mkdir(exist_ok=True)
    (resources / resource).write_text("kernel-coefficient=7\n", encoding="ascii")
    output_resources = build / "bin/resources"
    output_resources.mkdir(parents=True, exist_ok=True)
    shutil.copy2(resources / resource, output_resources / resource)
    write_private(build / "private/diagnostics.json", dict(schema=1, key_id=key_id(keys["public"]),
                  master_id=opaque(keys["master"], "master-id", "v1"), sites=rows))
    write_private(build / "private/compiler-keys.json", {k: keys[k] for k in ("schema", "master", "public")})
    write_private(build / "private/config.json", dict(protected=bool(protected), constants=bool(protected and constants), resource=resource,
                  key_id=key_id(keys["public"])))
    write_private(cache, dict(fingerprint=fingerprint))
    if os.name != "nt":
        os.chmod(build / "private", 0o700)
    return dict(sites=len(rows), protected=protected, demo_keys="PUBLIC DEMO" in keys.get("warning", ""))
