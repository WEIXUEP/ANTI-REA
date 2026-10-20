"""Generate scoped runtime-masked constants, not a secret-bearing cipher."""
import json
from pathlib import Path
import re

from .crypto import opaque, write_private


def generate_constants(catalog, generated, private, master, protected):
    catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    values = catalog.get("values")
    if (catalog.get("schema") != 1 or not isinstance(values, dict) or not values
            or any(not re.fullmatch(r"[a-z][a-z0-9_]*", name)
                   or type(value) is not int or not 0 <= value <= 0xffffffff
                   for name, value in values.items())):
        raise ValueError("Expected named unsigned 32-bit policy constants, schema 1")
    lines = ["#pragma once", "#include <cstdint>", "namespace aegis::constants {"]
    rows = []
    for name, value in values.items():
        if protected:
            for attempt in range(256):
                mask = int(opaque(master, "policy-constant-mask-v1", f"{name}:{attempt}", 8), 16)
                encoded = value ^ mask
                if mask and encoded and mask not in values.values() and encoded not in values.values():
                    break
            else:
                raise ValueError("Cannot derive nontrivial constant shares")
            # Volatile loads prevent backend constant folding, including /O2.
            lines.append(f"static const volatile std::uint32_t {name}_shares[2] = {{0x{encoded:08x}u, 0x{mask:08x}u}};")
            rows.append(dict(name=name, original=value, encoded=encoded, mask=mask))
        else:
            lines.append(f"inline constexpr std::uint32_t {name} = 0x{value:08x}u;")
            rows.append(dict(name=name, original=value))
    lines.extend(["}", "#define AR_POLICY_VALUE(name) " + (
        "(::aegis::constants::name##_shares[0] ^ ::aegis::constants::name##_shares[1])"
        if protected else "(::aegis::constants::name)"), ""])
    header = Path(generated) / "policy_constants.hpp"
    text = "\n".join(lines)
    if not header.exists() or header.read_text(encoding="ascii") != text:
        header.write_text(text, encoding="ascii")
    write_private(Path(private) / "constants.json", dict(schema=1, protected=bool(protected),
                  mechanism="volatile-xor-shares-v1" if protected else "plaintext", constants=rows))
