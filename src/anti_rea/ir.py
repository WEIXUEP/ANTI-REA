"""Strict, ABI-specific RTTI record transformations for the demonstration scope."""
import re
import subprocess
from .crypto import opaque

SCOPE = re.compile(r"\baegis::internal\b|\bprint_rtti\(\)::")
ITANIUM = re.compile(r'^(?P<head>@(?P<quote>"?)(?P<symbol>_ZTS[^"\s]+)(?P=quote) = [^\n]*?constant )\[(?P<size>\d+) x i8\] c"(?P<raw>[^"\n]+)\\00"(?P<tail>[^\n]*)$', re.M)
MSVC = re.compile(r'^(?P<head>@"(?P<symbol>\?\?_R0[^"\n]+)" = [^\n]*?global )(?P<layout>%rtti\.TypeDescriptor\d+|\{ ptr, ptr, \[\d+ x i8\] \}) \{ ptr (?P<vft>[^,]+), ptr null, \[(?P<size>\d+) x i8\] c"(?P<raw>[^"\n]+)\\00" \}(?P<tail>[^\n]*)$', re.M)


def decode_type(symbol, raw, tool, msvc):
    output = subprocess.run([str(tool), raw[1:] if msvc else symbol], check=True,
                            capture_output=True, text=True).stdout.strip()
    if msvc:
        # llvm-undname includes the input on its first line.
        lines = [line.strip() for line in output.splitlines() if line.strip() != raw[1:]]
        if not lines or all(line == raw[1:] for line in lines):
            raise ValueError("Cannot decode MSVC RTTI")
        return " ".join(lines)
    if not output.startswith("typeinfo name for "):
        raise ValueError("Cannot decode Itanium RTTI: " + symbol)
    return output[len("typeinfo name for "):]


def transform(ir, master, demangler, msvc=False, decode=None):
    pattern = MSVC if msvc else ITANIUM
    candidates = [line for line in ir.splitlines()
                  if (line.startswith('@"??_R0') if msvc else re.match(r'^@"?_ZTS', line))
                  and " = " in line and " external " not in line]
    matches = list(pattern.finditer(ir))
    if len(candidates) != len(matches):
        raise ValueError("Unsupported RTTI layout; refusing partial protection")
    rows = []

    def replace(match):
        raw = match["raw"]
        if "\\" in raw or len(raw.encode("ascii")) + 1 != int(match["size"]):
            raise ValueError("Unsupported RTTI name encoding")
        if msvc and match["layout"].startswith("%"):
            expected = match["layout"] + " = type { ptr, ptr, [" + match["size"] + " x i8] }"
            if expected not in ir.splitlines():
                raise ValueError("Unknown named MSVC TypeDescriptor layout")
        decoded = decode(raw) if decode else decode_type(match["symbol"], raw, demangler, msvc)
        selected = bool(SCOPE.search(decoded))
        identity = opaque(master, "rtti-msvc-v1" if msvc else "rtti-itanium-v1", raw.lstrip("*"), 64)
        name = (".?AVR_" + identity + "@@") if msvc else (("*" if raw.startswith("*") else "") + "65R" + identity)
        rows.append(dict(abi="msvc" if msvc else "itanium", original=raw, decoded=decoded,
                         opaque=name if selected else raw, protected=selected))
        if not selected:
            return match[0]
        size = len(name) + 1
        if msvc:
            if match["vft"] != '@"??_7type_info@@6B@"':
                raise ValueError("Unknown MSVC type_info runtime")
            layout = "{ ptr, ptr, [" + str(size) + " x i8] }"
            return match["head"] + layout + " { ptr " + match["vft"] + ', ptr null, [' + str(size) + ' x i8] c"' + name + '\\00" }' + match["tail"]
        return match["head"] + f'[{size} x i8] c"{name}\\00"' + match["tail"]

    return pattern.sub(replace, ir), rows
