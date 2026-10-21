"""Deterministic decoy labels and exact, reviewed LLVM function-symbol renaming."""
import json
from pathlib import Path
import re
from .crypto import opaque

FUNCTION_WORDS = ("read_buffer", "parse_header", "update_cache", "flush_queue",
                  "load_config", "write_record", "check_status", "copy_block")
TYPE_WORDS = ("BufferPool", "CacheEntry", "PacketHeader", "ConfigNode",
              "QueueItem", "FileRecord", "SessionState", "StreamBuffer")
STYLES = ("OPAQUE", "DECOY")
# LLVM identifiers are tokens, not substrings of strings, comments or metadata.
TOKEN = re.compile(r';[^\n]*|[@$](?:"(?:[^"\\\n]|\\[0-9a-fA-F]{2})*"|[-a-zA-Z$._][-a-zA-Z$._0-9]*)|"(?:[^"\\\n]|\\[0-9a-fA-F]{2})*"')
FUNCTION = re.compile(r'^(?:define|declare)\b[^\n]*?(@(?:"[^"\n]+"|[-a-zA-Z$._][-a-zA-Z$._0-9]*))\(', re.M)


def decoy(master, domain, original, kind):
    digest = opaque(master, "decoy-" + domain + "-v1", original, 64)
    words = TYPE_WORDS if kind == "type" else FUNCTION_WORDS
    return words[int(digest[:8], 16) % len(words)] + "_" + digest


def rtti_aliases(name):
    normalized = name.lstrip("*")
    result = {name, normalized, normalized.removeprefix(".?AV").removesuffix("@@")}
    sized = re.fullmatch(r"(\d+)([A-Za-z_][A-Za-z_0-9]*)", normalized)
    if sized and int(sized[1]) == len(sized[2]):
        result.add(sized[2])
    return result


def load_policy(path, msvc):
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(policy, dict) or policy.get("schema") != 1 or not isinstance(policy.get("functions"), list):
        raise ValueError("Expected schema-1 explicit function-name policy")
    abi = "msvc" if msvc else "itanium"
    result = {}
    for row in policy["functions"]:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise ValueError("Invalid function-name policy entry")
        symbol = row.get(abi)
        if (not isinstance(symbol, str) or not symbol.startswith("?" if msvc else "_Z")
                or not re.fullmatch(r"[A-Za-z_0-9?$@.]+", symbol) or symbol in result):
            raise ValueError("Expected unique, exact C++ symbols for " + abi)
        result[symbol] = row["name"]
    return result


def rename_functions(ir, master, policy, retain_exports=False):
    """Run after debug stripping and xollvm; preserve all types and call attributes."""
    headers = {}
    for match in FUNCTION.finditer(ir):
        token = match[1]
        symbol = token[1:].strip('"')
        if symbol in policy:
            if re.search(r"\b(?:dllexport|dllimport|available_externally)\b", match[0]):
                raise ValueError("Cannot rename exported/imported function: " + symbol)
            if symbol.startswith("_Z") and not re.search(r"\b(?:hidden|internal|private)\b", match[0]):
                raise ValueError("Cannot rename a default-visibility ELF function: " + symbol)
            if retain_exports and not symbol.startswith("?"):
                raise ValueError("Retained decoy exports support only MSVC ABI functions")
            if symbol in headers:
                raise ValueError("Duplicate function declaration: " + symbol)
            headers[symbol] = match[0].startswith("define")
    aliases = {symbol: decoy(master, "function", symbol, "function") for symbol in headers}
    if len(set(aliases.values())) != len(aliases):
        raise ValueError("Function alias collision")
    existing = {match[0][1:].strip('"') for match in TOKEN.finditer(ir) if match[0].startswith(("@", "$"))}
    if set(aliases.values()) & existing:
        raise ValueError("Function alias collides with an existing IR identifier")
    # Name-based assembly/linker references cannot be rewritten as LLVM operands.
    for match in TOKEN.finditer(ir):
        if match[0].startswith('"') and any(symbol in match[0] for symbol in aliases):
            raise ValueError("Selected function has a textual linker/assembly reference")

    def replace(match):
        token = match[0]
        if token.startswith(("@", "$")):
            symbol = token[1:].strip('"')
            if symbol in aliases:
                return token[0] + aliases[symbol]
        return token

    rows = [dict(original=symbol, decoded=policy[symbol], replacement=alias,
                 definition=headers[symbol], style="DECOY") for symbol, alias in sorted(aliases.items())]
    renamed = TOKEN.sub(replace, ir)
    if retain_exports:
        exported = set(aliases.values())

        def mark_export(match):
            if match[0].startswith("define") and match[1][1:] in exported:
                if not re.match(r"^define (?:dso_local )?(?:noundef |void |i\d+ |ptr |double |float )", match[0]):
                    raise ValueError("Unsupported function linkage for retained decoy exports")
                return re.sub(r"^(define(?: dso_local)?) ", r"\1 dllexport ", match[0], count=1)
            return match[0]

        renamed = FUNCTION.sub(mark_export, renamed)
    return renamed, rows
