"""Opt-in runtime observations of a trusted Python entry point; not a sandbox."""
import argparse
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import runpy
import sys
import types


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entry", required=True, type=Path)
    parser.add_argument("--module-prefix", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--execute", action="store_true", help="Explicitly execute a reviewed trusted target")
    parser.add_argument("--dump-code", action="store_true", help="Experimental serialization for ordinary owned CPython code; unsafe for modified/protected code objects")
    args = parser.parse_args()
    if not args.execute:
        parser.error("runtime capture requires --execute; static auditing never executes targets")
    entry, output = args.entry.resolve(), args.out.resolve()
    if output.exists() or output.is_relative_to(entry.parent):
        parser.error("capture output must be new and outside target")
    output.mkdir(parents=True)
    records, seen = [], set()

    def relevant(filename):
        return str(filename).startswith("<sealed/") or str(filename).replace("\\", "/").startswith(entry.parent.as_posix() + "/")

    def save(code, event):
        if not isinstance(code, types.CodeType) or len(records) >= 256:
            return
        if not args.dump_code:
            key = (id(code), event)
            if key not in seen:
                seen.add(key)
                records.append(dict(event=event, name=code.co_qualname, filename=code.co_filename))
            return
        body = marshal.dumps(code)
        key = hashlib.sha256(body).hexdigest()
        if key in seen or len(body) > 4 * 1024 * 1024:
            return
        seen.add(key)
        name = "code-" + key[:20] + ".pyc"
        (output / name).write_bytes(importlib.util.MAGIC_NUMBER + bytes(12) + body)
        records.append(dict(file=name, event=event, name=code.co_qualname, filename=code.co_filename))

    def audit(event, arguments):
        if event == "exec" and relevant(arguments[0].co_filename):
            save(arguments[0], event)
        if args.dump_code and event == "compile" and relevant(arguments[1]) and len(records) < 256:
            body = arguments[0]
            if isinstance(body, str):
                body = body.encode("utf-8")
            if isinstance(body, bytes) and len(body) <= 4 * 1024 * 1024:
                name = "source-" + hashlib.sha256(body).hexdigest()[:20] + ".py"
                if not (output / name).exists():
                    (output / name).write_bytes(body)
                    records.append(dict(file=name, event=event, filename=str(arguments[1])))

    def profile(frame, event, value):
        if event == "call" and str(frame.f_globals.get("__name__", "")).startswith(args.module_prefix):
            save(frame.f_code, event)

    sys.addaudithook(audit)
    sys.setprofile(profile)
    sys.path.insert(0, str(entry.parent))
    sys.argv = [str(entry)]
    try:
        runpy.run_path(str(entry), run_name="__main__")
    finally:
        sys.setprofile(None)
        (output / "observations.json").write_text(json.dumps(records, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
