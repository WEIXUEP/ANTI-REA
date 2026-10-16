"""Publish canonical skill instructions and an explicitly allowlisted download."""
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

SKILL_FILES = (
    "SKILL.md",
    "references/remediation.md",
    "references/validation.md",
    "references/windows.md",
    "scripts/audit.py",
    "agents/openai.yaml",
)


def skill_contents(root):
    directory = Path(root) / "skills/cpp-leakage-audit"
    result = {}
    for name in SKILL_FILES:
        source = directory / name
        if source.is_symlink() or not source.resolve().is_relative_to(directory.resolve()):
            raise ValueError("Refusing an external skill publication source: " + name)
        result[name] = source.read_bytes()
    license_file = Path(root) / "LICENSE"
    if license_file.is_symlink():
        raise ValueError("Refusing an external license publication source")
    result["LICENSE"] = license_file.read_bytes()
    return result


def skill_archive(contents):
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            entry = ZipInfo("cpp-leakage-audit/" + name, date_time=(2026, 1, 1, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    return output.getvalue()


def on_files(files, config):
    from mkdocs.structure.files import File

    root = Path(config.config_file_path).parent
    contents = skill_contents(root)
    for source, destination in (
        ("SKILL.md", "skill/index.md"),
        ("references/remediation.md", "skill/references/remediation.md"),
        ("references/validation.md", "skill/references/validation.md"),
        ("references/windows.md", "skill/references/windows.md"),
    ):
        files.append(File.generated(config, destination, content=contents[source].decode("utf-8")))
    files.append(File.generated(config, "downloads/cpp-leakage-audit.zip", content=skill_archive(contents)))
    return files
