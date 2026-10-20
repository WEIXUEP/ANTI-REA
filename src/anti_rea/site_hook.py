"""Publish two independent skills using explicit public-file allowlists."""
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

SKILL_FILES = {
    "cpp-leakage-audit": (
        "SKILL.md",
        "references/interpretation.md",
        "references/validation.md",
        "references/operations.md",
        "references/windows.md",
        "references/rea.md",
        "references/vm-recovery.md",
        "references/numeric-recovery.md",
        "references/html-reporting.md",
        "scripts/audit.py",
        "scripts/rea_audit.py",
        "scripts/probe_constant_pairs.py",
        "scripts/report_html.py",
        "scripts/requirements.txt",
        "agents/openai.yaml",
    ),
    "cpp-code-protection": (
        "SKILL.md",
        "references/remediation.md",
        "references/validation.md",
        "references/recovery-tools.md",
        "references/key-management.md",
        "references/operations.md",
        "references/integration.md",
        "references/windows.md",
        "references/runtime-constants.md",
        "scripts/generate_keys.py",
        "scripts/decode.py",
        "scripts/_recovery.py",
        "scripts/doctor.py",
        "scripts/measure.py",
        "scripts/requirements.txt",
        "agents/openai.yaml",
    ),
}
SKILL_ROUTES = {"cpp-leakage-audit": "skill", "cpp-code-protection": "protection-skill"}


def skill_contents(root, skill="cpp-leakage-audit"):
    directory = Path(root) / "skills" / skill
    result = {}
    for name in SKILL_FILES[skill]:
        source = directory / name
        if source.is_symlink() or not source.resolve().is_relative_to(directory.resolve()):
            raise ValueError("Refusing an external skill publication source: " + name)
        result[name] = source.read_bytes()
    license_file = Path(root) / "LICENSE"
    if license_file.is_symlink():
        raise ValueError("Refusing an external license publication source")
    result["LICENSE"] = license_file.read_bytes()
    return result


def skill_archive(contents, skill="cpp-leakage-audit"):
    if skill not in SKILL_FILES:
        raise ValueError("Unknown public skill: " + skill)
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            entry = ZipInfo(skill + "/" + name, date_time=(2026, 1, 1, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    return output.getvalue()


def on_files(files, config):
    from mkdocs.structure.files import File

    root = Path(config.config_file_path).parent
    for skill, route in SKILL_ROUTES.items():
        contents = skill_contents(root, skill)
        for source in SKILL_FILES[skill]:
            if not source.endswith(".md"):
                continue
            destination = route + "/" + ("index.md" if source == "SKILL.md" else source)
            files.append(File.generated(config, destination, content=contents[source].decode("utf-8")))
        files.append(File.generated(config, "downloads/" + skill + ".zip",
                                    content=skill_archive(contents, skill)))
    return files
