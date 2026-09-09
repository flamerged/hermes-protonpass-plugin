"""Check a wheel/sdist installation, using only installed Hermes/plugin imports.

Run from outside the checkout: <venv>/bin/python -I /path/to/this/script ARTIFACT.
The caller installs ARTIFACT with dependencies and runs `uv pip check` first.
No Proton session, account, or external plugin is accessed.
"""

from __future__ import annotations

import argparse
from importlib import metadata
import json
import os
from pathlib import Path
import sys
import sysconfig
import tarfile
import tempfile
import zipfile

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet


def artifact_bytes(artifact: Path, member: str) -> bytes:
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            return archive.read(member)
    with tarfile.open(artifact, "r:gz") as archive:
        matches = [m for m in archive.getmembers() if m.name.endswith("/" + member)]
        assert len(matches) == 1, f"Expected one {member} in {artifact.name}"
        stream = archive.extractfile(matches[0])
        assert stream is not None, f"Missing file contents for {member}"
        with stream:
            return stream.read()


def check_dependency_metadata() -> None:
    dist = metadata.distribution("hermes-protonpass-plugin")
    python_constraint = dist.metadata["Requires-Python"]
    assert python_constraint and sys.version.split()[0] in SpecifierSet(
        python_constraint
    )
    for text in dist.requires or []:
        requirement = Requirement(text)
        if requirement.marker and not requirement.marker.evaluate():
            continue
        installed = metadata.version(requirement.name)
        assert installed in requirement.specifier, f"{text}; installed {installed}"
        print(
            f"Dependency: {requirement.name} {installed} satisfies {requirement.specifier}"
        )


def check_installed_plugin(artifact: Path) -> None:
    import hermes_protonpass
    from agent.secret_sources import registry as source_registry
    from hermes_cli import plugins as plugins_mod
    from tools import skills_tool

    site_paths = {
        Path(sysconfig.get_path(key)).resolve() for key in ("purelib", "platlib")
    }
    for module in (hermes_protonpass, source_registry, plugins_mod, skills_tool):
        imported = Path(module.__file__).resolve()
        assert any(imported.is_relative_to(site) for site in site_paths), (
            f"Source checkout leaked into installed test: {imported}"
        )
        print(f"Installed import: {imported}")

    package_dir = Path(hermes_protonpass.__file__).resolve().parent
    for relative in ("__init__.py", "skills/vault-access/SKILL.md"):
        installed_bytes = (package_dir / relative).read_bytes()
        assert installed_bytes == artifact_bytes(
            artifact, "hermes_protonpass/" + relative
        )

    source_registry._reset_registry_for_tests()
    manager = plugins_mod.PluginManager()
    # Exercise real entry-point metadata and loading, without discovering any
    # user or repository plugins when skill_view calls discover_plugins().
    manifests = [m for m in manager._scan_entry_points() if m.name == "protonpass"]
    assert len(manifests) == 1, "Expected the installed protonpass entry point"
    manager._discovered = True
    plugins_mod._plugin_manager = manager
    manager._load_plugin(manifests[0])
    loaded = manager._plugins["protonpass"]
    assert loaded.enabled and loaded.error is None, loaded.error
    assert source_registry.get_source("protonpass") is not None
    assert source_registry.get_source("protonpass_vault") is not None
    assert manager._cli_commands["protonpass"]["plugin"] == "protonpass"

    skill_path = manager.find_plugin_skill("protonpass:vault-access")
    assert skill_path is not None
    assert skill_path.resolve() == package_dir / "skills/vault-access/SKILL.md"
    result = json.loads(skills_tool.skill_view("protonpass:vault-access"))
    assert result["success"], result
    assert result["name"] == "protonpass:vault-access"
    assert skill_path.read_text(encoding="utf-8") in result["content"]
    print(f"Installed entry point and skill_view passed for {artifact.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    assert sys.flags.isolated, "Run this check with python -I"
    checkout = Path(__file__).resolve().parents[1]
    assert not Path.cwd().resolve().is_relative_to(checkout), "Run outside the checkout"
    check_dependency_metadata()
    with tempfile.TemporaryDirectory(prefix="protonpass-installed-") as home:
        os.environ["HERMES_HOME"] = home
        check_installed_plugin(args.artifact.resolve())


if __name__ == "__main__":
    main()
