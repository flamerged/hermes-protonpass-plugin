"""Contract tests for the standalone Hermes plugin boundary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

import pytest
import yaml

import hermes_protonpass
from agent.secret_sources import registry as source_registry
from hermes_protonpass import source
from hermes_protonpass.cli import cmd_pp_status
from hermes_cli.plugins import PluginManager, PluginManifest
from tests.secret_sources.conformance import SecretSourceConformance


@pytest.fixture(autouse=True)
def isolated_hermes_home(tmp_path, monkeypatch):
    """Skill loading must never discover the developer's configured plugins."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))


class TestProtonPassConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return source.ProtonPassSource()


class TestProtonPassVaultConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return source.ProtonPassVaultSource()


class RecordingContext:
    def __init__(self) -> None:
        self.secret_sources = []
        self.cli_commands = []
        self.skills = []

    def register_secret_source(self, registered_source) -> None:
        self.secret_sources.append(registered_source)

    def register_cli_command(self, **command) -> None:
        self.cli_commands.append(command)

    def register_skill(self, name, path, description="") -> None:
        self.skills.append((name, path, description))


def test_register_uses_public_secret_source_and_cli_surfaces(monkeypatch):
    reset_calls = []
    monkeypatch.setattr(
        "hermes_cli.env_loader.reset_secret_source_cache",
        lambda: reset_calls.append(True),
    )
    ctx = RecordingContext()

    hermes_protonpass.register(ctx)

    assert len(ctx.secret_sources) == 2
    mapped, bulk = ctx.secret_sources
    assert isinstance(mapped, source.ProtonPassSource)
    assert mapped.name == "protonpass"
    assert mapped.shape == "mapped"
    assert mapped.scheme == "pass"
    assert isinstance(bulk, source.ProtonPassVaultSource)
    assert bulk.name == "protonpass_vault"
    assert bulk.shape == "bulk"
    assert bulk.scheme is None
    assert len(ctx.cli_commands) == 1
    assert ctx.cli_commands[0]["name"] == "protonpass"
    assert reset_calls == [True]
    assert len(ctx.skills) == 1
    skill_name, skill_path, _ = ctx.skills[0]
    assert skill_name == "vault-access"
    assert skill_path == (
        Path(hermes_protonpass.__file__).parent / "skills/vault-access/SKILL.md"
    )
    assert skill_path.is_file()


def test_missing_bundled_skill_preserves_source_and_cli_registration(
    tmp_path, monkeypatch, caplog
):
    """An incomplete install must not disable the secret source or its CLI."""
    monkeypatch.setattr(
        hermes_protonpass, "__file__", str(tmp_path / "hermes_protonpass/__init__.py")
    )
    reset_calls = []
    monkeypatch.setattr(
        "hermes_cli.env_loader.reset_secret_source_cache",
        lambda: reset_calls.append(True),
    )
    ctx = RecordingContext()

    hermes_protonpass.register(ctx)

    assert [source.name for source in ctx.secret_sources] == [
        "protonpass",
        "protonpass_vault",
    ]
    assert ctx.cli_commands[0]["name"] == "protonpass"
    assert ctx.skills == []
    assert reset_calls == [True]
    assert "vault-access" in caplog.text
    assert "reinstall" in caplog.text.lower()


def test_registered_cli_builds_plugin_owned_command_tree():
    ctx = RecordingContext()
    hermes_protonpass.register(ctx)
    parser = argparse.ArgumentParser()

    ctx.cli_commands[0]["setup_fn"](parser)
    args = parser.parse_args(["status"])

    assert args.protonpass_command == "status"
    assert args.func is cmd_pp_status


def test_bundled_skill_has_no_credentials_or_raw_vault_command_recipes():
    """Keep the guidance on the plugin's mapping/diagnostic boundary."""
    ctx = RecordingContext()
    hermes_protonpass.register(ctx)
    content = ctx.skills[0][1].read_text(encoding="utf-8")
    frontmatter = yaml.safe_load(content.split("---", 2)[1])
    assert "required_environment_variables" not in frontmatter
    assert "platforms" not in frontmatter
    shell_blocks = re.findall(r"```(?:bash|sh|shell)\n(.*?)```", content, re.DOTALL)
    assert shell_blocks
    allowed_commands = {"hermes protonpass status", "hermes protonpass sync"}
    for block in shell_blocks:
        assert set(block.strip().splitlines()) <= allowed_commands

    (example,) = re.findall(r"```yaml\n(.*?)```", content, re.DOTALL)
    mapping = yaml.safe_load(example)["secrets"]["protonpass"]["env"]
    assert mapping == {"MY_API_KEY": "pass://<share_id>/<item_id>/<field>"}


def test_directory_plugin_loads_through_current_hermes_manager(monkeypatch):
    """Exercise the same directory-loader boundary used by ~/.hermes/plugins."""
    source_registry._reset_registry_for_tests()
    monkeypatch.setattr(
        "agent.secret_sources.registry._ensure_builtin_sources", lambda: None
    )
    reset_calls = []
    monkeypatch.setattr(
        "hermes_cli.env_loader.reset_secret_source_cache",
        lambda: reset_calls.append(True),
    )
    plugin_dir = Path(__file__).resolve().parents[1]
    manager = PluginManager()
    manager._discovered = True
    manifest = PluginManifest(
        name="protonpass",
        version="0.1.0",
        source="user",
        path=str(plugin_dir),
        kind="standalone",
        key="protonpass",
    )

    try:
        manager._load_plugin(manifest)
        loaded = manager._plugins["protonpass"]
        assert loaded.enabled is True
        assert loaded.error is None
        assert source_registry.get_source("protonpass") is not None
        assert source_registry.get_source("protonpass_vault") is not None
        assert manager._cli_commands["protonpass"]["plugin"] == "protonpass"
        assert reset_calls == [True]

        # The bundled skill registers under the namespaced name and resolves
        # through the real skill_view() dispatch, not just the raw registry.
        skill_path = manager.find_plugin_skill("protonpass:vault-access")
        assert skill_path is not None
        assert skill_path.name == "SKILL.md"
        assert skill_path.is_file()

        from hermes_cli import plugins as plugins_mod
        from tools.skills_tool import skill_view

        monkeypatch.setattr(plugins_mod, "_plugin_manager", manager)
        result = json.loads(skill_view("protonpass:vault-access"))
        assert result["success"] is True
        assert result["name"] == "protonpass:vault-access"
        # Read-only framing must survive intact — this is the whole point of
        # bundling the skill instead of leaving the agent to guess.
        assert "read-only" in result["content"].lower()
        assert "never create" in result["content"].lower()
    finally:
        source_registry._reset_registry_for_tests()


def test_mapped_refs_beat_bulk_vault_claims(monkeypatch, tmp_path):
    source_registry._reset_registry_for_tests()
    monkeypatch.setattr(
        "agent.secret_sources.registry._ensure_builtin_sources", lambda: None
    )
    mapped = source.ProtonPassSource()
    bulk = source.ProtonPassVaultSource()
    monkeypatch.setattr(
        mapped,
        "fetch",
        lambda cfg, home: source.FetchResult(secrets={"SHARED": "mapped"}),
    )
    monkeypatch.setattr(
        bulk,
        "fetch",
        lambda cfg, home: source.FetchResult(secrets={"SHARED": "bulk"}),
    )

    try:
        assert source_registry.register_source(bulk)
        assert source_registry.register_source(mapped)
        env = {}
        report = source_registry.apply_all(
            {
                "sources": ["protonpass_vault", "protonpass"],
                "protonpass_vault": {"enabled": True, "vault": "V"},
                "protonpass": {
                    "enabled": True,
                    "env": {"SHARED": "pass://S/I/F"},
                },
            },
            tmp_path,
            environ=env,
        )
        assert env["SHARED"] == "mapped"
        assert report.provenance["SHARED"].source == "protonpass"
    finally:
        source_registry._reset_registry_for_tests()
