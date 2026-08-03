"""Hermes plugin registration for the Proton Pass secret source."""

from __future__ import annotations

from pathlib import Path

from .cli import register_protonpass_cli
from .source import ProtonPassSource, ProtonPassVaultSource

__all__ = ["ProtonPassSource", "ProtonPassVaultSource", "register"]


def register(ctx) -> None:
    """Register the secret source, its management command, and bundled skills."""
    ctx.register_secret_source(ProtonPassSource())
    ctx.register_secret_source(ProtonPassVaultSource())
    ctx.register_cli_command(
        name="protonpass",
        help="Manage the Proton Pass secret-source plugin",
        description="Configure, inspect, sync, or disable Proton Pass.",
        setup_fn=register_protonpass_cli,
    )

    skills_dir = Path(__file__).parent.parent / "skills"
    for child in sorted(skills_dir.iterdir()):
        skill_md = child / "SKILL.md"
        if child.is_dir() and skill_md.exists():
            ctx.register_skill(child.name, skill_md)

    # Hermes loads .env before general plugin discovery. Invalidate the
    # once-per-process guard so the next normal env load includes this newly
    # registered source instead of retaining the built-in-only result.
    from hermes_cli.env_loader import reset_secret_source_cache

    reset_secret_source_cache()
