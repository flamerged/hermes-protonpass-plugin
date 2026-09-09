"""Hermes plugin registration for the Proton Pass secret source."""

from __future__ import annotations

import logging
from pathlib import Path

from .cli import register_protonpass_cli
from .source import ProtonPassSource, ProtonPassVaultSource

__all__ = ["ProtonPassSource", "ProtonPassVaultSource", "register"]

logger = logging.getLogger(__name__)


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

    skill_md = Path(__file__).parent / "skills" / "vault-access" / "SKILL.md"
    if skill_md.is_file():
        ctx.register_skill("vault-access", skill_md)
    else:
        # Optional guidance must not disable credential resolution or the CLI
        # when an installation is incomplete. Never scan sibling packages.
        logger.warning(
            "Bundled vault-access skill is missing; reinstall "
            "hermes-protonpass-plugin to restore it."
        )

    # Hermes loads .env before general plugin discovery. Invalidate the
    # once-per-process guard so the next normal env load includes this newly
    # registered source instead of retaining the built-in-only result.
    from hermes_cli.env_loader import reset_secret_source_cache

    reset_secret_source_cache()
