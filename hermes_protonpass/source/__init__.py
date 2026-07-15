"""Proton Pass (`pass-cli`) integration.

Hermes pulls API keys from a user's Proton Pass account at process startup so
they don't have to live in plaintext in ``~/.hermes/.env``.  This mirrors the
Bitwarden Secrets Manager source (:mod:`agent.secret_sources.bitwarden`)
one-for-one so the rest of the system can wire it identically.

This package is split into focused modules:

* :mod:`~hermes_protonpass.source.config` — the ``ProtonPassConfig``
  model: the single home for config parsing/coercion/validation.
* :mod:`~hermes_protonpass.source.install` — binary discovery + the
  lazy, SHA-256-pinned ``pass-cli`` install.
* :mod:`~hermes_protonpass.source.session` — minimal-env subprocess
  plumbing + session establishment.
* :mod:`~hermes_protonpass.source.cache` — two-layer (in-process +
  disk) cache of resolved secrets.
* :mod:`~hermes_protonpass.source.fetch` — MODE A/B fetch + JSON
  parsing + argument-injection validators.
* :mod:`~hermes_protonpass.source.apply` — the legacy application
  planner used by the user-facing sync command.

Design summary
--------------

* The ``pass-cli`` binary is auto-installed into ``<hermes_home>/bin/pass-cli``
  on first use.  Hermes pins one version (``_PASS_CLI_VERSION``) and downloads
  the matching asset, verifying its SHA-256 against a HARDCODED pinned table
  (``_PINNED_SHA256`` in :mod:`install`).
* The service token (a Proton Pass personal-access / agent token) is stored in
  the active profile's ``.env`` as ``PROTON_PASS_PERSONAL_ACCESS_TOKEN`` (or
  whatever name the user picked in the source config).
* Two separately registered sources preserve Hermes' precedence semantics:
  mapped MODE B refs live under ``secrets.protonpass`` and bulk MODE A vault
  export lives under ``secrets.protonpass_vault``.
* Resolved values are cached in-process and on disk (mode 0600) so back-to-back
  ``hermes`` invocations don't re-establish a session.  Only the values + a
  token FINGERPRINT are persisted; the token itself is NEVER stored.
* Failures NEVER block Hermes startup.

The user-facing setup wizard lives in :mod:`hermes_protonpass.cli`.
"""

from __future__ import annotations

import os
from pathlib import Path

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource

from .apply import (
    PlanItem,
    SKIP_ALREADY_SET,
    SKIP_BOOTSTRAP_TOKEN,
    apply_protonpass_secrets,
    plan_application,
)
from .config import _DEFAULT_SERVICE_TOKEN_ENV, ProtonPassConfig
from .errors import classify_protonpass_error
from .fetch import fetch_protonpass_secrets
from .install import (
    find_pass_cli,
    get_pass_cli_version,
    install_pass_cli,
)

# Kept importable for the broad set of callers/tests that still reach for them
# as ``pp.<name>`` (the cache reset is used by every test module's autouse
# fixture; the pinned version by the install tests + the CLI ``install`` help),
# but DELIBERATELY left OUT of ``__all__`` below: they are private/test-only and
# should not be part of the package's advertised public surface.  Callers that
# want the validator or the version constant directly should import them from
# their defining submodule (``...config.is_valid_env_name``,
# ``...install._PASS_CLI_VERSION``).
from .cache import _reset_cache_for_tests  # noqa: F401
from .install import _PASS_CLI_VERSION  # noqa: F401


def _common_config_schema() -> dict:
    return {
        "enabled": {"description": "Master switch", "default": False},
        "service_token_env": {
            "description": "Env var holding the Proton Pass service token",
            "default": _DEFAULT_SERVICE_TOKEN_ENV,
        },
        "cache_ttl_seconds": {
            "description": "Disk+memory cache TTL; 0 disables",
            "default": 300,
        },
        "override_existing": {
            "description": "Resolved values overwrite .env/shell values",
            "default": False,
        },
        "auto_install": {
            "description": "Auto-download the pinned pass-cli binary",
            "default": True,
        },
    }


class _ProtonPassSourceBase(SecretSource):
    """Shared behavior for the mapped and bulk Proton Pass sources.

    ``fetch()`` only resolves configured values and returns them to the
    registry.  The registry owns precedence, protected variables,
    ``override_existing``, conflict warnings, provenance, and all environment
    writes.
    """

    def is_enabled(self, cfg: dict) -> bool:
        return ProtonPassConfig.from_mapping(cfg).enabled

    def override_existing(self, cfg: dict) -> bool:
        return ProtonPassConfig.from_mapping(cfg).override_existing

    def protected_env_vars(self, cfg: dict):
        parsed = ProtonPassConfig.from_mapping(cfg)
        return frozenset({_DEFAULT_SERVICE_TOKEN_ENV, parsed.service_token_env})

    def _fetch(
        self,
        parsed: ProtonPassConfig,
        home_path: Path,
        *,
        vault: str = "",
        env_refs: dict | None = None,
    ) -> FetchResult:
        result = FetchResult()

        service_token = os.environ.get(parsed.service_token_env, "").strip()
        if not service_token:
            result.error = (
                f"secrets.{self.name}.enabled is true but "
                f"{parsed.service_token_env} is not set.  Run "
                "`hermes protonpass setup`."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        binary = find_pass_cli(install_if_missing=parsed.auto_install)
        result.binary_path = binary
        if binary is None:
            result.error = (
                "pass-cli binary not available. Run `hermes protonpass "
                "install` to download the verified pinned version, "
                f"or leave `auto_install: true` in the secrets.{self.name} "
                "config so Hermes downloads it automatically."
            )
            result.error_kind = ErrorKind.BINARY_MISSING
            return result

        try:
            secrets, warnings = fetch_protonpass_secrets(
                service_token=service_token,
                vault=vault,
                env_refs=env_refs or {},
                binary=binary,
                cache_ttl_seconds=parsed.cache_ttl_seconds,
                auto_install=parsed.auto_install,
                home_path=home_path,
                bootstrap_env=parsed.service_token_env,
            )
        except Exception as exc:  # noqa: BLE001 — source contract: never raise
            from .session import _redact_token

            result.error = _redact_token(str(exc), service_token)
            result.error_kind = classify_protonpass_error(result.error)
            return result

        result.secrets = secrets
        result.warnings.extend(warnings)
        return result


class ProtonPassSource(_ProtonPassSourceBase):
    """Explicit ``ENV_VAR -> pass://...`` mappings (mapped precedence)."""

    name = "protonpass"
    label = "Proton Pass"
    shape = "mapped"
    scheme = "pass"

    def config_schema(self) -> dict:
        return {
            **_common_config_schema(),
            "env": {
                "description": "Map of ENV_VAR -> pass://SHARE/ITEM/FIELD reference",
                "default": {},
            },
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        parsed = ProtonPassConfig.from_mapping(cfg)
        if not parsed.env_refs:
            return FetchResult(
                error=(
                    "secrets.protonpass has no MODE B env refs. Run "
                    "`hermes protonpass setup`."
                ),
                error_kind=ErrorKind.NOT_CONFIGURED,
            )
        return self._fetch(parsed, home_path, env_refs=dict(parsed.env_refs))


class ProtonPassVaultSource(_ProtonPassSourceBase):
    """Whole-vault export for PAT sessions (bulk precedence)."""

    name = "protonpass_vault"
    label = "Proton Pass Vault"
    shape = "bulk"
    scheme = None

    def config_schema(self) -> dict:
        return {
            **_common_config_schema(),
            "vault": {
                "description": "MODE A vault name to bulk-list with a PAT",
                "default": "",
            },
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        parsed = ProtonPassConfig.from_mapping(cfg)
        if not parsed.vault:
            return FetchResult(
                error=(
                    "secrets.protonpass_vault has no MODE A vault. Run "
                    "`hermes protonpass setup`."
                ),
                error_kind=ErrorKind.NOT_CONFIGURED,
            )
        return self._fetch(parsed, home_path, vault=parsed.vault)


__all__ = [
    "apply_protonpass_secrets",
    "fetch_protonpass_secrets",
    "find_pass_cli",
    "get_pass_cli_version",
    "install_pass_cli",
    "FetchResult",
    "PlanItem",
    "ProtonPassSource",
    "ProtonPassVaultSource",
    "ProtonPassConfig",
    "plan_application",
    "SKIP_ALREADY_SET",
    "SKIP_BOOTSTRAP_TOKEN",
]
