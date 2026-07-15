"""Configuration model for the Proton Pass secret source.

``ProtonPassConfig`` is the single home for the ``secrets.protonpass.*`` config
invariants: parsing, coercion, validation, and the ``env``->``env_refs``
normalization.  Both the env_loader path AND the ``hermes protonpass``
CLI build their config through :meth:`ProtonPassConfig.from_mapping` so the two
agree byte-for-byte on what a given raw config means.

``from_mapping`` is DEFENSIVE: it tolerates garbage (a bare ``True``, the wrong
types, non-numeric TTLs, ...) WITHOUT raising — every field falls back to a
safe default.  This is what lets ``protonpass: true`` in config.yaml never
crash startup.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Tuple

_DEFAULT_SERVICE_TOKEN_ENV = "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
_DEFAULT_CACHE_TTL_SECONDS = 300.0

# ASCII-only POSIX-style env-var name: a leading letter/underscore followed by
# letters/digits/underscores.  Deliberately NOT str.isalpha/isalnum (which
# accept Unicode letters/digits) — an env var name must be pure ASCII because it
# is passed through to the OS environment and consumed as a shell identifier.
# This is the CANONICAL validator: fetch.py imports it from here so the rule
# lives in exactly one place (config imports nothing from the package, so the
# fetch->config edge introduces no import cycle).
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def is_valid_env_name(name: str) -> bool:
    """True iff ``name`` is a valid ASCII env-var name (``^[A-Za-z_][A-Za-z0-9_]*$``).

    ASCII-only by design: a Unicode-letter "name" would be rejected by the OS /
    shell that ultimately consumes it, so a non-ASCII derived (MODE A) or
    configured (MODE B) name is treated as invalid here rather than slipping
    through ``str.isalpha``/``isalnum`` (which accept Unicode).

    ``re.fullmatch`` anchors at the END OF STRING — unlike a trailing ``$``,
    which in Python also matches just before a final newline, so a name like
    ``"FOO\\n"`` is correctly REJECTED.
    """
    return bool(_ENV_NAME_RE.fullmatch(name))


def strip_bootstrap_ref(
    env_refs: Dict[str, str], bootstrap_env: str
) -> Tuple[Dict[str, str], List[str], List[str]]:
    """Remove a MODE B ref whose KEY equals the bootstrap service-token env var.

    Fetching that ref would be wasted work and the planner refuses to APPLY it
    anyway (it must never clobber the token we authenticated with).  This is the
    single home for the fetch-time half of the bootstrap-token invariant, shared
    by ``fetch_protonpass_secrets``, ``apply_protonpass_secrets``, and the CLI
    ``sync`` so all three agree.

    Returns ``(filtered_refs, skipped_names, warnings)``.  When ``bootstrap_env``
    is falsy (no bootstrap configured) the refs are returned unchanged.  A no-op
    (no matching key) yields empty ``skipped``/``warnings`` lists, so calling
    this on already-filtered refs never produces a duplicate warning.
    """
    if not bootstrap_env or bootstrap_env not in env_refs:
        return dict(env_refs), [], []
    filtered = {k: v for k, v in env_refs.items() if k != bootstrap_env}
    warnings = [
        f"Skipping MODE B ref {bootstrap_env!r}: it targets the "
        "bootstrap service-token env var and is never overridden."
    ]
    return filtered, [bootstrap_env], warnings


def strip_bootstrap_refs(
    env_refs: Dict[str, str], bootstrap_names: Iterable[str]
) -> Tuple[Dict[str, str], List[str], List[str]]:
    """Strip MODE B refs whose KEY is in ``bootstrap_names`` (the set form).

    Generalizes :func:`strip_bootstrap_ref` to a SET of protected env-var names
    (the canonical default token env var plus an optional custom one) so the
    fetch-time guard can fail closed on the default even when no explicit
    ``bootstrap_env`` was passed.  Each name that actually matched a ref yields
    exactly ONE warning (so the warning never fires for a name that no ref
    targeted, nor twice for the same name).  Falsy/empty names are ignored.

    Returns ``(filtered_refs, skipped_names, warnings)``.  A no-op (no matching
    keys) yields empty ``skipped``/``warnings`` lists, so calling this on
    already-filtered refs never produces a duplicate warning.
    """
    skipped: List[str] = []
    warnings: List[str] = []
    filtered = dict(env_refs)
    # Deterministic order: sort the actually-present matches so two protected
    # names colliding in one config warn in a stable order.
    for name in sorted(n for n in bootstrap_names if n and n in filtered):
        del filtered[name]
        skipped.append(name)
        warnings.append(
            f"Skipping MODE B ref {name!r}: it targets the "
            "bootstrap service-token env var and is never overridden."
        )
    return filtered, skipped, warnings


def _coerce_bool(value: object, default: bool) -> bool:
    """Coerce an arbitrary config value to a bool, falling back to ``default``."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "1", "on"):
            return True
        if lowered in ("false", "no", "0", "off", ""):
            return False
        return default
    return default


def _coerce_str(value: object, default: str = "") -> str:
    """Coerce a config value to a stripped string, falling back to ``default``.

    These fields (vault, service_token_env) are names/labels — a number or any
    non-string is garbage, so it falls back to the default rather than being
    stringified into a bogus name.
    """
    if isinstance(value, str):
        return value.strip()
    return default


def _coerce_float(value: object, default: float) -> float:
    """Coerce a config value to a float, falling back to ``default`` on garbage.

    A NON-FINITE result (``nan``/``inf``/``-inf``, whether from ``float('inf')``
    in the config or the string ``"nan"``/``"inf"``) is rejected: it would break
    the cache expiry math (``time.time() - fetched_at < ttl`` is always False for
    ``nan`` and meaningless for ``inf``), so fall back to ``default`` instead.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        coerced = float(value)
        return coerced if math.isfinite(coerced) else default
    if isinstance(value, str):
        try:
            coerced = float(value.strip())
        except (ValueError, TypeError):
            return default
        return coerced if math.isfinite(coerced) else default
    return default


def _coerce_env_refs(value: object) -> Dict[str, str]:
    """Coerce the ``env`` config key into a ``{ENV_VAR: pass://...}`` dict.

    Anything that isn't a mapping of str->str is dropped; non-string keys or
    values are skipped individually rather than discarding the whole map.

    A key that isn't a valid ASCII env-var name (``FOO-BAR``, ``1BAD``, a name
    with whitespace) is ALSO dropped: it can never be set as a real OS env var,
    and keeping it would make ``has_fetch_target()`` report True for a ref that
    fetch later skips with a warning.  The key is stripped before validation so
    accidental surrounding whitespace doesn't survive into ``env_refs``.
    """
    if not isinstance(value, Mapping):
        return {}
    refs: Dict[str, str] = {}
    for key, ref in value.items():
        if not isinstance(key, str) or not isinstance(ref, str):
            continue
        stripped = key.strip()
        if not is_valid_env_name(stripped):
            continue
        refs[stripped] = ref
    return refs


@dataclass
class ProtonPassConfig:
    """Parsed + validated ``secrets.protonpass`` configuration.

    The single source of truth for config invariants shared by the env_loader
    and the CLI.  Build it with :meth:`from_mapping`, never by hand from a raw
    config dict — that keeps coercion in exactly one place.
    """

    enabled: bool = False
    service_token_env: str = _DEFAULT_SERVICE_TOKEN_ENV
    vault: str = ""
    env_refs: Dict[str, str] = field(default_factory=dict)
    cache_ttl_seconds: float = _DEFAULT_CACHE_TTL_SECONDS
    override_existing: bool = False
    auto_install: bool = True

    @classmethod
    def from_mapping(cls, mapping: object) -> "ProtonPassConfig":
        """Build a config from a raw mapping, tolerating garbage.

        ``mapping`` is whatever ``config.yaml`` produced under
        ``secrets.protonpass`` — it may be a dict, ``None``, a bool
        (``protonpass: true``), or any other junk.  Non-mapping inputs yield an
        all-defaults (disabled) config.  This NEVER raises.
        """
        if not isinstance(mapping, Mapping):
            # e.g. `protonpass: true` (a bool) or a malformed scalar.  A
            # truthy scalar still can't be "enabled" because there's nothing to
            # fetch, so we return a safe disabled config.
            return cls()

        service_token_env = (
            _coerce_str(mapping.get("service_token_env"), _DEFAULT_SERVICE_TOKEN_ENV)
            or _DEFAULT_SERVICE_TOKEN_ENV
        )
        # A hand-edited config could set an illegal env-var name (``FOO-BAR``,
        # ``1BAD``, a name with a newline).  Such a name can't be a real OS env
        # var, so fall back to the default rather than trusting it downstream
        # (where it would be used as the bootstrap-token key and never match).
        if not is_valid_env_name(service_token_env):
            service_token_env = _DEFAULT_SERVICE_TOKEN_ENV

        return cls(
            enabled=_coerce_bool(mapping.get("enabled"), False),
            service_token_env=service_token_env,
            vault=_coerce_str(mapping.get("vault"), ""),
            env_refs=_coerce_env_refs(mapping.get("env")),
            cache_ttl_seconds=_coerce_float(
                mapping.get("cache_ttl_seconds"), _DEFAULT_CACHE_TTL_SECONDS
            ),
            override_existing=_coerce_bool(mapping.get("override_existing"), False),
            auto_install=_coerce_bool(mapping.get("auto_install"), True),
        )

    def has_fetch_target(self) -> bool:
        """True iff there is anything to fetch (a vault OR at least one ref).

        This is the single no-vault-no-refs invariant: both the loader path and
        the CLI ask this question through one method so ``fetch`` and ``apply``
        agree on what an empty config means.
        """
        return bool(self.vault) or bool(self.env_refs)
