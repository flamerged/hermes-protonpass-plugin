"""Tests for ``hermes_protonpass.source.config.ProtonPassConfig``.

``from_mapping`` is defensive: garbage in (a bare ``True``, wrong types,
non-numeric TTLs) never raises and falls back to safe defaults.  Also covers the
bool coercion (B9 — ``"false"`` must disable, not enable) and the
``has_fetch_target()`` invariant shared by fetch/apply/CLI.
"""

from __future__ import annotations

from _protonpass_helpers import (  # noqa: F401
    _reset_caches,
    pp_config,
)


def test_config_from_bool_does_not_raise_and_disables():
    # `protonpass: true` in config.yaml is a bool, not a mapping.
    cfg = pp_config.ProtonPassConfig.from_mapping(True)
    assert cfg.enabled is False
    assert cfg.vault == ""
    assert cfg.env_refs == {}
    assert not cfg.has_fetch_target()


def test_config_from_none_is_defaults():
    cfg = pp_config.ProtonPassConfig.from_mapping(None)
    assert cfg.enabled is False
    assert cfg.service_token_env == "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
    assert cfg.cache_ttl_seconds == 300.0
    assert cfg.auto_install is True


def test_config_coerces_wrong_types():
    cfg = pp_config.ProtonPassConfig.from_mapping(
        {
            "enabled": "yes",
            "service_token_env": 123,  # wrong type → default
            "vault": ["not", "a", "string"],  # wrong type → ""
            "env": "not-a-dict",  # wrong type → {}
            "cache_ttl_seconds": "not-a-number",  # garbage → default
            "override_existing": 1,
            "auto_install": "false",
        }
    )
    assert cfg.enabled is True
    assert cfg.service_token_env == "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
    assert cfg.vault == ""
    assert cfg.env_refs == {}
    assert cfg.cache_ttl_seconds == 300.0
    assert cfg.override_existing is True
    assert cfg.auto_install is False


def test_config_env_refs_drops_non_string_entries():
    cfg = pp_config.ProtonPassConfig.from_mapping(
        {
            "enabled": True,
            "env": {
                "GOOD": "pass://S/I/f",
                123: "pass://x",  # non-str key → dropped
                "BAD": 456,  # non-str value → dropped
            },
        }
    )
    assert cfg.env_refs == {"GOOD": "pass://S/I/f"}
    assert cfg.has_fetch_target()


def test_config_has_fetch_target():
    assert pp_config.ProtonPassConfig.from_mapping({"vault": "V"}).has_fetch_target()
    assert pp_config.ProtonPassConfig.from_mapping(
        {"env": {"X": "pass://S/I/f"}}
    ).has_fetch_target()
    assert not pp_config.ProtonPassConfig.from_mapping(
        {"enabled": True}
    ).has_fetch_target()


# ---------------------------------------------------------------------------
# enabled bool coercion (B9): a STRING "false" must DISABLE, not enable
# ---------------------------------------------------------------------------


def test_config_enabled_string_false_disables():
    """B9: ``enabled: "false"`` (a truthy bare str) must be coerced to False."""
    cfg = pp_config.ProtonPassConfig.from_mapping({"enabled": "false", "vault": "V"})
    assert cfg.enabled is False


def test_config_enabled_string_truthy_variants_enable():
    for raw in ("true", "yes", "1", "on", "True", " YES "):
        cfg = pp_config.ProtonPassConfig.from_mapping({"enabled": raw})
        assert cfg.enabled is True, raw


def test_config_enabled_string_falsey_variants_disable():
    for raw in ("false", "no", "0", "off", "", "False", " no "):
        cfg = pp_config.ProtonPassConfig.from_mapping({"enabled": raw})
        assert cfg.enabled is False, raw


def test_config_enabled_unknown_string_defaults_false():
    # An ambiguous string never silently turns the source ON.
    cfg = pp_config.ProtonPassConfig.from_mapping({"enabled": "maybe"})
    assert cfg.enabled is False


def test_coerce_bool_helper_directly():
    assert pp_config._coerce_bool("false", True) is False
    assert pp_config._coerce_bool("true", False) is True
    assert pp_config._coerce_bool(None, True) is True
    assert pp_config._coerce_bool(0, True) is False
    assert pp_config._coerce_bool("weird", True) is True  # unknown → default


# ---------------------------------------------------------------------------
# C3 — service_token_env is validated at the config boundary
# ---------------------------------------------------------------------------


def test_config_invalid_service_token_env_falls_back_to_default():
    """C3: a hand-edited config with an illegal env-var name for
    ``service_token_env`` (a dash, a leading digit) must fall back to the default
    rather than trusting an unusable name downstream."""
    cfg = pp_config.ProtonPassConfig.from_mapping(
        {
            "service_token_env": "BAD-NAME",
            "vault": "V",
        }
    )
    assert cfg.service_token_env == "PROTON_PASS_PERSONAL_ACCESS_TOKEN"

    cfg = pp_config.ProtonPassConfig.from_mapping(
        {
            "service_token_env": "1BAD",
            "vault": "V",
        }
    )
    assert cfg.service_token_env == "PROTON_PASS_PERSONAL_ACCESS_TOKEN"


def test_config_valid_service_token_env_kept():
    cfg = pp_config.ProtonPassConfig.from_mapping(
        {
            "service_token_env": "MY_PROTON_TOKEN",
            "vault": "V",
        }
    )
    assert cfg.service_token_env == "MY_PROTON_TOKEN"


# ---------------------------------------------------------------------------
# C4 — env-name validator anchors at end-of-string (re.fullmatch, not `$`)
# ---------------------------------------------------------------------------


def test_is_valid_env_name_basic():
    assert pp_config.is_valid_env_name("OPENAI_API_KEY")
    assert pp_config.is_valid_env_name("_X1")
    assert not pp_config.is_valid_env_name("1LEADING")
    assert not pp_config.is_valid_env_name("HAS-DASH")
    assert not pp_config.is_valid_env_name("")


def test_is_valid_env_name_rejects_trailing_newline():
    """C4: a trailing ``$`` matches before a final newline in Python, so the old
    anchoring wrongly accepted ``"FOO\\n"``.  ``re.fullmatch`` rejects it."""
    assert not pp_config.is_valid_env_name("FOO\n")
    assert not pp_config.is_valid_env_name("FOO\nBAR")


def test_config_service_token_env_with_newline_falls_back():
    """C3+C4: a service_token_env with an embedded newline is illegal and falls
    back to the default."""
    cfg = pp_config.ProtonPassConfig.from_mapping(
        {
            "service_token_env": "FOO\nBAR",
            "vault": "V",
        }
    )
    assert cfg.service_token_env == "PROTON_PASS_PERSONAL_ACCESS_TOKEN"


# ---------------------------------------------------------------------------
# C1 — strip_bootstrap_ref: the single home for the MODE B bootstrap filter
# ---------------------------------------------------------------------------


def test_strip_bootstrap_ref_removes_matching_key():
    refs = {"BOOT": "pass://S/I/token", "OTHER": "pass://S/I/f"}
    filtered, skipped, warnings = pp_config.strip_bootstrap_ref(refs, "BOOT")
    assert filtered == {"OTHER": "pass://S/I/f"}
    assert skipped == ["BOOT"]
    assert len(warnings) == 1
    assert "BOOT" in warnings[0]
    # The original mapping is not mutated.
    assert "BOOT" in refs


def test_strip_bootstrap_ref_noop_when_absent():
    refs = {"OTHER": "pass://S/I/f"}
    filtered, skipped, warnings = pp_config.strip_bootstrap_ref(refs, "BOOT")
    assert filtered == refs
    assert skipped == []
    assert warnings == []


def test_strip_bootstrap_ref_noop_when_bootstrap_empty():
    refs = {"OTHER": "pass://S/I/f"}
    filtered, skipped, warnings = pp_config.strip_bootstrap_ref(refs, "")
    assert filtered == refs
    assert skipped == []
    assert warnings == []


# ---------------------------------------------------------------------------
# strip_bootstrap_refs (plural / set form) — V8-B fail-closed helper
# ---------------------------------------------------------------------------


def test_strip_bootstrap_refs_removes_each_matching_key_once():
    refs = {"BOOT": "pass://S/I/t", "DEF": "pass://S/I/d", "OTHER": "pass://S/I/f"}
    filtered, skipped, warnings = pp_config.strip_bootstrap_refs(refs, {"BOOT", "DEF"})
    assert filtered == {"OTHER": "pass://S/I/f"}
    assert sorted(skipped) == ["BOOT", "DEF"]
    # Exactly one warning per matched name — never twice, never for OTHER.
    assert len(warnings) == 2
    assert any("BOOT" in w for w in warnings)
    assert any("DEF" in w for w in warnings)
    # The original mapping is not mutated.
    assert "BOOT" in refs


def test_strip_bootstrap_refs_ignores_unmatched_and_falsy_names():
    refs = {"OTHER": "pass://S/I/f"}
    # A name no ref targets (and an empty name) yields no warning / no skip.
    filtered, skipped, warnings = pp_config.strip_bootstrap_refs(
        refs, {"NOT_PRESENT", ""}
    )
    assert filtered == refs
    assert skipped == []
    assert warnings == []


def test_strip_bootstrap_refs_no_double_warning_on_prefiltered():
    # Already-filtered refs + the set must not produce a spurious warning.
    refs = {"OPENAI_API_KEY": "pass://S/I/f"}
    _filtered, skipped, warnings = pp_config.strip_bootstrap_refs(
        refs, {"PROTON_PASS_PERSONAL_ACCESS_TOKEN", "PROTON_TOKEN"}
    )
    assert skipped == []
    assert warnings == []


# ---------------------------------------------------------------------------
# V8-C — non-finite cache TTL falls back to the default (breaks expiry math)
# ---------------------------------------------------------------------------


def test_config_cache_ttl_non_finite_string_falls_back():
    """V8-C: ``"nan"``/``"inf"`` strings parse to a non-finite float that breaks
    cache expiry math, so they must fall back to the 300.0 default."""
    for raw in ("nan", "inf", "-inf", "Infinity", "NaN"):
        cfg = pp_config.ProtonPassConfig.from_mapping({"cache_ttl_seconds": raw})
        assert cfg.cache_ttl_seconds == 300.0, raw


def test_config_cache_ttl_non_finite_float_falls_back():
    """V8-C: a literal ``float('inf')`` / ``float('nan')`` in the mapping is
    likewise rejected in favor of the default."""
    cfg = pp_config.ProtonPassConfig.from_mapping({"cache_ttl_seconds": float("inf")})
    assert cfg.cache_ttl_seconds == 300.0
    cfg = pp_config.ProtonPassConfig.from_mapping({"cache_ttl_seconds": float("nan")})
    assert cfg.cache_ttl_seconds == 300.0
    cfg = pp_config.ProtonPassConfig.from_mapping({"cache_ttl_seconds": float("-inf")})
    assert cfg.cache_ttl_seconds == 300.0


def test_config_cache_ttl_finite_value_kept():
    """A finite numeric TTL still passes through unchanged."""
    cfg = pp_config.ProtonPassConfig.from_mapping({"cache_ttl_seconds": 42})
    assert cfg.cache_ttl_seconds == 42.0
    cfg = pp_config.ProtonPassConfig.from_mapping({"cache_ttl_seconds": "0"})
    assert cfg.cache_ttl_seconds == 0.0


# ---------------------------------------------------------------------------
# V8-D — env-ref normalization drops keys that aren't valid env-var names
# ---------------------------------------------------------------------------


def test_config_env_refs_drops_invalid_env_name_keys():
    """V8-D: a key that isn't a valid ASCII env-var name (a dash, a leading
    digit, whitespace) is dropped so it can't make ``has_fetch_target()`` lie
    about a ref fetch would later skip.  Valid keys survive (and are stripped)."""
    cfg = pp_config.ProtonPassConfig.from_mapping(
        {
            "enabled": True,
            "env": {
                "GOOD": "pass://S/I/f",
                "FOO-BAR": "pass://S/I/bad",  # dash → dropped
                "1BAD": "pass://S/I/bad",  # leading digit → dropped
                "HAS SPACE": "pass://S/I/bad",  # whitespace → dropped
                "  PADDED  ": "pass://S/I/p",  # stripped to a valid name → kept
            },
        }
    )
    assert cfg.env_refs == {
        "GOOD": "pass://S/I/f",
        "PADDED": "pass://S/I/p",
    }
    assert cfg.has_fetch_target()
