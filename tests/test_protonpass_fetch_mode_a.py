"""MODE A (vault list -> env vars) parsing tests for
``hermes_protonpass.source.fetch``.

* V6 — a MODE A bad/garbage-JSON list call (exit 0) degrades to a warning and
  does NOT abort MODE B refs in a combined config.

Split out of the former monolithic ``test_protonpass_fetch.py`` (>1000 lines);
the MODE B and C1-bootstrap/V8-B sections live in sibling modules.  Shared
fixtures/helpers come from ``tests._protonpass_helpers`` (do NOT duplicate them).
"""

from __future__ import annotations

import json
from unittest import mock

from _protonpass_helpers import (  # noqa: F401
    _ok,
    _patch_run,
    _reset_caches,
    hermes_home,
    pp,
)


# ---------------------------------------------------------------------------
# MODE A — vault list parsing
# ---------------------------------------------------------------------------


def _mode_a_payload():
    return json.dumps(
        {
            "items": [
                {
                    "content": {
                        "title": "Probe Login",
                        "content": {
                            "Login": {
                                "username": "alice",
                                "password": "s3cret",
                                "urls": ["https://example.com"],  # list → skipped
                                "totp_uri": "",  # empty → skipped
                            }
                        },
                        "extra_fields": [
                            {"name": "API Key", "content": {"Text": "key-123"}},
                            {"name": "Empty", "content": {"Text": ""}},
                        ],
                    }
                },
                {
                    # No title → entire item skipped.
                    "content": {"content": {"Login": {"password": "ignored"}}}
                },
            ]
        }
    )


def test_mode_a_parse_and_env_names(hermes_home, monkeypatch, tmp_path):
    binary = tmp_path / "pass-cli"
    binary.write_text("", encoding="utf-8")

    captured = []

    def fake_run(cmd, env):
        captured.append(cmd)
        verb = cmd[1]
        if verb in ("login", "info"):
            return _ok()
        if verb == "item":
            return mock.Mock(returncode=0, stdout=_mode_a_payload(), stderr="")
        return _ok()

    _patch_run(monkeypatch, fake_run)

    secrets, warnings = pp.fetch_protonpass_secrets(
        service_token="svc",
        vault="My Vault",
        binary=binary,
        use_cache=False,
        home_path=hermes_home,
    )

    assert secrets == {
        "PROBE_LOGIN_USERNAME": "alice",
        "PROBE_LOGIN_PASSWORD": "s3cret",
        "PROBE_LOGIN_API_KEY": "key-123",
    }
    # urls (list), empty totp, empty extra field all skipped silently.
    assert warnings == []
    # The list command shape is correct.
    list_cmd = [c for c in captured if len(c) > 1 and c[1] == "item"][0]
    assert "list" in list_cmd
    assert "My Vault" in list_cmd
    assert "--show-secrets" in list_cmd
    assert "--output" in list_cmd and "json" in list_cmd


def test_mode_a_show_secrets_rejection_warns_no_crash(
    hermes_home, monkeypatch, tmp_path
):
    binary = tmp_path / "pass-cli"
    binary.write_text("", encoding="utf-8")

    def fake_run(cmd, env):
        verb = cmd[1]
        if verb in ("login", "info"):
            return _ok()
        if verb == "item":
            return mock.Mock(
                returncode=2,
                stdout="",
                stderr="error: --show-secrets not permitted under agent session",
            )
        return _ok()

    _patch_run(monkeypatch, fake_run)

    secrets, warnings = pp.fetch_protonpass_secrets(
        service_token="svc",
        vault="Scoped",
        binary=binary,
        use_cache=False,
        home_path=hermes_home,
    )
    assert secrets == {}
    assert len(warnings) == 1
    assert "Scoped" in warnings[0]


def test_mode_a_invalid_json_degrades_not_raises(hermes_home, monkeypatch, tmp_path):
    """V6: MODE A garbage JSON on an exit-0 list call degrades to a warning +
    skip — it must NOT raise out of fetch (that would abort a combined config's
    independent MODE B refs)."""
    binary = tmp_path / "pass-cli"
    binary.write_text("", encoding="utf-8")

    def fake_run(cmd, env):
        verb = cmd[1]
        if verb in ("login", "info"):
            return _ok()
        return mock.Mock(returncode=0, stdout="not json at all", stderr="")

    _patch_run(monkeypatch, fake_run)

    secrets, warnings = pp.fetch_protonpass_secrets(
        service_token="svc",
        vault="V",
        binary=binary,
        use_cache=False,
        home_path=hermes_home,
    )
    assert secrets == {}
    assert len(warnings) == 1
    assert "non-JSON" in warnings[0]
    assert "V" in warnings[0]


def test_mode_a_bad_shape_degrades_not_raises(hermes_home, monkeypatch, tmp_path):
    """V6: a valid-JSON-but-wrong-shape MODE A payload (a bare list/scalar that
    isn't ``{"items": [...]}`` or a top-level list) also degrades, not raises."""
    binary = tmp_path / "pass-cli"
    binary.write_text("", encoding="utf-8")

    def fake_run(cmd, env):
        verb = cmd[1]
        if verb in ("login", "info"):
            return _ok()
        # Valid JSON, but a scalar — neither a dict wrapper nor a list.
        return mock.Mock(returncode=0, stdout=json.dumps("a string"), stderr="")

    _patch_run(monkeypatch, fake_run)

    secrets, warnings = pp.fetch_protonpass_secrets(
        service_token="svc",
        vault="V",
        binary=binary,
        use_cache=False,
        home_path=hermes_home,
    )
    assert secrets == {}
    assert len(warnings) == 1
    assert "unexpected shape" in warnings[0]


def test_mode_a_garbage_json_still_resolves_mode_b_refs(
    hermes_home, monkeypatch, tmp_path
):
    """V6 (the real bug): a combined ``vault:`` + ``env:`` config whose MODE A
    list returns exit-0 garbage JSON must STILL resolve the independent MODE B
    refs — the MODE A failure no longer aborts the fetch."""
    binary = tmp_path / "pass-cli"
    binary.write_text("", encoding="utf-8")

    def fake_run(cmd, env):
        verb = cmd[1]
        if verb in ("login", "info"):
            return _ok()
        if verb == "item" and "list" in cmd:
            # MODE A: exit-0 but garbage JSON.
            return mock.Mock(returncode=0, stdout="<<not json>>", stderr="")
        if verb == "item" and "view" in cmd:
            # MODE B: a healthy ref resolution.
            return mock.Mock(returncode=0, stdout="ref-value\n", stderr="")
        return _ok()

    _patch_run(monkeypatch, fake_run)

    secrets, warnings = pp.fetch_protonpass_secrets(
        service_token="svc",
        vault="V",
        env_refs={"OPENAI_API_KEY": "pass://SHARE/ITEM/api_key"},
        binary=binary,
        use_cache=False,
        home_path=hermes_home,
    )
    # The MODE B ref resolved despite MODE A's garbage JSON.
    assert secrets == {"OPENAI_API_KEY": "ref-value"}
    # And the MODE A failure surfaced as a (single) warning, not an exception.
    assert any("non-JSON" in w and "V" in w for w in warnings)
