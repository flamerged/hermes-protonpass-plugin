"""Shared fixtures + helpers for the Proton Pass (`pass-cli`) test modules.

The monolithic ``test_protonpass_secrets.py`` was split into per-module files
(install / session / fetch / cache / config / apply) so each stays focused and
well under 1000 lines.  Everything those files share lives here:

* the project-root ``sys.path`` shim and the package re-export imports
  (``pp`` plus the six submodules monkeypatched at the point of use);
* the autouse cache-reset fixture and the isolated ``hermes_home`` fixture;
* the ``_run_pass_cli`` fakes and the small response-sequencing helpers.

This is a plain importable module (NOT a ``conftest.py``): each test file does
``from _protonpass_helpers import hermes_home, _reset_caches, ...``.  An
autouse fixture imported into a test module's namespace still auto-applies, so
importing ``_reset_caches`` is enough to get per-test cache flushing.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest


# Make the worktree importable without depending on the installed wheel.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hermes_protonpass import source as pp  # noqa: E402
from hermes_protonpass.source import apply as pp_apply  # noqa: E402
from hermes_protonpass.source import cache as pp_cache  # noqa: E402
from hermes_protonpass.source import config as pp_config  # noqa: E402
from hermes_protonpass.source import fetch as pp_fetch  # noqa: E402
from hermes_protonpass.source import install as pp_install  # noqa: E402
from hermes_protonpass.source import session as pp_session  # noqa: E402

__all__ = [
    "pp",
    "pp_apply",
    "pp_cache",
    "pp_config",
    "pp_fetch",
    "pp_install",
    "pp_session",
    "hermes_home",
    "_reset_caches",
    "_patch_run",
    "_ok",
    "_fail",
    "_session_runner",
    "_vault_runner",
    "_SIMPLE_VAULT",
]


# ---------------------------------------------------------------------------
# Fixtures (autouse cache reset + isolated home)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_caches():
    pp._reset_cache_for_tests()
    yield
    pp._reset_cache_for_tests()


@pytest.fixture
def hermes_home(tmp_path, monkeypatch):
    """Point Hermes at an isolated home directory."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    # Some modules cache get_hermes_home; clear if needed.
    import hermes_constants

    if hasattr(hermes_constants, "_HERMES_HOME_CACHE"):
        hermes_constants._HERMES_HOME_CACHE = None  # type: ignore[attr-defined]
    pp._reset_cache_for_tests(home)
    return home


# ---------------------------------------------------------------------------
# _run_pass_cli fakes shared by session / fetch / apply / cache tests
# ---------------------------------------------------------------------------


def _patch_run(monkeypatch, fake):
    """Patch ``_run_pass_cli`` in BOTH the session and fetch modules.

    Session establishment (login/info/logout) goes through
    ``session._run_pass_cli`` while MODE A/B fetches go through
    ``fetch._run_pass_cli``; a test fake handles every verb, so we wire it into
    both namespaces.
    """
    monkeypatch.setattr(pp_session, "_run_pass_cli", fake)
    monkeypatch.setattr(pp_fetch, "_run_pass_cli", fake)


def _ok():
    return mock.Mock(returncode=0, stdout="", stderr="")


def _fail(stderr="boom"):
    return mock.Mock(returncode=1, stdout="", stderr=stderr)


def _session_runner(monkeypatch, responses, *, calls=None, target=pp_session):
    """Drive _run_pass_cli responses keyed on the pass-cli subcommand.

    ``responses`` maps a subcommand verb (login/info/logout/view/list) to a
    list of CompletedProcess-like results consumed in order; missing verbs
    default to a success.  ``_run_pass_cli`` now takes (cmd, env) — no token.
    """
    counters = {k: 0 for k in responses}

    def fake_run(cmd, env):
        if calls is not None:
            calls.append((cmd, env))
        verb = cmd[1] if len(cmd) > 1 else cmd[-1]
        seq = responses.get(verb)
        if seq is None:
            return _ok()
        idx = min(counters[verb], len(seq) - 1)
        counters[verb] += 1
        return seq[idx]

    monkeypatch.setattr(target, "_run_pass_cli", fake_run)


_SIMPLE_VAULT = __import__("json").dumps(
    {"items": [{"content": {"title": "K", "content": {"Login": {"password": "v"}}}}]}
)


def _vault_runner(monkeypatch, payload, counter):
    def fake_run(cmd, env):
        verb = cmd[1]
        if verb in ("login", "info"):
            return _ok()
        if verb == "item":
            counter["n"] += 1
            return mock.Mock(returncode=0, stdout=payload, stderr="")
        return _ok()

    _patch_run(monkeypatch, fake_run)
