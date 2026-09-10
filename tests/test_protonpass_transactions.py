"""Session transaction tests with synthetic CLI responses; no live credentials."""

from __future__ import annotations

from contextlib import contextmanager
import multiprocessing
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from _protonpass_helpers import (  # noqa: F401
    _patch_run,
    _reset_caches,
    hermes_home,
    pp,
    pp_cache,
    pp_fetch,
    pp_session,
)
from hermes_protonpass.source.locking import exclusive_file_lock


MISSING = "This operation requires an authenticated client"
INVALID = (
    "Your session has been invalidated and you have been logged out automatically."
)
REFS = {"A_KEY": "pass://SHARE/ITEM/a", "B_KEY": "pass://SHARE/ITEM/b"}


def _result(*, stderr="", value="synthetic-value"):
    return SimpleNamespace(returncode=1 if stderr else 0, stdout=value, stderr=stderr)


def _assert_transaction_held(env):
    with pytest.raises(TimeoutError):
        with exclusive_file_lock(
            Path(env["PROTON_PASS_SESSION_DIR"]) / ".lock", timeout=0
        ):
            pytest.fail("A CLI command ran outside its session transaction")


def _fetch(home, *, token="synthetic-token", use_cache=False, **kwargs):
    return pp.fetch_protonpass_secrets(
        service_token=token,
        env_refs=REFS,
        binary=home / "synthetic-pass-cli",
        use_cache=use_cache,
        home_path=home,
        **kwargs,
    )


@pytest.mark.parametrize("marker", [MISSING, INVALID, "\x1b[31m" + MISSING + "\x1b[0m"])
def test_retry_remains_locked_and_does_not_expose_failed_stdout(
    hermes_home, monkeypatch, marker
):
    calls = []

    def run(cmd, env):
        _assert_transaction_held(env)
        calls.append(cmd[1])
        if cmd[1] == "item" and calls.count("item") == 1:
            return _result(stderr=marker, value="FAILED-SECRET-STDOUT")
        return _result()

    _patch_run(monkeypatch, run)
    secrets, warnings = _fetch(hermes_home)
    assert secrets == {"A_KEY": "synthetic-value", "B_KEY": "synthetic-value"}
    assert calls == ["login", "info", "item", "logout", "login", "info", "item", "item"]
    assert "FAILED-SECRET-STDOUT" not in str(warnings)
    assert len(warnings) == 1


@pytest.mark.parametrize(
    "error",
    [
        "Error getting item key",
        "Error getting local key",
        "Error serializing auth",
        "Error getting opened share key",
        "permission denied",
        "network failure",
        "",
    ],
)
def test_unrelated_errors_and_transport_failure_do_not_reauthenticate(
    hermes_home, monkeypatch, error
):
    calls = []

    def run(cmd, env):
        calls.append(cmd[1])
        if cmd[1] == "item":
            return _result(stderr=error) if error else None
        return _result()

    _patch_run(monkeypatch, run)
    secrets, warnings = _fetch(hermes_home, use_cache=True)
    assert secrets == {}
    assert len(warnings) == 2
    assert calls == ["login", "info", "item", "item"]
    assert pp_fetch._CACHE == {}
    assert not pp_cache._disk_cache_path(hermes_home).exists()


@pytest.mark.parametrize("initial_recovery", [True, False])
def test_one_recovery_budget_for_establishment_and_all_refs(
    hermes_home, monkeypatch, initial_recovery
):
    calls = []

    def run(cmd, env):
        _assert_transaction_held(env)
        calls.append(cmd[1])
        if initial_recovery and calls == ["login"]:
            return _result(stderr=MISSING)
        if cmd[1] == "item":
            return _result(stderr=INVALID)
        return _result()

    _patch_run(monkeypatch, run)
    secrets, warnings = _fetch(hermes_home, use_cache=True)
    assert secrets == {}
    assert calls.count("logout") == 1
    assert calls.count("login") == 2
    assert calls.count("item") == (2 if initial_recovery else 3)
    assert pp_fetch._CACHE == {}
    assert warnings


def test_vault_and_refs_share_recovery_budget(hermes_home, monkeypatch):
    calls = []

    def run(cmd, env):
        _assert_transaction_held(env)
        verb = cmd[2] if cmd[1] == "item" else cmd[1]
        calls.append(verb)
        if verb == "list":
            if calls.count("list") == 1:
                return _result(stderr=MISSING)
            return _result(
                value='{"items": [{"content": {"title": "K", "content": {"Login": {"password": "v"}}}}]}'
            )
        if verb == "view":
            return _result(stderr=INVALID)
        return _result()

    _patch_run(monkeypatch, run)
    secrets, warnings = _fetch(hermes_home, vault="Personal", use_cache=True)
    assert secrets == {"K_PASSWORD": "v"}
    assert calls.count("logout") == 1
    assert calls.count("list") == 2
    assert calls.count("view") == 2
    assert any("A_KEY" in w for w in warnings)
    assert pp_fetch._CACHE == {}


def test_failed_recovery_does_not_repeat_or_leak_token(hermes_home, monkeypatch):
    calls = []

    def run(cmd, env):
        calls.append(cmd[1])
        if cmd[1] == "login" and calls.count("login") > 1:
            return _result(stderr="bad token synthetic-token", value="FAILED-SECRET")
        if cmd[1] == "item":
            return _result(stderr=MISSING + " synthetic-token", value="FAILED-SECRET")
        return _result()

    _patch_run(monkeypatch, run)
    secrets, warnings = _fetch(hermes_home, use_cache=True)
    assert secrets == {}
    assert calls.count("logout") == 1
    assert calls.count("login") == 2
    assert "synthetic-token" not in str(warnings)
    assert "FAILED-SECRET" not in str(warnings)
    assert pp_fetch._CACHE == {}


def test_source_lock_timeout_is_fail_open(hermes_home, monkeypatch):
    from agent.secret_sources.base import ErrorKind

    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "synthetic-token")
    monkeypatch.setattr(
        pp, "find_pass_cli", lambda **kwargs: hermes_home / "synthetic-pass-cli"
    )
    monkeypatch.setattr(pp_session, "_SESSION_LOCK_TIMEOUT", 0)
    with pp_session._session_lock("synthetic-token"):
        result = pp.ProtonPassSource().fetch({"env": REFS}, hermes_home)
    assert result.error_kind == ErrorKind.TIMEOUT
    assert result.secrets == {}
    assert "synthetic-token" not in result.error


def test_error_releases_transaction_and_cache_hit_avoids_it(hermes_home, monkeypatch):
    def fail(cmd, env):
        raise RuntimeError("synthetic command failure")

    _patch_run(monkeypatch, fail)
    with pytest.raises(RuntimeError, match="synthetic command failure"):
        _fetch(hermes_home)
    _patch_run(monkeypatch, lambda cmd, env: _result())
    expected = _fetch(hermes_home, use_cache=True)

    def forbidden(token):
        pytest.fail("A fresh cache hit must not acquire the session lock")

    monkeypatch.setattr(pp_fetch, "_session_lock", forbidden)
    assert _fetch(hermes_home, use_cache=True) == expected


def _transaction_worker(home, token, label, mode, attempted, held, release, messages):
    """Spawned process with fake CLI and real filesystem/cache/OS locks."""
    os.environ["HERMES_HOME"] = home
    import hermes_constants

    hermes_constants._HERMES_HOME_CACHE = None
    pp_fetch._CACHE.clear()
    original_lock = pp_fetch._session_lock
    calls = []

    @contextmanager
    def announce_lock(value):
        attempted.set()
        with original_lock(value):
            yield

    def run(cmd, env):
        _assert_transaction_held(env)
        verb = cmd[1]
        calls.append(verb)
        messages.put((label, "command", verb))
        nested = Path(env["PROTON_PASS_SESSION_DIR"]) / ".session"
        if verb == "login":
            nested.mkdir(exist_ok=True)
            (nested / "local.key").write_bytes(b"synthetic")
        if verb == "logout" and nested.exists():
            shutil.rmtree(nested)
        if verb == "item" and label == "first":
            if mode == "recovery" and calls.count("item") == 1:
                shutil.rmtree(nested)
                return _result(stderr=INVALID)
            if not held.is_set():
                held.set()
                if not release.wait(10):
                    raise RuntimeError("Test did not release in-flight fetch")
        return _result()

    pp_fetch._session_lock = announce_lock
    pp_fetch._run_pass_cli = run
    pp_session._run_pass_cli = run
    result = _fetch(Path(home), token=token, use_cache=mode == "cache")
    messages.put((label, "result", result))


@pytest.mark.parametrize("mode", ["cache", "recovery", "different-token"])
def test_concurrent_transactions(hermes_home, mode):
    ctx = multiprocessing.get_context("spawn")
    first_attempted, second_attempted, held, release = [ctx.Event() for _ in range(4)]
    messages = ctx.Queue()
    processes = []
    tokens = [
        "synthetic-token",
        "other-token" if mode == "different-token" else "synthetic-token",
    ]
    for index, (label, attempted) in enumerate(
        zip(["first", "second"], [first_attempted, second_attempted])
    ):
        processes.append(
            ctx.Process(
                target=_transaction_worker,
                args=(
                    str(hermes_home),
                    tokens[index],
                    label,
                    mode,
                    attempted,
                    held,
                    release,
                    messages,
                ),
            )
        )
    first, second = processes
    try:
        first.start()
        assert held.wait(10), "First process did not reach its protected fetch"
        second.start()
        assert second_attempted.wait(10), (
            "Second process did not attempt the transaction"
        )
        events = []
        results = {}

        def receive():
            label, kind, value = messages.get(timeout=5)
            if kind == "result":
                results[label] = value
            else:
                events.append((label, value))

        if mode == "different-token":
            # A distinct token completes while the first is still held.
            while "second" not in results:
                receive()
            assert first.is_alive()
        release.set()
        # Drain before join: a child's queue feeder must not block its exit
        # waiting for pipe space while the parent waits for that same exit.
        while len(results) < 2:
            receive()
        for process in processes:
            process.join(10)
            assert process.exitcode == 0
        for secrets, _warnings in results.values():
            assert secrets == {"A_KEY": "synthetic-value", "B_KEY": "synthetic-value"}
        if mode == "cache":
            assert events == [
                ("first", verb) for verb in ["login", "info", "item", "item"]
            ]
        elif mode == "recovery":
            assert events == [
                ("first", verb)
                for verb in [
                    "login",
                    "info",
                    "item",
                    "logout",
                    "login",
                    "info",
                    "item",
                    "item",
                ]
            ] + [("second", verb) for verb in ["login", "info", "item", "item"]]
    finally:
        release.set()
        for process in processes:
            if process.pid is None:
                continue
            process.join(5)
            if process.is_alive():
                process.terminate()
                process.join(5)
            process.close()
        messages.close()
        messages.join_thread()
