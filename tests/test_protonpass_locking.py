"""Native OS locking tests: plain pytest, no Hermes installation required."""

from __future__ import annotations

import errno
import importlib.util
import multiprocessing
import os
from pathlib import Path
import shutil
import threading

import pytest


def _load_locking():
    # Import the stdlib-only file without running the plugin package __init__.
    path = Path(__file__).resolve().parents[1] / "hermes_protonpass/source/locking.py"
    spec = importlib.util.spec_from_file_location("protonpass_locking", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


locking = _load_locking()


def _holder(path, ready, release):
    with _load_locking().exclusive_file_lock(Path(path), timeout=5):
        ready.set()
        if not release.wait(10):
            raise RuntimeError("Test did not release holder")


@pytest.fixture
def holder(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    path = tmp_path / ".lock"
    process = ctx.Process(target=_holder, args=(str(path), ready, release))
    process.start()
    try:
        assert ready.wait(10), "Child did not acquire lock"
        yield path, process, release
    finally:
        # A deliberately terminated process can leave multiprocessing Event's
        # internal condition locked. Do not touch it after holder-death tests.
        if process.is_alive():
            release.set()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join(5)
        process.close()


def test_other_process_is_excluded_then_can_acquire(holder):
    path, process, release = holder
    with pytest.raises(TimeoutError, match="Timed out"):
        with locking.exclusive_file_lock(path, timeout=0):
            pytest.fail("Another process already holds the lock")
    release.set()
    process.join(10)
    assert process.exitcode == 0
    with locking.exclusive_file_lock(path, timeout=1):
        assert path.exists()


def test_holder_death_releases_os_lock(holder):
    path, process, _release = holder
    process.terminate()
    process.join(10)
    assert process.exitcode is not None
    with locking.exclusive_file_lock(path, timeout=1):
        assert path.exists()


def test_other_token_root_is_independent(holder, tmp_path):
    _path, _process, _release = holder
    root = tmp_path / "different-token"
    root.mkdir()
    with locking.exclusive_file_lock(root / ".lock", timeout=0):
        pass


def test_cleanup_of_nested_session_preserves_exclusion(tmp_path):
    nested = tmp_path / ".session"
    nested.mkdir()
    (nested / "local.key").write_bytes(b"synthetic")
    path = tmp_path / ".lock"
    with locking.exclusive_file_lock(path, timeout=1):
        inode = path.stat().st_ino
        # Mirrors pinned pass-cli get_base_dir + logout --force.
        shutil.rmtree(nested)
        assert path.stat().st_ino == inode
        with pytest.raises(TimeoutError):
            with locking.exclusive_file_lock(path, timeout=0):
                pytest.fail("Cleanup must not create an independent lock")


def test_exception_releases_lock_without_deleting_file(tmp_path):
    path = tmp_path / ".lock"
    with pytest.raises(ValueError, match="synthetic failure"):
        with locking.exclusive_file_lock(path, timeout=1):
            raise ValueError("synthetic failure")
    assert path.exists()
    with locking.exclusive_file_lock(path, timeout=0):
        pass


def test_other_thread_and_unrelated_close_do_not_release_lock(tmp_path):
    path = tmp_path / ".lock"
    outcome = []

    def contender():
        # lockf would release the owning process's lock on this close.
        os.close(os.open(path, os.O_RDWR))
        try:
            with locking.exclusive_file_lock(path, timeout=0):
                outcome.append("acquired")
        except TimeoutError:
            outcome.append("blocked")

    with locking.exclusive_file_lock(path, timeout=1):
        thread = threading.Thread(target=contender)
        thread.start()
        thread.join(5)
        assert not thread.is_alive()
        assert outcome == ["blocked"]


def test_acquisition_timeout_is_monotonic_and_bounded(tmp_path, monkeypatch):
    now = [12.0]
    attempts = []
    closed = []
    real_close = os.close

    def contention(fd):
        attempts.append(fd)
        raise OSError(errno.EACCES, "synthetic contention")

    def close(fd):
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(locking, "_try_lock", contention)
    monkeypatch.setattr(locking.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        locking.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay)
    )
    monkeypatch.setattr(locking.os, "close", close)
    with pytest.raises(TimeoutError, match="Timed out"):
        with locking.exclusive_file_lock(tmp_path / ".lock", timeout=0.2):
            pytest.fail("Acquisition should time out")
    assert now[0] == pytest.approx(12.2)
    assert len(closed) == 1
    assert closed[0] == attempts[0]


@pytest.mark.parametrize("failure_phase", ["acquire", "unlock"])
def test_descriptor_closes_after_os_failure(tmp_path, monkeypatch, failure_phase):
    descriptors = []
    original = getattr(
        locking, "_try_lock" if failure_phase == "acquire" else "_unlock"
    )

    def fail(fd):
        descriptors.append(fd)
        if failure_phase == "unlock":
            original(fd)
        raise OSError(errno.EIO, "synthetic IO failure")

    monkeypatch.setattr(
        locking, "_try_lock" if failure_phase == "acquire" else "_unlock", fail
    )
    with pytest.raises(OSError, match="synthetic IO failure"):
        with locking.exclusive_file_lock(tmp_path / ".lock", timeout=1):
            pass
    with pytest.raises(OSError) as caught:
        os.fstat(descriptors[0])
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize("timeout", [-1, float("inf"), float("nan")])
def test_invalid_timeout_rejected_before_open(tmp_path, timeout):
    path = tmp_path / ".lock"
    with pytest.raises(ValueError):
        with locking.exclusive_file_lock(path, timeout=timeout):
            pass
    assert not path.exists()


@pytest.mark.skipif(
    os.name == "nt", reason="Creating symlinks needs Windows privileges"
)
def test_symlink_lock_file_rejected(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    path = tmp_path / ".lock"
    path.symlink_to(target)
    with pytest.raises(OSError, match="symlink"):
        with locking.exclusive_file_lock(path, timeout=0):
            pass
    assert target.read_bytes() == b"untouched"
