"""Tests for ``hermes_protonpass.source.install``.

Covers binary discovery (``find_pass_cli``), the pinned-hash + version-gated
lazy install (``install_pass_cli``), the managed-binary re-verification added in
v2 (A1/A2/A3/A4/A5), the pinned-SHA-256 table, the zip-slip defence, and the
HTTP download size cap.  We never hit the network or a real ``pass-cli`` binary.

v3 round:
* V3 — a PATH binary is handed the token ONLY when its SHA-256 matches a pinned
  asset digest (``_path_binary_trusted``); a version-only match is spoofable, so
  a non-pinned-hash PATH binary FAILS CLOSED and is never returned for token use
  (and the Windows zip platform can't hash-verify a PATH exe at all).
"""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from pathlib import Path

import pytest

from _protonpass_helpers import (  # noqa: F401
    _reset_caches,
    hermes_home,
    pp,
    pp_install,
)


# ---------------------------------------------------------------------------
# install_pass_cli — pinned hash + mocked download
# ---------------------------------------------------------------------------


def test_install_happy_path(hermes_home, monkeypatch):
    fake_binary = b"#!/bin/sh\necho 'pass-cli fake 2.1.1'\n"
    digest = hashlib.sha256(fake_binary).hexdigest()
    asset_name = pp_install._platform_asset_name()

    # Pin the digest of our fake asset so the checksum check passes.
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, digest)

    def fake_download(url, dest):
        assert url.endswith(asset_name)
        Path(dest).write_bytes(fake_binary)

    monkeypatch.setattr(pp_install, "_http_download", fake_download)
    # Post-install --version gate: report the pinned version.
    monkeypatch.setattr(
        pp_install,
        "_read_pass_cli_version",
        lambda binary: f"pass-cli {pp._PASS_CLI_VERSION}",
    )

    path = pp.install_pass_cli()
    assert path.exists()
    assert path.read_bytes() == fake_binary
    # Executable bit set + installed under the managed bin dir
    assert path.stat().st_mode & stat.S_IXUSR
    assert path == hermes_home / "bin" / pp_install._platform_binary_name()


def test_install_checksum_mismatch(hermes_home, monkeypatch):
    asset_name = pp_install._platform_asset_name()
    # Pin a digest that won't match the downloaded bytes.
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, "0" * 64)

    def fake_download(url, dest):
        Path(dest).write_bytes(b"the real bytes")

    monkeypatch.setattr(pp_install, "_http_download", fake_download)

    with pytest.raises(RuntimeError, match="Checksum mismatch"):
        pp.install_pass_cli()

    # No binary should have been installed on mismatch.
    assert not (hermes_home / "bin" / pp_install._platform_binary_name()).exists()


def test_install_post_version_mismatch_removes_binary(hermes_home, monkeypatch):
    fake_binary = b"#!/bin/sh\n"
    digest = hashlib.sha256(fake_binary).hexdigest()
    asset_name = pp_install._platform_asset_name()
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, digest)
    monkeypatch.setattr(
        pp_install,
        "_http_download",
        lambda url, dest: Path(dest).write_bytes(fake_binary),
    )
    # Installed binary reports the WRONG version → install must fail + clean up.
    monkeypatch.setattr(
        pp_install, "_read_pass_cli_version", lambda b: "pass-cli 9.9.9"
    )

    with pytest.raises(RuntimeError, match="does not report the pinned version"):
        pp.install_pass_cli()
    assert not (hermes_home / "bin" / pp_install._platform_binary_name()).exists()


def test_install_bin_dir_is_0700(hermes_home, monkeypatch):
    """A4: the managed bin dir is locked to 0o700 on creation."""
    fake_binary = b"#!/bin/sh\n"
    digest = hashlib.sha256(fake_binary).hexdigest()
    asset_name = pp_install._platform_asset_name()
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, digest)
    monkeypatch.setattr(
        pp_install,
        "_http_download",
        lambda url, dest: Path(dest).write_bytes(fake_binary),
    )
    monkeypatch.setattr(
        pp_install,
        "_read_pass_cli_version",
        lambda b: f"pass-cli {pp._PASS_CLI_VERSION}",
    )

    pp.install_pass_cli()
    bin_dir = hermes_home / "bin"
    assert bin_dir.exists()
    assert (os.stat(bin_dir).st_mode & 0o777) == 0o700


def test_ensure_bin_dir_chmod_0700(hermes_home):
    """A4: _ensure_bin_dir() creates + locks the bin dir to 0o700 directly."""
    bin_dir = pp_install._ensure_bin_dir()
    assert bin_dir.exists()
    assert (os.stat(bin_dir).st_mode & 0o777) == 0o700


def test_install_reverifies_existing_target_and_skips_reinstall(
    hermes_home, monkeypatch
):
    """A2: an existing, VALID target is returned without re-downloading."""
    target = hermes_home / "bin" / pp_install._platform_binary_name()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)

    # The existing target verifies cleanly → no download should happen.
    monkeypatch.setattr(pp_install, "_managed_binary_verified", lambda b: True)

    def boom_download(url, dest):  # pragma: no cover - must not be called
        raise AssertionError("must not re-download a verified existing target")

    monkeypatch.setattr(pp_install, "_http_download", boom_download)

    assert pp.install_pass_cli() == target


def test_install_reinstalls_invalid_existing_target(hermes_home, monkeypatch):
    """A2: an existing but INVALID target (stale/non-exec) is reinstalled."""
    target = hermes_home / "bin" / pp_install._platform_binary_name()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("stale", encoding="utf-8")

    # First verification (the existing target) fails → force a reinstall path.
    verify_calls = {"n": 0}

    def fake_verified(_b):
        verify_calls["n"] += 1
        return False

    monkeypatch.setattr(pp_install, "_managed_binary_verified", fake_verified)

    fake_binary = b"#!/bin/sh\nfresh\n"
    digest = hashlib.sha256(fake_binary).hexdigest()
    asset_name = pp_install._platform_asset_name()
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, digest)
    monkeypatch.setattr(
        pp_install,
        "_http_download",
        lambda url, dest: Path(dest).write_bytes(fake_binary),
    )
    monkeypatch.setattr(
        pp_install,
        "_read_pass_cli_version",
        lambda b: f"pass-cli {pp._PASS_CLI_VERSION}",
    )

    path = pp.install_pass_cli()
    assert path.read_bytes() == fake_binary
    assert verify_calls["n"] >= 1


def test_install_force_stages_before_replacing_working_binary(hermes_home, monkeypatch):
    """A5: a forced reinstall whose new binary fails the version gate must NOT
    destroy the existing working binary."""
    target = hermes_home / "bin" / pp_install._platform_binary_name()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"#!/bin/sh\nworking\n")
    target.chmod(0o755)

    fake_binary = b"#!/bin/sh\nbroken\n"
    digest = hashlib.sha256(fake_binary).hexdigest()
    asset_name = pp_install._platform_asset_name()
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, digest)
    monkeypatch.setattr(
        pp_install,
        "_http_download",
        lambda url, dest: Path(dest).write_bytes(fake_binary),
    )
    # The STAGED binary reports the wrong version → must raise BEFORE replacing.
    monkeypatch.setattr(
        pp_install, "_read_pass_cli_version", lambda b: "pass-cli 9.9.9"
    )

    with pytest.raises(RuntimeError, match="does not report the pinned version"):
        pp.install_pass_cli(force=True)

    # The existing working binary is untouched (never clobbered by the failed
    # staged copy).
    assert target.read_bytes() == b"#!/bin/sh\nworking\n"


# ---------------------------------------------------------------------------
# I1: the staged tempfile carries the platform suffix (.exe on Windows)
# ---------------------------------------------------------------------------


def _capture_mkstemp_suffix(monkeypatch):
    """Wrap tempfile.mkstemp so the FIRST call's ``suffix`` kwarg is captured.

    Only the binary staging call matters (prefix ``.pass-cli_``); the sidecar
    staging call (prefix ``.pass-cli-sha256_``) is delegated untouched.
    """
    captured = {}
    real_mkstemp = pp_install.tempfile.mkstemp

    def fake_mkstemp(*args, **kwargs):
        prefix = kwargs.get("prefix", "")
        if prefix == ".pass-cli_" and "binary_suffix" not in captured:
            captured["binary_suffix"] = kwargs.get("suffix", "")
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(pp_install.tempfile, "mkstemp", fake_mkstemp)
    return captured


def test_install_staged_tempfile_has_exe_suffix_on_windows(hermes_home, monkeypatch):
    """I1: on Windows the staged tempfile must carry ``.exe`` so CreateProcess
    can run the version gate on it."""
    monkeypatch.setattr(pp_install.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        pp_install,
        "_platform_asset_name",
        lambda: "pass-cli-windows-x86_64.zip",
    )
    monkeypatch.setattr(pp_install, "_platform_binary_name", lambda: "pass-cli.exe")

    exe_bytes = b"MZ fake pass-cli.exe bytes\n"
    archive_digest = hashlib.sha256(b"the archive bytes\n").hexdigest()
    monkeypatch.setitem(
        pp_install._PINNED_SHA256, "pass-cli-windows-x86_64.zip", archive_digest
    )

    def fake_download(url, dest):
        with zipfile.ZipFile(dest, "w") as zf:
            zf.writestr("pass-cli.exe", exe_bytes)

    monkeypatch.setattr(pp_install, "_http_download", fake_download)
    monkeypatch.setattr(
        pp_install, "_sha256_file", _hash_dispatch(exe_bytes, archive_digest)
    )
    monkeypatch.setattr(
        pp_install,
        "_read_pass_cli_version",
        lambda b: f"pass-cli {pp._PASS_CLI_VERSION}",
    )

    captured = _capture_mkstemp_suffix(monkeypatch)
    pp.install_pass_cli()
    assert captured["binary_suffix"] == ".exe"


def test_install_staged_tempfile_no_suffix_on_non_windows(hermes_home, monkeypatch):
    """I1: on non-Windows hosts the staged tempfile carries no suffix."""
    monkeypatch.setattr(pp_install.platform, "system", lambda: "Linux")

    fake_binary = b"#!/bin/sh\n"
    digest = hashlib.sha256(fake_binary).hexdigest()
    asset_name = pp_install._platform_asset_name()
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, digest)
    monkeypatch.setattr(
        pp_install,
        "_http_download",
        lambda url, dest: Path(dest).write_bytes(fake_binary),
    )
    monkeypatch.setattr(
        pp_install,
        "_read_pass_cli_version",
        lambda b: f"pass-cli {pp._PASS_CLI_VERSION}",
    )

    captured = _capture_mkstemp_suffix(monkeypatch)
    pp.install_pass_cli()
    assert captured["binary_suffix"] == ""


# ---------------------------------------------------------------------------
# Windows sidecar digest flow (install + verify without execution)
# ---------------------------------------------------------------------------


def test_install_windows_writes_sidecar_digest(hermes_home, monkeypatch):
    """Install on the Windows zip platform computes the extracted exe's SHA-256
    and stores it in a 0600 sidecar (the pinned digest is the archive's, so the
    exe can't be hash-matched against the pinned table)."""
    # Force the Windows zip platform regardless of host.
    monkeypatch.setattr(
        pp_install,
        "_platform_asset_name",
        lambda: "pass-cli-windows-x86_64.zip",
    )
    monkeypatch.setattr(pp_install, "_platform_binary_name", lambda: "pass-cli.exe")

    exe_bytes = b"MZ fake pass-cli.exe bytes\n"
    archive_bytes = b"the .zip archive bytes (different from the exe)\n"
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    monkeypatch.setitem(
        pp_install._PINNED_SHA256, "pass-cli-windows-x86_64.zip", archive_digest
    )

    def fake_download(url, dest):
        # Write a real zip whose pinned hash we override below to match.
        with zipfile.ZipFile(dest, "w") as zf:
            zf.writestr("pass-cli.exe", exe_bytes)

    monkeypatch.setattr(pp_install, "_http_download", fake_download)
    # The downloaded zip's actual hash must match the pinned archive digest.
    monkeypatch.setattr(
        pp_install, "_sha256_file", _hash_dispatch(exe_bytes, archive_digest)
    )
    monkeypatch.setattr(
        pp_install,
        "_read_pass_cli_version",
        lambda b: f"pass-cli {pp._PASS_CLI_VERSION}",
    )

    path = pp.install_pass_cli()
    sidecar = pp_install._sidecar_digest_path(path)
    assert sidecar.exists()
    stored = sidecar.read_text(encoding="utf-8").strip()
    assert stored == hashlib.sha256(exe_bytes).hexdigest()
    if os.name != "nt":
        assert (os.stat(sidecar).st_mode & 0o777) == 0o600


def test_install_windows_sidecar_replace_failure_is_fail_closed(
    hermes_home, monkeypatch
):
    """I2: if the sidecar os.replace fails AFTER the exe is in place, the target
    (and any sidecar) is removed so the next find_pass_cli reinstalls cleanly —
    an exe-without-valid-sidecar is treated as unverified, so we must not leave
    a trusted-looking exe behind."""
    monkeypatch.setattr(
        pp_install,
        "_platform_asset_name",
        lambda: "pass-cli-windows-x86_64.zip",
    )
    monkeypatch.setattr(pp_install, "_platform_binary_name", lambda: "pass-cli.exe")

    exe_bytes = b"MZ fake pass-cli.exe bytes\n"
    archive_digest = hashlib.sha256(b"the archive bytes\n").hexdigest()
    monkeypatch.setitem(
        pp_install._PINNED_SHA256, "pass-cli-windows-x86_64.zip", archive_digest
    )

    def fake_download(url, dest):
        with zipfile.ZipFile(dest, "w") as zf:
            zf.writestr("pass-cli.exe", exe_bytes)

    monkeypatch.setattr(pp_install, "_http_download", fake_download)
    monkeypatch.setattr(
        pp_install, "_sha256_file", _hash_dispatch(exe_bytes, archive_digest)
    )
    monkeypatch.setattr(
        pp_install,
        "_read_pass_cli_version",
        lambda b: f"pass-cli {pp._PASS_CLI_VERSION}",
    )

    target = hermes_home / "bin" / "pass-cli.exe"
    real_replace = pp_install.os.replace

    # Fail the SECOND os.replace (the sidecar): the exe is already in place by
    # then, so the cleanup must remove the target.
    calls = {"n": 0}

    def flaky_replace(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("simulated sidecar replace failure")
        return real_replace(src, dst)

    monkeypatch.setattr(pp_install.os, "replace", flaky_replace)

    with pytest.raises(OSError, match="simulated sidecar replace failure"):
        pp.install_pass_cli()

    # Fail closed: neither the exe nor its sidecar may survive.
    assert not target.exists()
    assert not pp_install._sidecar_digest_path(target).exists()
    # No leftover staged tempfiles either.
    leftovers = list((hermes_home / "bin").glob(".pass-cli*"))
    assert leftovers == []


def test_managed_windows_verified_against_sidecar(hermes_home, monkeypatch, tmp_path):
    """A managed Windows exe verifies against the STORED sidecar digest, with no
    execution, and a missing sidecar (legacy install) fails closed."""
    monkeypatch.setattr(
        pp_install,
        "_platform_asset_name",
        lambda: "pass-cli-windows-x86_64.zip",
    )
    monkeypatch.setattr(pp_install, "_platform_binary_name", lambda: "pass-cli.exe")

    exe = hermes_home / "bin" / "pass-cli.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"the extracted exe bytes")
    exe.chmod(0o755)

    # No sidecar yet → legacy/partial install → unverified.
    assert pp_install._managed_binary_verified(exe) is False

    # Write the matching sidecar → verified, no execution needed.
    pp_install._write_sidecar_digest(
        exe, hashlib.sha256(b"the extracted exe bytes").hexdigest()
    )
    assert pp_install._managed_binary_verified(exe) is True

    # Tamper the exe but keep the (now stale) sidecar → mismatch → unverified.
    exe.write_bytes(b"tampered bytes")
    assert pp_install._managed_binary_verified(exe) is False


def test_managed_windows_corrupt_sidecar_fails_closed(hermes_home, monkeypatch):
    monkeypatch.setattr(
        pp_install,
        "_platform_asset_name",
        lambda: "pass-cli-windows-x86_64.zip",
    )
    exe = hermes_home / "bin" / "pass-cli.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"verified candidate")
    exe.chmod(0o755)
    pp_install._sidecar_digest_path(exe).write_bytes(b"\xff")

    assert pp_install._managed_binary_verified(exe) is False


# ---------------------------------------------------------------------------
# SECURITY regression: verification must NEVER execute the managed binary
# ---------------------------------------------------------------------------


def test_managed_verification_never_executes_binary(hermes_home, monkeypatch, tmp_path):
    """A tampered managed binary must NOT be executed during verification.

    We plant a REAL executable at the managed path that writes a marker file
    when run, and we DELIBERATELY do not stub ``_read_pass_cli_version`` — so if
    verification ever shells out to the binary (the old ``--version``-before-hash
    bug) the marker would appear.  We assert the marker is never created and
    that ``find_pass_cli`` rejects the impostor (its SHA-256 does not match the
    pinned digest, and on Windows it has no sidecar)."""
    if os.name == "nt":
        pytest.skip("POSIX shell marker script; covered on Unix hosts")

    marker = tmp_path / "EXECUTED"
    managed = hermes_home / "bin" / pp_install._platform_binary_name()
    managed.parent.mkdir(parents=True, exist_ok=True)
    # A genuine, runnable binary — running it would create the marker and (the
    # whole point) could read ~/.hermes/.env as the user.
    managed.write_text(
        f"#!/bin/sh\ntouch {marker}\necho 'pass-cli {pp._PASS_CLI_VERSION}'\n",
        encoding="utf-8",
    )
    managed.chmod(0o755)

    # Its bytes do NOT match the pinned digest → must be rejected as unverified.
    asset_name = pp_install._platform_asset_name()
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, "0" * 64)
    # No PATH fallback so a rejection returns None rather than a PATH binary.
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: None)

    # auto_install off so we don't try to download — pure verify path.
    result = pp.find_pass_cli(install_if_missing=False)

    assert result is None, "tampered managed binary must not be returned"
    assert not marker.exists(), "verification executed the unverified binary!"


def _hash_dispatch(exe_bytes, archive_digest):
    """Return a fake ``_sha256_file`` that maps the staged exe to its real
    digest and any zip/archive path to the pinned archive digest."""
    real_exe_digest = hashlib.sha256(exe_bytes).hexdigest()

    def fake(path):
        p = str(path)
        if p.endswith(".zip"):
            return archive_digest
        # Staged copy (named .pass-cli_*) and final exe both ARE the exe bytes.
        return real_exe_digest

    return fake


# ---------------------------------------------------------------------------
# Version probe uses a minimal/scrubbed env (A3) — token never visible
# ---------------------------------------------------------------------------


def test_version_probe_uses_minimal_env_without_token(hermes_home, monkeypatch):
    """A3: ``_read_pass_cli_version`` must probe with a scrubbed env that
    contains NO token and NONE of the inherited secrets."""
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "leak-me")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-leak")

    captured = {}

    def fake_run(cmd, *, extra_env, timeout):
        captured["extra_env"] = extra_env
        captured["timeout"] = timeout
        return _CompletedVersion()

    monkeypatch.setattr(pp_install, "run_secret_cli", fake_run)

    pp_install._read_pass_cli_version(Path("/usr/bin/pass-cli"))

    env = captured["extra_env"]
    # The probe env must NOT carry the token or any inherited secret.
    assert "PROTON_PASS_PERSONAL_ACCESS_TOKEN" not in env
    assert "OPENAI_API_KEY" not in env
    # It IS a minimal env (NO_COLOR is the canonical marker the builder sets).
    assert env.get("NO_COLOR") == "1"
    assert captured["timeout"] == 5


def test_version_probe_passes_explicit_env(hermes_home, monkeypatch):
    """A3: the probe forces a clean env (passes ``env=`` explicitly) rather than
    inheriting the parent process env."""
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "leak-me")
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return _CompletedVersion()

    monkeypatch.setattr(pp_install, "run_secret_cli", fake_run)
    pp_install._read_pass_cli_version(Path("/usr/bin/pass-cli"))
    assert "extra_env" in seen  # a minimal env is passed explicitly


def test_version_probe_nonzero_exit_returns_none(hermes_home, monkeypatch):
    monkeypatch.setattr(
        pp_install,
        "run_secret_cli",
        lambda cmd, **kw: _CompletedVersion(returncode=1),
    )
    assert pp_install._read_pass_cli_version(Path("/usr/bin/pass-cli")) is None


def test_version_probe_transport_failure_returns_none(hermes_home, monkeypatch):
    def boom(cmd, **kw):
        raise RuntimeError("failed to invoke pass-cli")

    monkeypatch.setattr(pp_install, "run_secret_cli", boom)
    assert pp_install._read_pass_cli_version(Path("/nope")) is None


class _CompletedVersion:
    def __init__(self, returncode=0, stdout="pass-cli 2.1.1", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# Pinned-hash lookup
# ---------------------------------------------------------------------------


def test_expected_sha256_known_asset():
    asset_name = pp_install._platform_asset_name()
    digest = pp_install._expected_sha256(asset_name)
    assert digest == pp_install._PINNED_SHA256[asset_name]
    assert len(digest) == 64


def test_expected_sha256_unknown_asset_raises():
    with pytest.raises(RuntimeError, match="No pinned SHA-256"):
        pp_install._expected_sha256("pass-cli-unknown-platform")


def test_platform_asset_name_rejects_unknown_arch(monkeypatch):
    """I3: an unrecognised CPU arch must raise the unsupported-platform error
    rather than silently mapping to the x86_64 asset (a misleading checksum or
    download failure)."""
    monkeypatch.setattr(pp_install.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pp_install.platform, "machine", lambda: "armv7l")
    with pytest.raises(RuntimeError, match="Unsupported platform for pass-cli"):
        pp_install._platform_asset_name()


def test_platform_asset_name_maps_amd64_and_x64_to_x86_64(monkeypatch):
    """I3: amd64/x64 are recognised aliases for x86_64 (Darwin + Linux)."""
    monkeypatch.setattr(pp_install.platform, "system", lambda: "Linux")
    for machine in ("amd64", "x64", "X86_64"):
        monkeypatch.setattr(pp_install.platform, "machine", lambda m=machine: m)
        assert pp_install._platform_asset_name() == "pass-cli-linux-x86_64"

    monkeypatch.setattr(pp_install.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(pp_install.platform, "machine", lambda: "amd64")
    assert pp_install._platform_asset_name() == "pass-cli-macos-x86_64"


def test_platform_asset_name_maps_arm_aliases(monkeypatch):
    """I3: arm64/aarch64 both map to the aarch64 asset."""
    monkeypatch.setattr(pp_install.platform, "system", lambda: "Darwin")
    for machine in ("arm64", "aarch64"):
        monkeypatch.setattr(pp_install.platform, "machine", lambda m=machine: m)
        assert pp_install._platform_asset_name() == "pass-cli-macos-aarch64"


def test_platform_asset_name_windows_unknown_arch_raises(monkeypatch):
    """V8-A: Windows + an unknown machine (armv7l/ppc64le → arch is None) must
    RAISE the unsupported-platform error rather than silently aliasing to the
    x86_64 zip."""
    monkeypatch.setattr(pp_install.platform, "system", lambda: "Windows")
    for machine in ("armv7l", "ppc64le"):
        monkeypatch.setattr(pp_install.platform, "machine", lambda m=machine: m)
        with pytest.raises(RuntimeError, match="Unsupported platform for pass-cli"):
            pp_install._platform_asset_name()


def test_platform_asset_name_windows_arm64_maps_to_x86_64_zip(monkeypatch):
    """V8-A: Windows-on-ARM64 runs the x64 binary via the OS emulation layer, so
    arm64/aarch64 map to the published x86_64 zip (documented exception)."""
    monkeypatch.setattr(pp_install.platform, "system", lambda: "Windows")
    for machine in ("arm64", "aarch64"):
        monkeypatch.setattr(pp_install.platform, "machine", lambda m=machine: m)
        assert pp_install._platform_asset_name() == "pass-cli-windows-x86_64.zip"


def test_platform_asset_name_windows_x86_64_maps_to_x86_64_zip(monkeypatch):
    """V8-A: Windows + amd64/x86_64 map to the published x86_64 zip."""
    monkeypatch.setattr(pp_install.platform, "system", lambda: "Windows")
    for machine in ("amd64", "x86_64"):
        monkeypatch.setattr(pp_install.platform, "machine", lambda m=machine: m)
        assert pp_install._platform_asset_name() == "pass-cli-windows-x86_64.zip"


def test_pinned_table_covers_all_platforms():
    # The five published 2.1.1 assets must all be pinned.
    for asset in (
        "pass-cli-macos-aarch64",
        "pass-cli-macos-x86_64",
        "pass-cli-linux-aarch64",
        "pass-cli-linux-x86_64",
        "pass-cli-windows-x86_64.zip",
    ):
        assert asset in pp_install._PINNED_SHA256


# ---------------------------------------------------------------------------
# Version-token matching helper
# ---------------------------------------------------------------------------


def test_version_token_matches_handles_prefixes_and_separators():
    v = pp._PASS_CLI_VERSION
    assert pp_install._version_token_matches(f"pass-cli {v}")
    assert pp_install._version_token_matches(f"pass-cli v{v}")
    assert pp_install._version_token_matches(f"pass-cli version={v}")
    assert pp_install._version_token_matches(v)
    assert not pp_install._version_token_matches("pass-cli 9.9.9")
    assert not pp_install._version_token_matches("")
    assert not pp_install._version_token_matches(None)


# ---------------------------------------------------------------------------
# find_pass_cli — managed bin re-verified, PATH fallback, install_if_missing
# ---------------------------------------------------------------------------


def test_find_prefers_managed_bin_when_verified(hermes_home, monkeypatch):
    """A1: the managed copy wins over PATH — but only after it RE-VERIFIES."""
    managed = hermes_home / "bin" / pp_install._platform_binary_name()
    managed.parent.mkdir(parents=True, exist_ok=True)
    managed.write_text("#!/bin/sh\n", encoding="utf-8")
    managed.chmod(0o755)

    # Managed copy passes verification (version gate + hash) → trusted.
    monkeypatch.setattr(pp_install, "_managed_binary_verified", lambda b: True)
    # Even if PATH has one, the managed copy wins.
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: "/usr/bin/pass-cli")

    assert pp.find_pass_cli() == managed


def test_find_managed_bin_unverified_no_install_returns_none(hermes_home, monkeypatch):
    """A1: a managed copy that FAILS verification is never returned blindly when
    auto-install is off — we warn + skip rather than hand it the token."""
    managed = hermes_home / "bin" / pp_install._platform_binary_name()
    managed.parent.mkdir(parents=True, exist_ok=True)
    managed.write_text("#!/bin/sh\n", encoding="utf-8")
    managed.chmod(0o755)

    monkeypatch.setattr(pp_install, "_managed_binary_verified", lambda b: False)
    # A version-matched PATH binary must NOT be used as a silent substitute when
    # the managed copy is present-but-invalid and install is off: we return None.
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: None)

    assert pp.find_pass_cli(install_if_missing=False) is None


def test_find_managed_bin_unverified_reinstalls_when_install_on(
    hermes_home, monkeypatch
):
    """A1: a managed copy that fails verification triggers a forced reinstall of
    the pinned binary when ``install_if_missing`` is True."""
    managed = hermes_home / "bin" / pp_install._platform_binary_name()
    managed.parent.mkdir(parents=True, exist_ok=True)
    managed.write_text("#!/bin/sh\n", encoding="utf-8")
    managed.chmod(0o755)

    monkeypatch.setattr(pp_install, "_managed_binary_verified", lambda b: False)
    forced = {"force": None}

    def fake_install(*, force=False):
        forced["force"] = force
        return managed

    monkeypatch.setattr(pp_install, "install_pass_cli", fake_install)

    assert pp.find_pass_cli(install_if_missing=True) == managed
    # The reinstall is forced — it must replace, not skip, the invalid copy.
    assert forced["force"] is True


def test_find_path_fallback_requires_pinned_hash(hermes_home, monkeypatch):
    """V3: a PATH binary is used as a last resort ONLY when it hash-verifies
    against the pinned asset digest — a version match alone is not enough."""
    # No managed binary present; fall back to PATH only if SHA-256 matches.
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: "/usr/bin/pass-cli")
    monkeypatch.setattr(pp_install, "_path_binary_trusted", lambda binary: True)
    assert pp.find_pass_cli() == Path("/usr/bin/pass-cli")


def test_find_path_binary_unpinned_hash_not_returned(hermes_home, monkeypatch):
    """V3 (security): a PATH ``pass-cli`` that passes the version gate but whose
    SHA-256 does NOT match a pinned asset is NOT returned for token use — we fail
    closed (a spoofed binary that just prints ``2.1.1`` must never get the
    token)."""
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: "/usr/bin/pass-cli")
    # Version is fine (spoofable) but the bytes don't hash to a pinned digest.
    monkeypatch.setattr(
        pp_install,
        "_read_pass_cli_version",
        lambda binary: f"pass-cli {pp._PASS_CLI_VERSION}",
    )
    monkeypatch.setattr(pp_install, "_path_binary_trusted", lambda binary: False)
    assert pp.find_pass_cli() is None


def test_path_binary_trusted_matches_pinned_hash(hermes_home, monkeypatch, tmp_path):
    """V3: a PATH binary whose bytes hash to the pinned asset digest IS trusted
    (genuine pinned bytes, regardless of where they live on disk)."""
    asset_name = pp_install._platform_asset_name()
    if asset_name.endswith(".zip"):
        pytest.skip("Windows zip platform: PATH binary can't be hash-verified")
    real_bytes = b"#!/bin/sh\nthe genuine pinned pass-cli bytes\n"
    digest = hashlib.sha256(real_bytes).hexdigest()
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, digest)

    binary = tmp_path / "pass-cli"
    binary.write_bytes(real_bytes)
    binary.chmod(0o755)

    assert pp_install._path_binary_trusted(binary) is True


def test_path_binary_trusted_rejects_nonmatching_hash(
    hermes_home, monkeypatch, tmp_path
):
    """V3: a PATH binary whose bytes do NOT hash to the pinned digest is not
    trusted, even if it would pass a version gate."""
    asset_name = pp_install._platform_asset_name()
    if asset_name.endswith(".zip"):
        pytest.skip("Windows zip platform: PATH binary can't be hash-verified")
    monkeypatch.setitem(pp_install._PINNED_SHA256, asset_name, "0" * 64)

    binary = tmp_path / "pass-cli"
    binary.write_bytes(b"impostor bytes that print 2.1.1")
    binary.chmod(0o755)

    assert pp_install._path_binary_trusted(binary) is False


def test_path_binary_trusted_fails_closed_on_zip_platform(
    hermes_home, monkeypatch, tmp_path
):
    """V3: on the Windows zip platform the pinned digest is the archive's (not
    the extracted exe's), so a PATH ``.exe`` can NEVER be hash-matched — we fail
    closed and do not auto-trust it."""
    # Force the zip asset regardless of the host platform.
    monkeypatch.setattr(
        pp_install,
        "_platform_asset_name",
        lambda: "pass-cli-windows-x86_64.zip",
    )
    binary = tmp_path / "pass-cli.exe"
    binary.write_bytes(b"anything")
    try:
        binary.chmod(0o755)
    except OSError:
        pass
    assert pp_install._path_binary_trusted(binary) is False


def test_find_prefers_install_over_path_binary(hermes_home, monkeypatch):
    # When auto-install is enabled and the managed copy is absent, install the
    # verified pinned binary rather than trusting an unverified PATH binary.
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: "/usr/bin/pass-cli")
    sentinel = hermes_home / "bin" / "pass-cli"
    installed = {"n": 0}

    def fake_install():
        installed["n"] += 1
        return sentinel

    def boom_version(binary):  # pragma: no cover - must not be called
        raise AssertionError("PATH binary must not be probed when install wins")

    monkeypatch.setattr(pp_install, "install_pass_cli", fake_install)
    monkeypatch.setattr(pp_install, "_read_pass_cli_version", boom_version)

    assert pp.find_pass_cli(install_if_missing=True) == sentinel
    assert installed["n"] == 1


def test_find_install_if_missing_invokes_installer(hermes_home, monkeypatch):
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: None)
    sentinel = hermes_home / "bin" / "pass-cli"
    called = {"n": 0}

    def fake_install():
        called["n"] += 1
        return sentinel

    monkeypatch.setattr(pp_install, "install_pass_cli", fake_install)

    assert pp.find_pass_cli(install_if_missing=True) == sentinel
    assert called["n"] == 1


def test_find_install_failure_returns_none(hermes_home, monkeypatch):
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: None)

    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(pp_install, "install_pass_cli", boom)

    # Never blocks startup — failure yields None, not an exception.
    assert pp.find_pass_cli(install_if_missing=True) is None


def test_find_no_install_returns_none(hermes_home, monkeypatch):
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: None)
    assert pp.find_pass_cli(install_if_missing=False) is None


# ---------------------------------------------------------------------------
# auto_install=false must never trigger a download (install side)
# ---------------------------------------------------------------------------


def test_auto_install_false_never_installs(hermes_home, monkeypatch):
    monkeypatch.setattr(pp_install.shutil, "which", lambda name: None)

    def boom():  # pragma: no cover - must not be called
        raise AssertionError("install_pass_cli must not run when auto_install=False")

    monkeypatch.setattr(pp_install, "install_pass_cli", boom)

    with pytest.raises(RuntimeError, match="pass-cli binary not available"):
        pp.fetch_protonpass_secrets(
            service_token="svc",
            vault="V",
            use_cache=False,
            auto_install=False,
            home_path=hermes_home,
        )


# ---------------------------------------------------------------------------
# zip-slip: members with absolute paths or `..` are rejected
# ---------------------------------------------------------------------------


def test_zip_slip_member_rejected():
    assert pp_install._is_unsafe_zip_member("../evil")
    assert pp_install._is_unsafe_zip_member("/abs/evil")
    assert pp_install._is_unsafe_zip_member("C:\\windows\\evil")
    # I4: the drive-letter check runs on the NORMALISED path, so the
    # forward-slash form (C:/...) is caught too, not just the backslash form.
    assert pp_install._is_unsafe_zip_member("C:/windows/evil")
    assert pp_install._is_unsafe_zip_member("nested/../../evil")
    assert not pp_install._is_unsafe_zip_member("pass-cli.exe")
    assert not pp_install._is_unsafe_zip_member("dir/pass-cli.exe")


def test_pick_zip_member_skips_unsafe(tmp_path):
    zpath = tmp_path / "a.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../pass-cli.exe", b"evil")
        zf.writestr("pass-cli.exe", b"good")
    with zipfile.ZipFile(zpath) as zf:
        member = pp_install._pick_zip_member(zf, "pass-cli.exe")
    assert member == "pass-cli.exe"


def test_pick_zip_member_all_unsafe_raises(tmp_path):
    zpath = tmp_path / "a.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../pass-cli.exe", b"evil")
    with zipfile.ZipFile(zpath) as zf:
        with pytest.raises(RuntimeError, match="Could not find"):
            pp_install._pick_zip_member(zf, "pass-cli.exe")


# ---------------------------------------------------------------------------
# HTTP download — size cap + status check
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, chunks, *, status=200, content_length=None):
        self._chunks = list(chunks)
        self.status = status
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def getcode(self):
        return self.status

    def read(self, n):
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_http_download_declared_size_cap(monkeypatch, tmp_path):
    big = pp_install._MAX_DOWNLOAD_BYTES + 1
    monkeypatch.setattr(
        pp_install.urllib.request,
        "urlopen",
        lambda req, timeout: _FakeResp([b"x"], content_length=big),
    )
    with pytest.raises(RuntimeError, match="exceeds cap"):
        pp_install._http_download("https://example/x", tmp_path / "out")


def test_http_download_streaming_cap(monkeypatch, tmp_path):
    # No Content-Length, but the stream exceeds the cap mid-flight.
    chunk = b"x" * 65536
    n = (pp_install._MAX_DOWNLOAD_BYTES // 65536) + 2
    monkeypatch.setattr(
        pp_install.urllib.request,
        "urlopen",
        lambda req, timeout: _FakeResp([chunk] * n),
    )
    with pytest.raises(RuntimeError, match="size cap"):
        pp_install._http_download("https://example/x", tmp_path / "out")
