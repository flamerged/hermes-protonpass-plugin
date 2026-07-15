"""``pass-cli`` binary discovery + lazy install.

Hermes pins one ``pass-cli`` version (:data:`_PASS_CLI_VERSION`) and downloads
the matching asset from the official Proton download path, verifying the
SHA-256 against a HARDCODED pinned table (:data:`_PINNED_SHA256`).  Because the
version is pinned, the asset digests are constants — there is no runtime
manifest fetch, no recursive JSON walk, and no "scan for the version" logic.

Bumping pass-cli: update :data:`_PASS_CLI_VERSION` AND :data:`_PINNED_SHA256`
together (pull the new digests from
``https://proton.me/download/pass-cli/versions.json``), in the same PR.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import shutil
import stat
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from agent.secret_sources.base import run_secret_cli

logger = logging.getLogger(__name__)


# Pinned upstream version.  Bump in a follow-up PR — never auto-resolve
# "latest" because upstream release shape (asset names, CLI flags) is allowed
# to change between majors and we want updates to be deliberate.
_PASS_CLI_VERSION = "2.1.1"

# Pinned per-asset SHA-256 digests for _PASS_CLI_VERSION (lowercase hex, no
# algo prefix), taken from proton.me/download/pass-cli/versions.json.
#
# IMPORTANT: bump this table ALONGSIDE _PASS_CLI_VERSION — the two must always
# move together.  Because the version is pinned the digests are constants, so
# there is no manifest fetch / recursive walk at runtime.
_PINNED_SHA256 = {
    "pass-cli-macos-aarch64": "787b107dbfb759502460cac361724e2862d5082025fc02e902f436a92df050a9",
    "pass-cli-macos-x86_64": "a23b7781578d0220d655f745b40e89abf5b0a8cd3fa3537f2ec080c747abb8af",
    "pass-cli-linux-aarch64": "d76579e5191ea4a56d8e254898c9c6c5242a7f3a3a5204dccb88f34409e4c9fb",
    "pass-cli-linux-x86_64": "97eeed17907674cfde7b397157f14f3ae0d1391c82732062971f4b1333559a8f",
    "pass-cli-windows-x86_64.zip": "42379f09ca606d9b6da851dbf6cba73482bded52b8cd8771defd72a1be443a0c",
}

# Assets live under the versioned download path.
_PASS_CLI_DOWNLOAD_BASE = f"https://proton.me/download/pass-cli/{_PASS_CLI_VERSION}"

# How long to wait for an HTTP download, in seconds.
_PASS_CLI_DOWNLOAD_TIMEOUT = 60

# Hard cap on a downloaded asset so a malicious/compromised upstream can't
# exhaust the disk before any secret is even fetched.
_MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024  # 64 MiB


def _hermes_bin_dir() -> Path:
    """Where Hermes stores its managed binaries.  Profile-aware."""
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "bin"


def _ensure_bin_dir() -> Path:
    """Return the managed bin dir, creating it and locking it to 0o700.

    The bin dir holds the trusted, checksum-verified binary; locking it down
    (consistent with the session and cache dirs) keeps another local user from
    swapping in a binary we would then hand the service token.  chmod is
    best-effort: a filesystem that can't honour POSIX modes must not crash
    startup.
    """
    bin_dir = _hermes_bin_dir()
    bin_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(bin_dir, 0o700)
    except OSError:
        pass
    return bin_dir


def find_pass_cli(*, install_if_missing: bool = False) -> Optional[Path]:
    """Return a path to a usable ``pass-cli`` binary, or None.

    Resolution order (security-aware):
      1. ``<hermes_home>/bin/pass-cli``  (our managed copy) — preferred, but
         NEVER trusted blindly.  We re-verify it by SHA-256 WITHOUT EXECUTING
         it (exec bit + a hash match against the pinned digest on raw-asset
         platforms, or against the install-time sidecar digest on the Windows
         zip platform) before returning it.  We deliberately do NOT run
         ``--version`` on a managed copy: executing an unverified binary is the
         very hijack we are defending against (a tampered managed copy could run
         as the user and read ``~/.hermes/.env`` before any hash check).  On
         mismatch we reinstall (when ``install_if_missing``) or warn + skip — we
         never hand the token to an unverified managed binary just because the
         path exists.
      2. When ``install_if_missing`` is True and the managed copy is
         absent/invalid, INSTALL the verified pinned binary BEFORE falling back
         to a PATH binary.  Installing a known-good, checksum-verified binary is
         safer than running whatever ``pass-cli`` happens to be first on
         ``PATH`` (a PATH-hijack would otherwise be handed the service token).
      3. ``shutil.which("pass-cli")``    (system PATH) — used only as a last
         resort, and only after CRYPTOGRAPHICALLY verifying it.  A PATH binary
         is handed the service token ONLY when its SHA-256 matches a pinned
         asset digest (genuine pinned bytes, regardless of where they live).
         A version-only gate is NOT sufficient here: a malicious PATH ``pass-cli``
         could simply print ``2.1.1`` to pass it and then receive the token.  On
         any mismatch (or a platform we can't hash-verify, e.g. the Windows zip
         asset whose pinned digest is the archive's, not the extracted exe's) we
         FAIL CLOSED — warn + return None — rather than trust an unverified PATH
         binary.  See :func:`_path_binary_trusted` for the trust model.

    Returns None when nothing usable is found.
    """
    managed = _hermes_bin_dir() / _platform_binary_name()
    if managed.exists():
        if _managed_binary_verified(managed):
            return managed
        # The managed copy exists but failed verification (wrong version, hash
        # mismatch, or not executable).  Never return it.
        if install_if_missing:
            logger.warning(
                "Managed pass-cli at %s failed verification; reinstalling the "
                "pinned %s binary",
                managed,
                _PASS_CLI_VERSION,
            )
            try:
                return install_pass_cli(force=True)
            except Exception as exc:  # noqa: BLE001 — never block startup
                logger.warning("pass-cli reinstall failed: %s", exc)
                # Fall through to a SHA-256-trusted PATH binary as a last resort.
        else:
            logger.warning(
                "Ignoring managed pass-cli at %s: it failed verification "
                "against the pinned %s (run `hermes protonpass install` "
                "to reinstall the verified binary)",
                managed,
                _PASS_CLI_VERSION,
            )
            return None

    # Prefer installing the verified pinned binary over trusting PATH.
    elif install_if_missing:
        try:
            return install_pass_cli()
        except Exception as exc:  # noqa: BLE001 — never block startup
            logger.warning("pass-cli auto-install failed: %s", exc)
            # Fall through to a SHA-256-trusted PATH binary as a last resort.

    system = shutil.which("pass-cli")
    if system:
        system_path = Path(system)
        # SECURITY: a PATH binary is trusted with the token ONLY when its bytes
        # hash to a pinned asset digest.  A version-only gate is spoofable (a
        # hostile pass-cli can just print the pinned version), so we FAIL CLOSED
        # on any hash mismatch / unhashable platform.
        if _path_binary_trusted(system_path):
            return system_path
        logger.warning(
            "Ignoring PATH pass-cli at %s: it could not be verified by SHA-256 "
            "against the pinned %s asset (a version match alone is not enough to "
            "be handed the service token). Run `hermes protonpass "
            "install` to fetch and use the verified pinned binary.",
            system_path,
            _PASS_CLI_VERSION,
        )
        return None
    return None


def get_pass_cli_version(binary: Path) -> Optional[str]:
    """Public, scrubbed-env probe of ``pass-cli --version`` for a binary.

    Thin wrapper over :func:`_read_pass_cli_version` so callers outside this
    module (e.g. the CLI ``status``/``setup`` surface) don't reach for the
    private name.  Same contract: best-effort, never raises, runs with a
    MINIMAL scrubbed environment (no token, no inherited secrets), returns the
    reported version string or ``None``.
    """
    return _read_pass_cli_version(binary)


def _read_pass_cli_version(binary: Path) -> Optional[str]:
    """Return the version string reported by ``pass-cli --version``, or None.

    Best-effort and never raises: a timeout, OSError, or non-zero exit yields
    None so callers can decide how to treat an unknown version.

    SECURITY: the probe runs with a MINIMAL, scrubbed environment (no service
    token, no inherited secrets).  ``binary`` may be a PATH-resolved or
    not-yet-verified copy, so it must never see the parent process's secrets —
    we reuse the same minimal-env builder the session plumbing uses.  A clean
    env is forced (not merely inherited) by passing ``env=`` explicitly.
    """
    # Local import avoids a module-load import cycle (session imports
    # _hermes_bin_dir from this module).
    from .session import _minimal_env

    try:
        proc = run_secret_cli(
            [str(binary), "--version"],
            extra_env=_minimal_env(),
            timeout=5,
        )
    except RuntimeError:
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or proc.stderr or "").strip()


def _version_token_matches(reported: Optional[str]) -> bool:
    """True iff ``reported`` carries ``_PASS_CLI_VERSION`` as a whole token.

    The reported string may be prefixed with the program name
    (e.g. ``pass-cli 2.1.1`` / ``pass-cli v2.1.1`` / a bare ``2.1.1``); we
    tokenise on whitespace and common separators so all forms match cleanly.
    """
    if not reported:
        return False
    tokens = reported.replace("v", " ").replace("=", " ").split()
    return _PASS_CLI_VERSION in tokens


def _path_binary_trusted(binary: Path) -> bool:
    """True iff a PATH ``pass-cli`` may be handed the service token.

    TRUST MODEL (fail-closed): a binary discovered on ``$PATH`` is NOT the
    checksum-verified copy Hermes installs under ``<hermes_home>/bin``.  A
    version-only gate is SPOOFABLE — a malicious ``pass-cli`` first on ``PATH``
    can simply print ``2.1.1`` to pass it and then receive the
    ``PROTON_PASS_PERSONAL_ACCESS_TOKEN``.  So we trust a PATH binary ONLY when
    its bytes hash to the pinned asset digest for this platform (genuine pinned
    bytes, regardless of where on disk they live).

    On macOS/Linux the upstream asset IS the raw binary, so its SHA-256 must
    equal the pinned digest and we can verify directly.  On Windows the pinned
    digest is the ``.zip`` archive's, NOT the extracted ``.exe``'s, so a PATH
    ``.exe`` can never be hash-matched against it — we therefore do NOT auto-
    trust a PATH binary on Windows and FAIL CLOSED (the user must run the
    managed `hermes protonpass install`).  Any I/O error or unpinned
    platform also fails closed.
    """
    try:
        asset_name = _platform_asset_name()
    except RuntimeError:
        # Unsupported/unpinned platform: nothing to hash against → fail closed.
        return False
    if asset_name.endswith(".zip"):
        # Windows zip asset: the pinned digest is the archive's, so an extracted
        # PATH .exe can't be hash-verified against it.  Fail closed.
        return False
    pinned = _PINNED_SHA256.get(asset_name)
    if not pinned:
        return False
    if not (binary.exists() and os.access(binary, os.X_OK)):
        return False
    try:
        actual = _sha256_file(binary)
    except OSError:
        return False
    return pinned.lower() == actual.lower()


def _managed_binary_hash_ok(binary: Path) -> bool:
    """True iff a managed binary's SHA-256 matches the pinned asset digest.

    Only meaningful for platforms whose upstream asset is the RAW binary
    (macOS/Linux): there the installed file IS the downloaded asset, so its
    digest must equal the pinned one.  Windows ships a ``.zip`` (the extracted
    ``.exe`` has a different hash than the archive), so we can't hash-verify it
    against the pinned table here and return False — that platform is verified
    against the install-time sidecar digest by :func:`_managed_binary_verified`.
    """
    try:
        asset_name = _platform_asset_name()
    except RuntimeError:
        return False
    if asset_name.endswith(".zip"):
        return False
    pinned = _PINNED_SHA256.get(asset_name)
    if not pinned:
        return False
    try:
        actual = _sha256_file(binary)
    except OSError:
        return False
    return pinned.lower() == actual.lower()


def _managed_binary_verified(binary: Path) -> bool:
    """True iff a managed ``pass-cli`` is trustworthy enough to hand the token.

    A managed copy under ``<hermes_home>/bin`` is NOT trusted just because it
    exists — another local user (or a stale/half-written install) could have
    left an impostor there.  Verification is done by SHA-256 and WITHOUT EVER
    EXECUTING the binary: running an unverified managed copy is precisely the
    privilege-escalation we are defending against (a tampered ``<bin>/pass-cli``
    would otherwise run as the user — and could read ``~/.hermes/.env`` — before
    any hash check, even though that check would later fail).

    * Raw-asset platforms (macOS/Linux): the installed file IS the downloaded
      asset, so its SHA-256 must equal the pinned digest.  A hash match IS proof
      of the pinned version, so we do NOT run ``--version`` at all.
    * Windows zip platform: the pinned digest is the archive's, not the
      extracted exe's, so we compare against the install-time sidecar digest
      written by :func:`install_pass_cli`.  A missing/garbage sidecar
      (legacy/partial install) is treated as UNVERIFIED → the caller reinstalls
      (when auto_install) or fails closed.  We never run the exe to "fix up" a
      missing sidecar.

    On any mismatch the caller reinstalls or refuses rather than handing the
    service token to an unverified binary.
    """
    if not (binary.exists() and os.access(binary, os.X_OK)):
        return False
    try:
        asset_name = _platform_asset_name()
    except RuntimeError:
        # Unsupported/unpinned platform: we have nothing to hash against and
        # MUST NOT execute an unverified binary to learn its version → fail
        # closed rather than trust it with the token.
        return False
    if asset_name.endswith(".zip"):
        # Windows zip asset: verify the extracted exe against the install-time
        # sidecar digest (NO execution).  Missing sidecar → unverified.
        stored = _read_sidecar_digest(binary)
        if stored is None:
            return False
        try:
            actual = _sha256_file(binary)
        except OSError:
            return False
        return stored == actual.lower()
    return _managed_binary_hash_ok(binary)


def _platform_binary_name() -> str:
    return "pass-cli.exe" if platform.system() == "Windows" else "pass-cli"


def _sidecar_digest_path(binary: Path) -> Path:
    """Path to the install-time SHA-256 sidecar for a managed binary.

    Windows ships a ``.zip`` whose pinned digest is the ARCHIVE's, not the
    extracted ``.exe``'s, so the managed ``.exe`` cannot be hash-matched against
    the pinned table directly.  At install time we compute the extracted exe's
    SHA-256 and write it here (``<binary>.sha256``, mode 0600); later
    verification reads it back and compares WITHOUT executing the binary.
    """
    return binary.parent / (binary.name + ".sha256")


def _read_sidecar_digest(binary: Path) -> Optional[str]:
    """Return the stored SHA-256 hex for a managed binary, or None.

    Best-effort and never raises: a missing/unreadable/garbage sidecar yields
    None so the caller treats the binary as unverified (legacy/partial install)
    and fails closed (reinstall when auto_install, else skip).
    """
    sidecar = _sidecar_digest_path(binary)
    try:
        raw = sidecar.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    # Tolerate an optional "sha256:" prefix; require a bare 64-char hex body.
    digest = raw.split(":", 1)[-1].strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return None
    return digest


def _write_sidecar_digest(
    binary: Path, digest: str, *, path: Optional[Path] = None
) -> None:
    """Write ``digest`` to a binary's SHA-256 sidecar, locked to 0o600.

    By default the sidecar is the managed binary's ``<binary>.sha256`` path; the
    install flow passes an explicit ``path`` to write a STAGED sidecar tempfile
    first and ``os.replace`` it into place (atomic, fail-closed).  chmod is
    best-effort (a filesystem that can't honour POSIX modes must not crash an
    install).  The value is a SHA-256 hex digest, never a secret.
    """
    sidecar = path if path is not None else _sidecar_digest_path(binary)
    sidecar.write_text(digest.lower() + "\n", encoding="utf-8")
    try:
        os.chmod(sidecar, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _platform_asset_name() -> str:
    """Map (uname, arch) → the upstream asset filename.

    Proton ships RAW binaries (not archives) for macOS/Linux and a zip for
    Windows.  Asset names follow ``pass-cli-<os>-<arch>`` with a ``.zip``
    suffix only on Windows.
    """
    system = platform.system()
    machine = platform.machine().lower()

    # Only map KNOWN machines.  Silently coercing every non-ARM machine to
    # x86_64 (the old behaviour) sent armv7l/ppc64le/s390x/i686 down the
    # x86_64 path and produced a misleading checksum/download failure instead
    # of a clear unsupported-platform error.  Anything we don't recognise
    # falls through to the same RuntimeError raised for unknown OSes.
    if machine in ("arm64", "aarch64"):
        arch = "aarch64"
    elif machine in ("x86_64", "amd64", "x64"):
        arch = "x86_64"
    else:
        arch = None

    if system == "Darwin" and arch is not None:
        return f"pass-cli-macos-{arch}"

    if system == "Linux" and arch is not None:
        return f"pass-cli-linux-{arch}"

    # Windows: Proton publishes ONLY the x86_64 zip at 2.1.1.  Windows-on-ARM64
    # runs x64 binaries transparently via the OS x64-emulation layer, so we
    # deliberately map BOTH x86_64 and aarch64 to the x86_64 zip (the documented
    # ARM64-via-x64-emulation exception).  Crucially we gate on a KNOWN arch: an
    # unknown machine (armv7l/i686/ppc64le → arch is None) must NOT silently
    # alias to x86_64, so it falls through to the unsupported-platform error.
    if system == "Windows" and arch in ("x86_64", "aarch64"):
        return "pass-cli-windows-x86_64.zip"

    raise RuntimeError(
        f"Unsupported platform for pass-cli auto-install: {system} {machine}"
    )


def _expected_sha256(asset_name: str) -> str:
    """Return the pinned SHA-256 for ``asset_name``.

    A plain dict lookup against :data:`_PINNED_SHA256` — the version is pinned,
    so the digests are constants.  An unknown asset (a platform we don't pin)
    raises a clear error rather than silently installing an unverified binary.
    """
    digest = _PINNED_SHA256.get(asset_name)
    if not digest:
        raise RuntimeError(
            f"No pinned SHA-256 for asset {asset_name!r} at pass-cli version "
            f"{_PASS_CLI_VERSION}; this platform/asset is not pinned. Install "
            "pass-cli manually from https://proton.me/download/pass-cli."
        )
    return digest


def install_pass_cli(*, force: bool = False) -> Path:
    """Download, verify, and install the pinned ``pass-cli`` binary.

    Returns the path to the installed executable.  Raises on any failure
    (network, checksum, extraction, post-install version mismatch) — callers
    in the auto-install path catch these; the user-facing ``hermes protonpass
    setup`` surface lets them propagate so the wizard can show a
    clear error.

    Verification is two-pronged: the downloaded asset's SHA-256 must match the
    pinned digest (a mismatch raises and the binary is NOT installed), and the
    STAGED binary's ``--version`` must report ``_PASS_CLI_VERSION`` BEFORE it is
    moved into place — so a version-gate failure never destroys a working
    existing binary.  Executing the staged binary here is safe: it was just
    proven (by hash) to be the pinned download (or, on Windows, extracted from
    the pinned-hash archive), unlike the later VERIFICATION path which must
    never run an on-disk managed copy it has not first hash-checked.

    Windows sidecar: the pinned digest is the ``.zip`` archive's, not the
    extracted ``.exe``'s, so the extracted exe can't be hash-matched against the
    pinned table on later verification.  We therefore compute the extracted
    exe's SHA-256 here and write it to a 0600 sidecar (``<binary>.sha256``);
    :func:`_managed_binary_verified` checks the exe against that stored digest
    (no execution) on every subsequent ``find_pass_cli``.  The sidecar is staged
    and replaced atomically (digest written to a staged tempfile FIRST, then the
    exe and sidecar each ``os.replace``'d into place); on any failure both
    staged files AND the target are removed so a crash can't leave a
    trusted-looking exe without a valid sidecar (fail-closed → clean reinstall).
    """
    bin_dir = _ensure_bin_dir()
    target = bin_dir / _platform_binary_name()

    if target.exists() and not force:
        # Re-verify rather than reporting success on a stale/non-exec binary.
        if _managed_binary_verified(target):
            return target
        # Existing target is invalid (wrong version, hash mismatch, or not
        # executable); reinstall it instead of trusting it.
        logger.warning(
            "Existing managed pass-cli at %s failed verification; reinstalling",
            target,
        )

    asset_name = _platform_asset_name()
    asset_url = f"{_PASS_CLI_DOWNLOAD_BASE}/{asset_name}"

    expected = _expected_sha256(asset_name)

    with tempfile.TemporaryDirectory(prefix="hermes-pass-cli-") as tmpdir:
        tmp = Path(tmpdir)
        download_path = tmp / asset_name

        logger.info("Downloading %s", asset_url)
        _http_download(asset_url, download_path)

        actual = _sha256_file(download_path)
        if expected.lower() != actual.lower():
            raise RuntimeError(
                f"Checksum mismatch for {asset_name}: expected {expected}, got {actual}"
            )

        # macOS/Linux assets are raw binaries; Windows ships a zip.
        if asset_name.endswith(".zip"):
            import zipfile

            with zipfile.ZipFile(download_path) as zf:
                member = _pick_zip_member(zf, _platform_binary_name())
                zf.extract(member, tmp)
                extracted = tmp / member
        else:
            extracted = download_path

        # Stage into a sibling tempfile in the FINAL directory (so the later
        # rename can't cross filesystems), then version-gate the STAGED copy
        # BEFORE replacing the target.  A version-gate failure must not destroy
        # an existing working binary, so we verify before any os.replace.  The
        # staged file carries the platform suffix (``.exe`` on Windows) because
        # CreateProcess requires the extension to run the version gate below.
        suffix = ".exe" if platform.system() == "Windows" else ""
        fd, staged = tempfile.mkstemp(
            dir=str(bin_dir), prefix=".pass-cli_", suffix=suffix
        )
        os.close(fd)
        # Staged sidecar (Windows only); kept alongside ``staged`` so a failure
        # can unlink both.  Populated below for the zip platform.
        staged_sidecar: Optional[str] = None
        # Becomes True once we START mutating the final target (first
        # os.replace).  Before that point a failure (e.g. the version gate)
        # must NOT touch an existing working binary; after it, we fail closed
        # and remove the half-installed pair so the next run reinstalls.
        replacing = False
        try:
            shutil.copy2(extracted, staged)
            os.chmod(
                staged,
                stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IRGRP
                | stat.S_IXGRP
                | stat.S_IROTH
                | stat.S_IXOTH,
            )
            # Pre-replace gate: the staged binary must report the pinned
            # version.  A digest-matched-but-version-wrong binary (mispinned
            # table, swapped asset) must not become the trusted copy, and must
            # not clobber a working one.
            reported = _read_pass_cli_version(Path(staged))
            if not _version_token_matches(reported):
                raise RuntimeError(
                    f"Downloaded pass-cli does not report the pinned version "
                    f"{_PASS_CLI_VERSION} (got {reported!r}); kept the existing "
                    "binary. This usually means the pinned asset or hash table "
                    "is out of sync."
                )
            # On the Windows zip platform, capture the extracted exe's SHA-256
            # from the STAGED copy (still proven-good via the pinned archive
            # hash) so later verification can hash-match it WITHOUT execution.
            staged_digest = (
                _sha256_file(Path(staged)) if asset_name.endswith(".zip") else None
            )

            # FAIL-CLOSED sidecar atomicity (Windows zip platform):
            # _managed_binary_verified treats an exe with no valid sidecar as
            # UNVERIFIED, so a crash AFTER the exe replace but BEFORE the
            # sidecar write would leave a trusted-looking exe that later fails
            # closed.  Tighten the ordering: write the digest to a STAGED
            # sidecar (0600) FIRST, then replace the exe, then replace the
            # sidecar.  On ANY failure we unlink both staged files AND the
            # target, so the next find_pass_cli reinstalls from scratch rather
            # than reading a half-written pair.
            if staged_digest is not None:
                fd_s, staged_sidecar = tempfile.mkstemp(
                    dir=str(bin_dir), prefix=".pass-cli-sha256_"
                )
                os.close(fd_s)
                _write_sidecar_digest(target, staged_digest, path=Path(staged_sidecar))
                replacing = True
                os.replace(staged, target)
                os.replace(staged_sidecar, _sidecar_digest_path(target))
                staged_sidecar = None  # consumed by the replace above
            else:
                replacing = True
                os.replace(staged, target)
            staged = None  # consumed by the replace above
        except BaseException:
            # Always discard the staged tempfiles.
            for leftover in (staged, staged_sidecar):
                if leftover is None:
                    continue
                try:
                    os.unlink(leftover)
                except OSError:
                    pass
            # Only fail closed on the TARGET once we've begun mutating it: a
            # failure during the replace sequence could leave a trusted-looking
            # exe without a valid sidecar, so remove the target + sidecar so the
            # next find_pass_cli reinstalls cleanly.  A pre-replace failure
            # (e.g. the version gate) leaves any existing working binary intact.
            if replacing:
                try:
                    os.unlink(target)
                except OSError:
                    pass
                try:
                    os.unlink(_sidecar_digest_path(target))
                except OSError:
                    pass
            raise

    logger.info("Installed pass-cli %s at %s", _PASS_CLI_VERSION, target)
    return target


def _http_download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "hermes-agent"})
    try:
        with urllib.request.urlopen(req, timeout=_PASS_CLI_DOWNLOAD_TIMEOUT) as resp:  # noqa: S310
            # Reject a non-2xx response up front (urllib raises HTTPError for
            # most of these, but guard explicitly in case a handler returns a
            # redirect/other status object).
            status = getattr(resp, "status", None)
            if status is None:
                status = resp.getcode()
            if status is not None and not (200 <= int(status) < 300):
                raise RuntimeError(f"Refusing to download {url}: HTTP status {status}")
            # Reject an oversized Content-Length up front when present.
            declared = resp.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > _MAX_DOWNLOAD_BYTES:
                        raise RuntimeError(
                            f"Refusing to download {url}: declared size "
                            f"{declared} bytes exceeds cap "
                            f"{_MAX_DOWNLOAD_BYTES}"
                        )
                except ValueError:
                    pass  # unparsable header — fall through to streaming cap
            # Stream with a hard byte cap so a lying/absent Content-Length
            # can't exhaust the disk.
            total = 0
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD_BYTES:
                        raise RuntimeError(
                            f"Refusing to download {url}: exceeded size cap "
                            f"{_MAX_DOWNLOAD_BYTES} bytes"
                        )
                    f.write(chunk)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Failed to download {url}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to download {url}: {exc}") from exc


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_unsafe_zip_member(name: str) -> bool:
    """True if a zip member name would escape the extraction dir (zip-slip).

    Rejects absolute paths (POSIX ``/foo`` or Windows ``C:\\foo`` / ``\\foo``)
    and any path with a ``..`` traversal component.  We normalise backslashes
    to forward slashes first because upstream ships a Windows zip and zip
    entries may use either separator.
    """
    if not name:
        return True
    norm = name.replace("\\", "/")
    # Absolute POSIX path, or Windows drive-letter / UNC-style absolute.  The
    # drive-letter check operates on the NORMALISED path so that both
    # ``C:\foo`` and ``C:/foo`` are caught (the raw name only catches the
    # backslash form).
    if norm.startswith("/") or (len(norm) >= 2 and norm[1] == ":"):
        return True
    parts = norm.split("/")
    return any(p == ".." for p in parts)


def _pick_zip_member(zf, binary_name: str) -> str:
    """Find the binary inside the upstream zip (Windows only).

    Tolerate a top-level directory in case upstream nests the binary, but
    reject any member with an absolute path or a ``..`` component BEFORE we
    hand a name to ``zf.extract`` (zip-slip defence).
    """
    safe_names = [n for n in zf.namelist() if not _is_unsafe_zip_member(n)]
    candidates = [n for n in safe_names if n.split("/")[-1] == binary_name]
    if not candidates:
        raise RuntimeError(
            f"Could not find {binary_name} inside downloaded archive "
            f"(members: {zf.namelist()[:5]}...)"
        )
    # Prefer the shortest path (i.e. root over nested) for determinism.
    candidates.sort(key=len)
    return candidates[0]
