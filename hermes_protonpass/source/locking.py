"""Bounded, process-safe file locking using only the standard library.

The caller owns directory creation and permissions. Lock files must remain at
the same path and must never be deleted, including when a holder exits.
"""

from __future__ import annotations

import errno
import math
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def _try_lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        # Windows permits locking a byte range beyond EOF, including a new
        # empty file. No initialization write can race an existing holder.
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        # flock is tied to the open file description, unlike process-wide
        # lockf locks that another thread can inadvertently release.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def exclusive_file_lock(path: Path, *, timeout: float) -> Iterator[None]:
    """Hold an exclusive lock, or raise TimeoutError within ``timeout`` seconds.

    Separate opens exclude both other processes and other threads. Acquisition
    is not reentrant: the transaction owner must not acquire this lock again.
    Closing the descriptor releases the OS lock even if explicit unlock fails.
    """
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("Lock timeout must be finite and non-negative")
    deadline = time.monotonic() + timeout
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    if path.is_symlink():
        raise OSError("Refusing a symlinked Proton Pass lock file")
    fd = os.open(path, flags, 0o600)
    acquired = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("Proton Pass lock file is not a regular file")
        while True:
            try:
                _try_lock(fd)
                acquired = True
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Timed out waiting for the Proton Pass session transaction"
                    ) from None
                time.sleep(min(0.05, remaining))
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Timed out waiting for the Proton Pass session transaction"
                    )
        yield
    finally:
        try:
            if acquired:
                _unlock(fd)
        finally:
            os.close(fd)
