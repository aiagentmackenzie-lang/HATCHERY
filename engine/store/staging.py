"""A single-use plaintext staging file for the path-based pipeline (D28).

The analysis pipeline — YARA, capa, delivery intake, ``put_archive`` — reads a
sample from a *path*. The store therefore decrypts in memory and hands the
submit pipeline a staging path for the duration of one run. The staging file

* lives in a fresh ``0700`` directory under the system temporary directory,
  never inside the store or the results root;
* is created ``0600`` and written with ``O_EXCL``;
* is unlinked in a ``finally`` **and** at interpreter exit, so an exception,
  a failed analysis or a ``SystemExit`` cannot leave it behind;
* is never registered in the index and cannot be mistaken for a stored sample
  (the store only recognises ``<64-hex>.sample`` blobs in its own root).

What this does **not** survive is SIGKILL or power loss, which can leave a
plaintext file in the OS temporary directory. That is stated in D28 and in
``docs/RETENTION.md`` rather than glossed over: the guarantee this phase makes
is that no plaintext sample is written *into the store*, its temporaries, its
index, a bundle or the results tree. Avoiding a staging file altogether would
mean teaching every path-based analyser to read bytes, which is a larger change
than this slice.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

STAGE_PREFIX = "hatchery-stage-"


class StagedPlaintext:
    """A plaintext file that exists only while this object is open."""

    def __init__(self, data: bytes, filename: str = "sample", *, directory: Optional[Path] = None) -> None:
        self._directory = Path(tempfile.mkdtemp(prefix=STAGE_PREFIX, dir=str(directory) if directory else None))
        try:
            os.chmod(self._directory, 0o700)
        except OSError:  # pragma: no cover - platforms without chmod
            pass
        safe_name = Path(filename).name or "sample"
        self.path = self._directory / safe_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._closed = False
        self._registered = True
        atexit.register(self.close)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.unlink(self.path)
        except OSError:
            pass
        try:
            shutil.rmtree(self._directory, ignore_errors=True)
        except OSError:  # pragma: no cover - rmtree does not raise with ignore_errors
            pass
        if self._registered:
            self._registered = False
            try:
                atexit.unregister(self.close)
            except Exception:  # pragma: no cover - Python < 3.9 guard
                pass

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        # The path is fine to show; the contents are never part of the repr.
        return f"StagedPlaintext(path={str(self.path)!r}, closed={self._closed})"


@contextmanager
def stage_plaintext(
    data: bytes, filename: str = "sample", *, directory: Optional[Path] = None
) -> Iterator[Path]:
    """Yield a path to ``data`` and remove it on exit, whatever happens."""
    staged = StagedPlaintext(data, filename, directory=directory)
    try:
        yield staged.path
    finally:
        staged.close()


__all__ = ["STAGE_PREFIX", "StagedPlaintext", "stage_plaintext"]
