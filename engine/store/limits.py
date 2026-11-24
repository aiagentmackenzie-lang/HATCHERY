"""The one rule for what may be read as a sample, applied before the read (D40).

D39 bounded every parser behind the sample; it left one unbounded read in front
of them. ``SampleUploader.upload`` did ``Path.read_bytes()`` and only then
handed the bytes to the store, which refused anything above its 256 MiB limit —
so a 400 MiB sample cost **474 MiB of RSS to print a refusal** (measured), and a
64 GiB file was an out-of-memory kill instead of an error. The same shape as the
five ``read_bytes()`` sites D39 fixed one layer down: the check ran after the
allocation it was meant to prevent.

This module is that check, in one place, with the store's own reason codes
(``symlink``, ``not-a-file``, ``too-large``) so an operator sees one vocabulary.
It runs on ``lstat`` — before any bytes are read — and it refuses the three
inputs a full read cannot survive:

* a symlink (the store never follows one; the direct ``submit`` path used to),
* anything that is not a regular file (a FIFO blocks a read forever; a device
  can be endless),
* a file larger than the limit (stat first, then a bounded read; a file that
  grows between the two is caught by the reader).

The caller translates :class:`SampleSourceError` into its own error type, so the
store keeps raising ``SampleStoreError`` and the CLI keeps exiting 1.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from engine.store.errors import NOT_A_FILE, NOT_FOUND, SYMLINK, TOO_LARGE


class SampleSourceError(ValueError):
    """A file that cannot be read as a sample, with a stable ``reason`` code."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        self.message = message
        super().__init__(f"{reason}: {message}" if message else reason)


def check_sample_source(path: Path | str, *, limit: int) -> os.stat_result:
    """``lstat`` ``path`` and refuse it unless it is a regular file within ``limit``.

    Returns the ``stat`` result so a caller can use the size it already checked.
    Nothing is opened: the point is that none of these refusals may allocate the
    sample.
    """
    source = Path(path)
    try:
        info = os.lstat(source)
    except FileNotFoundError as exc:
        raise SampleSourceError(
            NOT_FOUND, f"the sample file {source} does not exist"
        ) from exc
    if stat.S_ISLNK(info.st_mode):
        raise SampleSourceError(
            SYMLINK, f"{source} is a symlink; refusing to follow it"
        )
    if not stat.S_ISREG(info.st_mode):
        raise SampleSourceError(
            NOT_A_FILE,
            f"{source} is not a regular file; refusing to read it",
        )
    if info.st_size > limit:
        raise SampleSourceError(
            TOO_LARGE,
            f"{source} is {info.st_size} bytes, above the "
            f"{limit}-byte store limit",
        )
    return info
