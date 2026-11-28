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

D42 adds the second source a sample can arrive from: a **stream**. A pipe has
no ``lstat``, so the stat-based rule cannot run in front of the read. The
equivalent guarantee is :func:`read_sample_stream` — the limit bounds the
allocation and the store *while reading*, so nothing above it is ever held in
memory and nothing at all is written. What a stream cannot do is refuse before
the read: bytes already crossed the pipe, and a socket read cannot be undone.
That is the one difference from a file, it is stated rather than glossed, and it
is why the HTTP layer keeps its own earlier refusal.

The caller translates :class:`SampleSourceError` into its own error type, so the
store keeps raising ``SampleStoreError`` and the CLI keeps exiting 1.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import BinaryIO

from engine.store.errors import NOT_A_FILE, NOT_FOUND, SYMLINK, TOO_LARGE


#: The chunk size a stream is read in. Below the store's own read size, so a
#: stream that runs over the limit is refused with at most one chunk of slack
#: rather than a whole sample's worth.
STREAM_CHUNK_BYTES = 64 * 1024


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


def read_sample_stream(stream: BinaryIO, *, limit: int) -> bytes:
    """Read a sample from a pipe, refusing anything above ``limit`` as it arrives.

    D42: the HTTP boundary hands the API a body stream and no file. Reading it
    with ``read()`` and checking afterwards would repeat D40's defect one layer
    up — the allocation happens before the check — so the limit is applied to
    every chunk: past it, the reader stops, raises ``too-large`` and the caller
    has stored nothing.

    The refusal is therefore *while reading*, not *before reading*. A file gets
    the stronger guarantee (D40 refuses from an ``lstat``), a socket cannot: the
    bytes are already on the wire. The API keeps its own earlier refusal
    (``limits.fileSize``, ``MAX_UPLOAD_BYTES``) so a caller who sends 300 MiB
    learns at the boundary and the engine's limit is defence in depth.

    An empty stream is returned empty; ``SampleStore.put_bytes`` owns the
    ``empty`` refusal so there is one place that decides a sample is not a
    sample.
    """
    buffer = bytearray()
    while True:
        chunk = stream.read(STREAM_CHUNK_BYTES)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > limit:
            raise SampleSourceError(
                TOO_LARGE,
                f"the sample on the stream passed the {limit}-byte store limit; "
                "the read stopped at the limit and nothing was stored",
            )
    return bytes(buffer)
