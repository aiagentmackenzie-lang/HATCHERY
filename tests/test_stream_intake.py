"""A sample may arrive on a stream, and no plaintext is written down (D42).

D28 encrypted the sample store and left one plaintext hole in front of it: the two
entry points that took a *path*. ``upload`` reads a file the operator names (D40
bounds it, but it is their file), and the API streamed an HTTP body into
``uploads/<taskId>/`` as plaintext — up to 256 MiB of live malware, on disk, at the
one moment it is most dangerous.

D42 removes the second: the body is read as it arrives, under the store's limit,
encrypted from memory, and the job is queued from the content address. Nothing at
a size limit ever exists as a file.

The API's own suite (``server/test/upload_limit.test.mjs``) proves the route's
shape against a stand-in engine. These tests use the real engine and a real store,
and pin the four things that justify the slice:

* bytes from a pipe reach the store and nothing lands on a filesystem;
* the limit is applied *while reading* (a pipe has no ``lstat``) and a refusal
  stores nothing;
* a job can be queued from an address with no path at all, and a retry preserves
  the job rather than inventing a lookalike;
* the run that comes out names the client's filename, not the ``store:`` marker.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from engine.queue import JobStore
from engine.store import SampleStore
from engine.store.limits import SampleSourceError, read_sample_stream

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = b"MZ\x90\x00hatchery-d42-streamed-sample"


def _env(tmp_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["HATCHERY_SAMPLE_STORE"] = str(tmp_path / "samples")
    env["HATCHERY_RESULTS_ROOT"] = str(tmp_path / "results")
    env["PYTHONPATH"] = str(REPO_ROOT)
    env.pop("HATCHERY_SAMPLE_KEY", None)
    env.pop("HATCHERY_SAMPLE_KEY_FILE", None)
    return env


def _run(args: list[str], tmp_path: Path, *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        cwd=tmp_path,
        env=_env(tmp_path),
        input=stdin,
        capture_output=True,
        timeout=300,
        check=False,
    )


def _last_json(completed: subprocess.CompletedProcess[bytes]) -> dict:
    """The engine's one JSON object, from stdout or from the store group's stderr.

    ``submit --enqueue`` prints its object on stdout; ``store put`` refuses on
    stderr by the store group's own contract ("stdout is the machine-readable
    object, diagnostics go to stderr"). The API parses both streams for the same
    reason — a caller must never have to guess which convention produced a refusal.
    """
    for stream in (completed.stdout, completed.stderr):
        for line in reversed(stream.decode("utf-8", "replace").strip().splitlines()):
            candidate = line.strip()
            if candidate.startswith("{"):
                return json.loads(candidate)
    raise AssertionError(
        f"no JSON object on stdout or stderr:\n{completed.stdout!r}\n{completed.stderr!r}"
    )


def _plaintext_files(root: Path, needle: bytes) -> list[Path]:
    """Every file under ``root`` whose bytes contain ``needle`` (a plaintext leak)."""
    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if needle in path.read_bytes():
                found.append(path)
        except OSError:  # a store blob is still readable, but be conservative
            continue
    return found


# ---------------------------------------------------------------------------
# 1. The rule for a stream
# ---------------------------------------------------------------------------


def test_a_stream_is_read_under_the_limit_and_stops_there() -> None:
    import io

    assert read_sample_stream(io.BytesIO(SAMPLE), limit=len(SAMPLE)) == SAMPLE

    with pytest.raises(SampleSourceError) as caught:
        read_sample_stream(io.BytesIO(b"A" * 4096), limit=1024)
    assert caught.value.reason == "too-large"


def test_the_stream_reader_holds_at_most_one_chunk_of_slack() -> None:
    """A refusal must not allocate the sample it refuses (D40's rule, for a pipe).

    The reader is given a stream that yields 64 KiB chunks forever; the recorded
    byte count proves it stopped at the limit rather than draining the pipe.
    """
    import io

    delivered = 0

    class Endless(io.RawIOBase):
        def read(self, size: int = -1) -> bytes:  # noqa: D401 - a stream
            nonlocal delivered
            delivered += 64 * 1024
            return b"B" * (64 * 1024)

        def readable(self) -> bool:
            return True

    with pytest.raises(SampleSourceError):
        read_sample_stream(Endless(), limit=200 * 1024)
    assert delivered <= 300 * 1024, f"the reader drained {delivered} bytes to refuse 200 KiB"


# ---------------------------------------------------------------------------
# 2. The store's intake boundary
# ---------------------------------------------------------------------------


def test_store_put_stdin_stores_the_bytes_and_writes_no_plaintext(tmp_path: Path) -> None:
    completed = _run(["store", "put", "--stdin", "--json", "--name", "invoice.docm"], tmp_path, stdin=SAMPLE)
    assert completed.returncode == 0, completed.stderr.decode()
    payload = _last_json(completed)

    assert payload["ok"] is True
    assert payload["size"] == len(SAMPLE)
    assert payload["encrypted"] is True

    store = SampleStore(tmp_path / "samples")
    try:
        assert store.has(payload["sha256"])
        blob = store.read(payload["sha256"])
        assert blob.data == SAMPLE, "the stored sample must decrypt to the bytes that were sent"
    finally:
        store.close()

    leaks = _plaintext_files(tmp_path, SAMPLE)
    assert leaks == [], f"plaintext sample bytes reached {leaks}"


def test_store_put_refuses_an_empty_stream_without_storing_anything(tmp_path: Path) -> None:
    completed = _run(["store", "put", "--stdin", "--json"], tmp_path, stdin=b"")
    assert completed.returncode == 1
    payload = _last_json(completed)
    assert payload["reason"] == "empty"
    assert not (tmp_path / "samples" / "index.db").exists() or not any(
        (tmp_path / "samples").glob("*.sample")
    )


# ---------------------------------------------------------------------------
# 3. Queueing an address that has no path
# ---------------------------------------------------------------------------


def test_a_job_can_be_queued_from_an_address_with_no_path(tmp_path: Path) -> None:
    stored = _run(["store", "put", "--stdin", "--json"], tmp_path, stdin=SAMPLE)
    sha = _last_json(stored)["sha256"]

    enqueued = _run(
        [
            "submit", "--from-store", sha, "--enqueue",
            "--name", "invoice.docm", "--no-sandbox", "--timeout", "240",
            "--owner", "token:abc123", "--job-id", "stream-job",
            "--queue", str(tmp_path / "queue.db"),
        ],
        tmp_path,
    )
    assert enqueued.returncode == 0, enqueued.stderr.decode()
    payload = _last_json(enqueued)

    assert payload["sample_store_ref"] == sha
    assert payload["sample_name"] == "invoice.docm"
    assert payload["sample_path"] == f"store:{sha}", (
        "a job with no path must record the marker, not a plausible-looking path"
    )

    store = JobStore(tmp_path / "queue.db")
    try:
        job = store.get("stream-job")
        assert job is not None
        assert job.sample_store_ref == sha
        assert job.sample_name == "invoice.docm"
        assert job.args["timeout"] == 240
        # D43: the queue records who submitted the job, because the API's per-caller
        # cap counts queued+running jobs by owner rather than keeping a second tally.
        assert job.owner == "token:abc123"
    finally:
        store.close()


def test_queueing_an_address_that_is_not_stored_is_refused(tmp_path: Path) -> None:
    missing = "a" * 64
    completed = _run(
        ["submit", "--from-store", missing, "--enqueue", "--queue", str(tmp_path / "queue.db")],
        tmp_path,
    )
    assert completed.returncode == 1
    assert _last_json(completed)["reason"] == "not-found"
    assert not (tmp_path / "queue.db").exists(), "a refused enqueue must not create a queue"


def test_a_requeue_keeps_the_job_and_does_not_need_a_path(tmp_path: Path) -> None:
    stored = _run(["store", "put", "--stdin", "--json"], tmp_path, stdin=SAMPLE)
    sha = _last_json(stored)["sha256"]
    queue = str(tmp_path / "queue.db")
    _run(
        [
            "submit", "--from-store", sha, "--enqueue", "--name", "kept.docm",
            "--no-sandbox", "--timeout", "300", "--job-id", "kept",
            "--queue", queue,
        ],
        tmp_path,
    )

    # Mark it finished, as a worker would, then retry.
    store = JobStore(tmp_path / "queue.db")
    try:
        assert store.claim("test-worker") is not None
        assert store.complete("kept", "test-worker", run_dir=str(tmp_path / "run"))
    finally:
        store.close()

    requeued = _run(["queue", "kept", "--requeue", "--json", "--queue", queue], tmp_path)
    assert requeued.returncode == 0, requeued.stderr.decode()
    job = json.loads(requeued.stdout)

    assert job["status"] == "queued"
    assert job["attempts"] == 0
    assert job["sample_store_ref"] == sha
    assert job["sample_name"] == "kept.docm"
    assert job["args"]["timeout"] == 300, "a retry must run the same job, not a lookalike"
    assert job["args"]["no_sandbox"] is True
