"""The sample limit is applied before the read (D40).

D39 bounded every parser behind the sample and left one unbounded read in front
of them: ``SampleUploader.upload`` did ``Path.read_bytes()`` and only then let
the store refuse anything above its 256 MiB limit. Measured on the defect: a
400 MiB sample cost **474 MiB of peak RSS to print a refusal**, and a 64 GiB
file would have been an out-of-memory kill instead of an error.

These tests pin the fix at the three entry points (upload, ``submit`` and
``static``) and for the three inputs a full read cannot survive: an oversized
regular file, a symlink, and a FIFO.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from engine.intake.uploader import SampleUploader
from engine.store import SampleStore, SampleStoreError

REPO_ROOT = Path(__file__).resolve().parent.parent


def _sparse(path: Path, size: int) -> Path:
    """A file of ``size`` bytes that occupies no disk blocks (instant, no I/O)."""
    with path.open("wb") as handle:
        handle.truncate(size)
    return path


def _cli_env(tmp_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["HATCHERY_RESULTS_ROOT"] = str(tmp_path / "results")
    env["HATCHERY_SAMPLE_STORE"] = str(tmp_path / "samples")
    env.pop("HATCHERY_SAMPLE_KEY", None)
    env.pop("HATCHERY_SAMPLE_KEY_FILE", None)
    return env


def test_an_oversized_sample_is_refused_before_it_is_read(tmp_path: Path, monkeypatch):
    store = SampleStore(tmp_path / "samples", max_bytes=1024)
    uploader = SampleUploader(store=store)

    big = _sparse(tmp_path / "big.bin", 64 * 1024 * 1024)

    def forbidden(self):  # noqa: ANN001 - the API under test
        raise AssertionError("the uploader read the whole sample before refusing it")

    monkeypatch.setattr(Path, "read_bytes", forbidden)

    with pytest.raises(SampleStoreError) as caught:
        uploader.upload(big)

    assert caught.value.reason == "too-large"
    assert "64" in caught.value.message and "1024-byte" in caught.value.message
    store.close()


def test_a_symlinked_sample_is_refused_like_the_queue_path(tmp_path: Path):
    """``submit --enqueue`` already refused symlinks; the direct path did not."""
    store = SampleStore(tmp_path / "samples")
    uploader = SampleUploader(store=store)

    real = tmp_path / "real.bin"
    real.write_bytes(b"MZ" + b"\x00" * 64)
    link = tmp_path / "link.bin"
    link.symlink_to(real)

    with pytest.raises(SampleStoreError) as caught:
        uploader.upload(link)
    assert caught.value.reason == "symlink"
    store.close()


def test_a_fifo_is_refused_instead_of_blocking(tmp_path: Path):
    """A read on a FIFO with no writer blocks forever; the stat check runs first.

    Run in a subprocess with a timeout so a regression fails the test rather
    than hanging the suite.
    """
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    program = (
        "import sys\n"
        "from pathlib import Path\n"
        "from engine.intake.uploader import SampleUploader\n"
        "from engine.store import SampleStore, SampleStoreError\n"
        "store = SampleStore(Path(sys.argv[1]) / 'samples')\n"
        "try:\n"
        "    SampleUploader(store=store).upload(Path(sys.argv[2]))\n"
        "except SampleStoreError as exc:\n"
        "    print(exc.reason, exc.message)\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(3)\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", program, str(tmp_path), str(fifo)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "not-a-file" in result.stdout


@pytest.mark.parametrize("command", ["submit", "static"])
def test_the_cli_refuses_a_64_gib_sample_quickly(command: str, tmp_path: Path):
    """64 GiB sparse: a stat refusal is instant; a read is an OOM kill."""
    big = _sparse(tmp_path / "huge.bin", 64 * 1024**3)
    run_dir = tmp_path / "run"

    args = [sys.executable, "-m", "engine.cli", command, str(big)]
    if command == "submit":
        args += ["--no-sandbox", "-o", str(run_dir)]

    started = time.monotonic()
    result = subprocess.run(
        args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        env=_cli_env(tmp_path),
    )
    elapsed = time.monotonic() - started

    assert result.returncode == 1, result.stdout[-1500:] + result.stderr[-1500:]
    assert "too-large" in (result.stdout + result.stderr)
    assert "Traceback" not in (result.stdout + result.stderr)
    assert elapsed < 20, f"{command} took {elapsed:.1f}s on a sparse 64 GiB file"
    assert not (run_dir / "bundle" / "analysis.json").exists()


def test_classification_uses_a_bounded_head_and_the_real_size(tmp_path: Path):
    """The head is enough to type the sample; the size comes from the record."""
    store = SampleStore(tmp_path / "samples")
    uploader = SampleUploader(store=store)

    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZ" + b"\x00" * (2 * 1024 * 1024))

    metadata = uploader.upload(sample)

    assert metadata.file_type == "PE"
    assert metadata.file_size == 2 * 1024 * 1024 + 2
    assert metadata.sha256 == store.read(metadata.sha256).sha256
    store.close()


def test_an_empty_sample_still_raises_value_error(tmp_path: Path):
    """The ordering change must not turn the empty-file contract into a store error."""
    store = SampleStore(tmp_path / "samples")
    uploader = SampleUploader(store=store)

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    with pytest.raises(ValueError, match="empty"):
        uploader.upload(empty)
    store.close()
