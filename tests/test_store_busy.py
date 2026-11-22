"""A busy sample store is a named error, not a traceback (D34).

``busy_timeout`` does not apply to ``PRAGMA journal_mode = WAL``: three
simultaneous openers could make one ``SampleStore()`` raise
``sqlite3.OperationalError: database is locked`` straight through the CLI. These
tests use one real store on purpose, because the store is exactly what is under
test: N concurrent real ``hatchery submit`` processes, and a forced-busy
constructor that must fail closed with ``store-busy`` and exit 1.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from _results_builder import SAMPLE, base_env
from engine.results import verify_run
from engine.store import SampleStore, SampleStoreError, index as index_module


# ---------------------------------------------------------------------------
# 1. N real submits, one store
# ---------------------------------------------------------------------------


def test_concurrent_submits_against_one_store_all_exit_zero_and_verify(
    tmp_path: Path,
) -> None:
    env = base_env(tmp_path)
    results = tmp_path / "results"
    results.mkdir()
    start = time.time() + 3.0
    launcher = r"""
import sys, time
start = float(sys.argv[1])
while time.time() < start:
    pass
sys.argv = ["hatchery", "submit", sys.argv[2], "--no-sandbox", "-o", sys.argv[3]]
from engine.cli import cli
cli()
"""
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                launcher,
                str(start),
                str(SAMPLE),
                str(results / f"run-{index}"),
            ],
            cwd=tmp_path,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(5)
    ]
    outcomes = [process.communicate(timeout=900) for process in processes]

    for index, (process, (stdout, stderr)) in enumerate(zip(processes, outcomes)):
        assert process.returncode == 0, f"run-{index}: {stdout[-2000:]}{stderr[-2000:]}"
        assert "Traceback" not in stderr, stderr[-2000:]
        assert "OperationalError" not in stderr, stderr[-2000:]
        assert "database is locked" not in stderr, stderr[-2000:]
        report = verify_run(results / f"run-{index}")
        assert report["ok"] is True
        assert report["state"] == "intact"

    # One store, five samples' worth of one sample: content-addressed, so one
    # blob, and every run that wrote one verifies.
    assert len(list((tmp_path / "samples").glob("*.sample"))) == 1


# ---------------------------------------------------------------------------
# 2. A forced busy pragma fails closed
# ---------------------------------------------------------------------------


def _busy(_conn: object, _path: str) -> None:
    import sqlite3

    raise sqlite3.OperationalError("database is locked")


def test_a_forced_busy_store_raises_store_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(index_module, "_set_journal_mode", _busy)
    monkeypatch.setattr(index_module, "BUSY_TIMEOUT_SECONDS", 0.05)

    with pytest.raises(SampleStoreError) as excinfo:
        SampleStore(tmp_path / "samples")
    assert excinfo.value.reason == "store-busy"
    assert "another process" in excinfo.value.message


@pytest.mark.parametrize("enqueue", [False, True])
def test_a_busy_store_is_exit_one_without_a_traceback(
    tmp_path: Path, enqueue: bool
) -> None:
    env = base_env(tmp_path)
    args = ["submit", str(SAMPLE), "--no-sandbox", "-o", str(tmp_path / "results" / "run")]
    if enqueue:
        args = ["submit", str(SAMPLE), "--enqueue"]
    wrapper = r"""
import sqlite3, sys
from engine.store import index

def busy(conn, path):
    raise sqlite3.OperationalError("database is locked")

index._set_journal_mode = busy
index.BUSY_TIMEOUT_SECONDS = 0.05
sys.argv = ["hatchery", *sys.argv[1:]]
from engine.cli import cli
cli()
"""
    result = subprocess.run(
        [sys.executable, "-c", wrapper, *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1, output[-3000:]
    assert "store-busy" in output, output[-3000:]
    assert "Cannot store the sample" in output, output[-3000:]
    assert "Traceback" not in output, output[-3000:]
    assert "OperationalError" not in output, output[-3000:]
    # No run directory was half-created around the failed store construction.
    if not enqueue:
        assert not (tmp_path / "results" / "run").exists()


def test_an_enqueued_job_is_recorded_only_after_the_store_accepts_it(
    tmp_path: Path,
) -> None:
    """The healthy path still enqueues and the worker path is untouched."""
    env = base_env(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "engine.cli", "submit", str(SAMPLE), "--enqueue"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["job_id"]
    assert payload["sample_store_ref"]
    assert "Traceback" not in result.stderr
