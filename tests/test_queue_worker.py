"""The queue worker (D27): executing jobs, bounded concurrency, crash recovery.

The submit runner is injected, so these tests never start a subprocess or a
container. A fake runner writes the bundle that a real ``hatchery submit -o DIR``
would write, which lets the test assert the worker's actual authority rule: the
bundle, not the exit code.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from engine.queue.store import COMPLETED, FAILED, QUEUED, RUNNING, Job, JobStore
from engine.queue.worker import Worker, WorkerConfig, build_job_command


def _output_dir(command: list[str]) -> Path:
    return Path(command[command.index("-o") + 1])


def write_bundle(command: list[str], task_id: str = "engine-task") -> Path:
    bundle_dir = _output_dir(command) / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "analysis.json").write_text(
        json.dumps({"task_id": task_id, "summary": {"events_total": 0}}), encoding="utf-8"
    )
    (bundle_dir / "events.jsonl").write_text("", encoding="utf-8")
    return bundle_dir


def runner_writing_bundle(task_id: str = "engine-task"):
    def run(command: list[str], timeout: float) -> tuple[int, str, str]:
        write_bundle(command, task_id)
        return 0, "done", ""
    return run


def test_worker_completes_a_job_and_records_the_bundle(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    job = store.enqueue(tmp_path / "sample.bin", output_dir=tmp_path / "out")
    worker = Worker(store, WorkerConfig(once=True), runner=runner_writing_bundle("t-42"))

    outcomes = worker.run_once()

    assert [outcome.status for outcome in outcomes] == [COMPLETED]
    row = store.get(job.job_id)
    assert row is not None
    assert row.status == COMPLETED
    assert row.task_id == "t-42"
    assert row.run_dir == str(tmp_path / "out" / "bundle")
    assert Path(row.run_dir).is_dir()
    store.close()


def test_exit_zero_without_a_bundle_is_a_failure(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    job = store.enqueue(tmp_path / "sample.bin", output_dir=tmp_path / "out")
    # A quiet submit that produced nothing must not be called success.
    worker = Worker(store, WorkerConfig(), runner=lambda command, timeout: (0, "looked fine", ""))

    worker.run_once()

    row = store.get(job.job_id)
    assert row is not None
    assert row.status == FAILED
    assert "no bundle" in (row.error or "")
    store.close()


def test_nonzero_exit_with_a_bundle_is_a_failure(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    job = store.enqueue(tmp_path / "sample.bin", output_dir=tmp_path / "out")

    def run(command: list[str], timeout: float) -> tuple[int, str, str]:
        write_bundle(command)
        return 2, "", "delivery intake crashed"

    worker = Worker(store, WorkerConfig(), runner=run)
    worker.run_once()

    row = store.get(job.job_id)
    assert row is not None
    assert row.status == FAILED
    assert row.exit_code == 2
    assert "delivery intake crashed" in (row.error or "")
    store.close()


def test_a_runner_exception_fails_the_job_with_the_reason(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    job = store.enqueue(tmp_path / "sample.bin", output_dir=tmp_path / "out")

    def boom(command: list[str], timeout: float) -> tuple[int, str, str]:
        raise RuntimeError("subprocess exploded")

    Worker(store, WorkerConfig(), runner=boom).run_once()

    row = store.get(job.job_id)
    assert row is not None
    assert row.status == FAILED
    assert "RuntimeError" in (row.error or "")
    store.close()


def test_concurrency_is_bounded_and_every_job_runs(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    jobs = [store.enqueue(tmp_path / f"{index}.bin", job_id=f"job-{index}") for index in range(4)]

    lock = threading.Lock()
    live = 0
    peak = 0

    def run(command: list[str], timeout: float) -> tuple[int, str, str]:
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.05)
        write_bundle(command)
        with lock:
            live -= 1
        return 0, "", ""

    worker = Worker(store, WorkerConfig(concurrency=2), runner=run)
    outcomes = worker.run_once()

    assert peak <= 2, f"concurrency exceeded the bound: peak={peak}"
    assert len(outcomes) == 4
    assert all(store.get(job.job_id).status == COMPLETED for job in jobs)  # type: ignore[union-attr]
    store.close()


def test_a_crashed_worker_is_recovered_and_the_job_finishes(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    job = store.enqueue(tmp_path / "sample.bin", output_dir=tmp_path / "out", max_attempts=3)

    # The previous worker claimed the job and died without completing it.
    claimed = store.claim("dead-worker", lease_seconds=0.05)
    assert claimed is not None
    time.sleep(0.15)

    recovered = JobStore(store.path)
    worker = Worker(recovered, WorkerConfig(), runner=runner_writing_bundle("recovered"))
    outcomes = worker.run_once()

    assert [outcome.status for outcome in outcomes] == [COMPLETED]
    row = store.get(job.job_id)
    assert row is not None
    assert row.status == COMPLETED
    assert row.attempts == 2, "the crash cost an attempt and the retry counted"
    assert row.task_id == "recovered"
    recovered.close()
    store.close()


def test_heartbeat_keeps_the_lease_alive_while_the_job_runs(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    job = store.enqueue(tmp_path / "sample.bin", output_dir=tmp_path / "out")

    started = threading.Event()
    release = threading.Event()

    def slow(command: list[str], timeout: float) -> tuple[int, str, str]:
        started.set()
        assert release.wait(5), "the test never released the fake submit"
        write_bundle(command)
        return 0, "", ""

    config = WorkerConfig(lease_seconds=0.5, heartbeat_interval=0.02)
    worker = Worker(store, config, runner=slow)
    thread = threading.Thread(target=worker.run_once, daemon=True)
    thread.start()

    assert started.wait(5), "the worker never started the job"
    first = store.get(job.job_id)
    assert first is not None
    initial_expiry = first.lease_expires_at
    assert initial_expiry is not None

    time.sleep(0.25)  # many heartbeat intervals
    during = store.get(job.job_id)
    assert during is not None
    assert during.status == RUNNING
    assert during.lease_expires_at is not None
    assert during.lease_expires_at > initial_expiry, "the lease must have been renewed"

    # even a competing worker must not recover a lease that is being renewed
    assert store.recover_expired() == []
    assert store.claim("poacher") is None

    release.set()
    thread.join(timeout=5)
    assert store.get(job.job_id).status == COMPLETED  # type: ignore[union-attr]
    store.close()


def test_worker_returns_nothing_on_an_empty_queue(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    worker = Worker(store, WorkerConfig(), runner=runner_writing_bundle())
    assert worker.run_once() == []
    # recovery is still run, so a stale running job is not stranded
    store.enqueue(tmp_path / "a.bin")
    store.claim("dead", lease_seconds=0.01)
    time.sleep(0.05)
    worker.run_once()
    assert store.counts()[RUNNING] == 0
    store.close()


def test_build_job_command_uses_absolute_paths_and_a_flag_whitelist(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    job = store.enqueue(
        tmp_path / "s.bin",
        output_dir=tmp_path / "out",
        args={
            "timeout": 45,
            "no_sandbox": True,
            "emulate": False,
            "allow_host_emulation": True,  # meaningless without --emulate
            "emulate_timeout": 99,          # ditto
            "triage": True,
            "triage_model": "mistral:7b",
            "unknown_future_option": "ignored",
        },
    )
    command = build_job_command(job, python="python-x")

    assert command[:3] == ["python-x", "-m", "engine.cli"]
    assert command[command.index("-o") + 1] == str(tmp_path / "out")
    assert "--no-sandbox" in command
    assert "--triage" in command
    assert command[command.index("--triage-model") + 1] == "mistral:7b"
    assert command[command.index("--timeout") + 1] == "45"
    assert "--allow-host-emulation" not in command
    assert "--emulate-timeout" not in command
    assert "unknown_future_option" not in " ".join(command)
    store.close()


def test_worker_config_rejects_a_nonpositive_concurrency() -> None:
    import pytest

    with pytest.raises(ValueError, match="concurrency"):
        WorkerConfig(concurrency=0)
    with pytest.raises(ValueError, match="lease_seconds"):
        WorkerConfig(lease_seconds=0)


def test_job_to_dict_is_json_serialisable() -> None:
    job = Job(job_id="j", status=QUEUED, sample_path="/s", output_dir="/o")
    json.dumps(job.to_dict())
