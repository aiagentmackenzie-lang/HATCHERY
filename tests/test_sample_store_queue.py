"""Queue integration and the versioned queue migration (D27 + D28).

A job records the content address it will run, so deleting the original path
does not break it. A pre-D28 queue keeps its job ids and states and gains the
column additively; its queued jobs are adopted into the store on claim or by
``hatchery store migrate``, never silently dropped.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from _store_builder import make_queue_db, make_store

from engine.queue.store import (
    QUEUE_SCHEMA_VERSION,
    JobError,
    JobStore,
)
from engine.queue.worker import Worker, WorkerConfig, build_job_command


def _job_row_count(path: Path) -> int:
    conn = sqlite3.connect(str(path))
    try:
        return int(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
    finally:
        conn.close()


def _columns(path: Path) -> set[str]:
    conn = sqlite3.connect(str(path))
    try:
        return {str(row[1]) for row in conn.execute("PRAGMA table_info(jobs)")}
    finally:
        conn.close()


def test_a_pre_d28_queue_is_migrated_additively_and_preserves_ids_and_states(
    tmp_path: Path,
) -> None:
    queue_db = make_queue_db(
        tmp_path / "queue.db",
        [
            {"job_id": "old-queued", "sample_path": "/gone/a.bin", "status": "queued"},
            {
                "job_id": "old-completed",
                "sample_path": "/gone/b.bin",
                "status": "completed",
                "attempts": 2,
            },
            {"job_id": "old-failed", "sample_path": "/gone/c.bin", "status": "failed"},
        ],
    )
    before = _job_row_count(queue_db)
    assert "sample_store_ref" not in _columns(queue_db)

    store = JobStore(queue_db)
    try:
        assert "sample_store_ref" in _columns(queue_db)
        conn = sqlite3.connect(str(queue_db))
        try:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        finally:
            conn.close()
        assert version == QUEUE_SCHEMA_VERSION
        assert _job_row_count(queue_db) == before

        queued = store.get("old-queued")
        assert queued is not None
        assert queued.status == "queued"
        assert queued.sample_store_ref is None
        completed = store.get("old-completed")
        assert completed is not None
        assert completed.status == "completed" and completed.attempts == 2
        failed = store.get("old-failed")
        assert failed is not None and failed.status == "failed"
    finally:
        store.close()

    # Re-opening is idempotent: no second column, no lost rows.
    again = JobStore(queue_db)
    again.close()
    assert "sample_store_ref" in _columns(queue_db)
    assert _job_row_count(queue_db) == before


def test_a_queue_from_a_newer_build_is_refused(tmp_path: Path) -> None:
    queue_db = make_queue_db(tmp_path / "queue.db", [])
    conn = sqlite3.connect(str(queue_db))
    conn.execute(f"PRAGMA user_version = {QUEUE_SCHEMA_VERSION + 5}")
    conn.commit()
    conn.close()
    with pytest.raises(JobError, match="newer build"):
        JobStore(queue_db)


def test_enqueue_records_the_content_address_and_store_reference(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "queue.db")
    sha = hashlib.sha256(b"queued bytes").hexdigest()
    job = store.enqueue(
        tmp_path / "original.bin",
        sample_sha256=sha,
        sample_store_ref=sha,
        output_dir=tmp_path / "out",
    )
    assert job.sample_sha256 == sha
    assert job.sample_store_ref == sha
    payload = json.loads(json.dumps(job.to_dict()))
    assert payload["sample_store_ref"] == sha
    store.close()


def test_attach_sample_is_owner_checked_while_running(tmp_path: Path) -> None:
    jobs = JobStore(tmp_path / "queue.db")
    job = jobs.enqueue(tmp_path / "original.bin", output_dir=tmp_path / "out")
    claimed = jobs.claim("worker-a", lease_seconds=60)
    assert claimed is not None

    sha = hashlib.sha256(b"adopted").hexdigest()
    assert jobs.attach_sample(job.job_id, sha256=sha, store_ref=sha, worker_id="worker-b") is False
    assert jobs.attach_sample(job.job_id, sha256=sha, store_ref=sha, worker_id="worker-a") is True
    row = jobs.get(job.job_id)
    assert row is not None and row.sample_store_ref == sha
    jobs.close()


def test_the_worker_adopts_a_legacy_job_then_runs_it_from_the_store(tmp_path: Path) -> None:
    sample = tmp_path / "legacy.bin"
    sample.write_bytes(b"legacy queued sample")
    sha = hashlib.sha256(b"legacy queued sample").hexdigest()
    queue_db = make_queue_db(
        tmp_path / "pre-d28.db",
        [
            {
                "job_id": "legacy-job",
                "sample_path": str(sample),
                "status": "queued",
                "output_dir": str(tmp_path / "out"),
            }
        ],
    )

    commands: list[list[str]] = []

    def runner(command: list[str], timeout: float) -> tuple[int, str, str]:
        commands.append(command)
        out = Path(command[command.index("-o") + 1])
        (out / "bundle").mkdir(parents=True, exist_ok=True)
        (out / "bundle" / "analysis.json").write_text(
            json.dumps({"task_id": "legacy-task"}), encoding="utf-8"
        )
        return 0, "", ""

    jobs = JobStore(queue_db)
    worker = Worker(
        jobs,
        WorkerConfig(),
        runner=runner,
        sample_store=make_store(tmp_path),
    )
    outcomes = worker.run_once()

    assert [outcome.status for outcome in outcomes] == ["completed"]
    row = jobs.get("legacy-job")
    assert row is not None
    assert row.status == "completed"
    assert row.sample_sha256 == sha
    assert row.sample_store_ref == sha
    assert commands and "--from-store" in commands[0]
    assert commands[0][commands[0].index("--from-store") + 1] == sha
    assert str(sample) in commands[0], "the original path is kept as a hint only"

    store = make_store(tmp_path)
    assert store.read(sha).data == b"legacy queued sample"
    store.close()
    jobs.close()


def test_a_legacy_job_whose_sample_is_gone_fails_with_the_reason_and_is_kept(
    tmp_path: Path,
) -> None:
    queue_db = make_queue_db(
        tmp_path / "pre-d28.db",
        [{"job_id": "orphan", "sample_path": str(tmp_path / "gone.bin"), "status": "queued"}],
    )
    jobs = JobStore(queue_db)
    worker = Worker(
        jobs,
        WorkerConfig(),
        runner=lambda command, timeout: (0, "", ""),
        sample_store=make_store(tmp_path),
    )
    outcomes = worker.run_once()

    assert [outcome.status for outcome in outcomes] == ["failed"]
    row = jobs.get("orphan")
    assert row is not None
    assert row.status == "failed"
    assert "gone" in (row.error or "")
    assert row.run_dir is None
    jobs.close()


def test_migrate_adopts_only_queued_legacy_jobs_and_reports_failures(tmp_path: Path) -> None:
    sample = tmp_path / "present.bin"
    sample.write_bytes(b"present sample")
    queue_db = make_queue_db(
        tmp_path / "pre-d28.db",
        [
            {"job_id": "queued-present", "sample_path": str(sample), "status": "queued"},
            {"job_id": "queued-gone", "sample_path": str(tmp_path / "gone.bin"), "status": "queued"},
            {"job_id": "done", "sample_path": str(sample), "status": "completed"},
        ],
    )
    store = make_store(tmp_path)
    report = store.migrate(apply=True, queue_db=queue_db)

    assert report["adopted_queue_jobs"] == [
        {"job_id": "queued-present", "sha256": hashlib.sha256(b"present sample").hexdigest()}
    ]
    assert [item["job_id"] for item in report["failed"]] == ["queued-gone"]
    assert report["failed"][0]["reason"] == "not-found"

    jobs = JobStore(queue_db)
    try:
        gone = jobs.get("queued-gone")
        assert gone is not None and gone.status == "queued", "never silently dropped"
        done = jobs.get("done")
        assert done is not None and done.sample_store_ref is None
    finally:
        jobs.close()
    store.close()


def test_build_job_command_uses_the_store_reference_when_present(tmp_path: Path) -> None:
    jobs = JobStore(tmp_path / "queue.db")
    sha = hashlib.sha256(b"x").hexdigest()
    job = jobs.enqueue(
        tmp_path / "original.bin",
        sample_sha256=sha,
        sample_store_ref=sha,
        output_dir=tmp_path / "out",
    )
    command = build_job_command(job, python="python-x")
    assert command[:5] == ["python-x", "-m", "engine.cli", "submit", "--from-store"]
    assert command[command.index("--from-store") + 1] == sha
    assert command[command.index("--sample-hint") + 1] == str(tmp_path / "original.bin")

    legacy = jobs.enqueue(tmp_path / "legacy.bin", output_dir=tmp_path / "out2")
    legacy_command = build_job_command(legacy, python="python-x")
    assert legacy_command[:4] == ["python-x", "-m", "engine.cli", "submit"]
    assert "--from-store" not in legacy_command
    jobs.close()
