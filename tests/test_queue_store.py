"""The durable job store (D27): states, atomic claims, leases, recovery.

All local — a temporary SQLite file (or ``:memory:``) and no Docker, no Ollama and
no subprocess. Two *separate* store instances are used to prove the claim is
atomic across connections, which is what makes two workers safe.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from engine.queue.store import (
    COMPLETED,
    FAILED,
    QUEUED,
    RUNNING,
    JobError,
    JobStore,
    resolve_queue_db,
)


@pytest.fixture()
def store(tmp_path: Path) -> JobStore:
    instance = JobStore(tmp_path / "queue.db")
    yield instance
    instance.close()


def test_enqueue_then_claim_and_complete(store: JobStore, tmp_path: Path) -> None:
    job = store.enqueue(tmp_path / "sample.bin", output_dir=tmp_path / "out")
    assert job.status == QUEUED
    assert job.attempts == 0
    assert Path(job.output_dir).is_absolute()
    assert Path(job.sample_path).is_absolute()

    claimed = store.claim("worker-a", lease_seconds=30)
    assert claimed is not None
    assert claimed.job_id == job.job_id
    assert claimed.status == RUNNING
    assert claimed.attempts == 1
    assert claimed.worker_id == "worker-a"
    assert claimed.lease_expires_at is not None

    assert store.claim("worker-b") is None

    assert store.complete(job.job_id, "worker-a", run_dir="/runs/x", task_id="t1") is True
    done = store.get(job.job_id)
    assert done is not None
    assert done.status == COMPLETED
    assert done.run_dir == "/runs/x"
    assert done.task_id == "t1"
    assert done.worker_id is None


def test_duplicate_job_id_is_refused_unless_requeued(store: JobStore, tmp_path: Path) -> None:
    store.enqueue(tmp_path / "a.bin", job_id="fixed")
    with pytest.raises(JobError, match="already exists"):
        store.enqueue(tmp_path / "b.bin", job_id="fixed")

    # a failed job can be re-queued with its attempt count reset
    store.claim("w")
    store.fail("fixed", "w", error="boom")
    requeued = store.enqueue(tmp_path / "b.bin", job_id="fixed", requeue=True)
    assert requeued.status == QUEUED
    assert requeued.attempts == 0
    assert requeued.error is None


def test_requeue_refuses_a_running_job_with_a_live_lease(store: JobStore, tmp_path: Path) -> None:
    store.enqueue(tmp_path / "a.bin", job_id="live")
    store.claim("w", lease_seconds=300)
    with pytest.raises(JobError, match="live lease"):
        store.enqueue(tmp_path / "b.bin", job_id="live", requeue=True)


def test_heartbeat_only_works_for_the_owner(store: JobStore, tmp_path: Path) -> None:
    store.enqueue(tmp_path / "a.bin")
    claimed = store.claim("worker-a", lease_seconds=10, now=1000.0)
    assert claimed is not None
    assert store.heartbeat(claimed.job_id, "worker-b", lease_seconds=10, now=1005.0) is False
    assert store.heartbeat(claimed.job_id, "worker-a", lease_seconds=10, now=1005.0) is True
    renewed = store.get(claimed.job_id)
    assert renewed is not None
    assert renewed.lease_expires_at == pytest.approx(1015.0)


def test_a_non_owner_cannot_complete_or_fail(store: JobStore, tmp_path: Path) -> None:
    store.enqueue(tmp_path / "a.bin")
    claimed = store.claim("worker-a")
    assert claimed is not None
    assert store.complete(claimed.job_id, "worker-b") is False
    assert store.fail(claimed.job_id, "worker-b", error="sneaky") is False
    still = store.get(claimed.job_id)
    assert still is not None and still.status == RUNNING


def test_expired_lease_is_requeued_not_left_running(store: JobStore, tmp_path: Path) -> None:
    store.enqueue(tmp_path / "a.bin", max_attempts=3)
    claimed = store.claim("dead-worker", lease_seconds=10, now=1000.0)
    assert claimed is not None

    # not expired yet: nothing is recovered
    assert store.recover_expired(now=1005.0) == []
    assert store.get(claimed.job_id).status == RUNNING  # type: ignore[union-attr]

    recovered = store.recover_expired(now=1011.0)
    assert recovered == [claimed.job_id]
    row = store.get(claimed.job_id)
    assert row is not None
    assert row.status == QUEUED
    assert row.worker_id is None
    assert row.lease_expires_at is None
    assert row.attempts == 1
    assert "lease expired" in (row.error or "")

    # a fresh worker can pick it up again
    again = store.claim("worker-b", lease_seconds=10, now=1020.0)
    assert again is not None
    assert again.attempts == 2


def test_a_crash_loop_ends_in_failure_with_a_reason(store: JobStore, tmp_path: Path) -> None:
    store.enqueue(tmp_path / "a.bin", max_attempts=2)

    # attempt 1 -> crash -> recover (requeued)
    first = store.claim("w1", lease_seconds=1, now=0.0)
    assert first is not None
    assert store.recover_expired(now=2.0) == [first.job_id]

    # attempt 2 -> crash -> recover must FAIL it rather than loop forever
    second = store.claim("w2", lease_seconds=1, now=3.0)
    assert second is not None
    assert store.recover_expired(now=5.0) == [second.job_id]

    row = store.get(second.job_id)
    assert row is not None
    assert row.status == FAILED
    assert row.attempts == 2
    assert "lease expired after 2 attempt(s)" in (row.error or "")

    # and it can no longer be claimed
    assert store.claim("w3") is None


def test_fail_records_the_real_reason(store: JobStore, tmp_path: Path) -> None:
    store.enqueue(tmp_path / "a.bin")
    claimed = store.claim("w")
    assert claimed is not None
    assert store.fail(claimed.job_id, "w", error="submit exited 2: bad sample", exit_code=2) is True
    row = store.get(claimed.job_id)
    assert row is not None
    assert row.status == FAILED
    assert row.exit_code == 2
    assert row.error == "submit exited 2: bad sample"


def test_two_concurrent_claimers_cannot_double_run_one_job(tmp_path: Path) -> None:
    db = tmp_path / "queue.db"
    first = JobStore(db)
    second = JobStore(db)
    first.enqueue(tmp_path / "only-one.bin", job_id="contended")

    barrier = threading.Barrier(2)

    def claim(store: JobStore, worker_id: str) -> str | None:
        barrier.wait()
        job = store.claim(worker_id, lease_seconds=30)
        return job.job_id if job else None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(claim, first, "w1"), pool.submit(claim, second, "w2")]
        results = [future.result() for future in futures]

    first.close()
    second.close()

    claimed = [result for result in results if result is not None]
    assert claimed == ["contended"], "exactly one claimer must win"


def test_claim_is_fifo_and_counts_are_reported(store: JobStore, tmp_path: Path) -> None:
    first = store.enqueue(tmp_path / "1.bin", job_id="one", now=1.0)
    second = store.enqueue(tmp_path / "2.bin", job_id="two", now=2.0)
    assert store.claim("w", now=3.0).job_id == first.job_id  # type: ignore[union-attr]
    assert store.claim("w", now=4.0).job_id == second.job_id  # type: ignore[union-attr]
    assert store.claim("w", now=5.0) is None

    counts = store.counts()
    assert counts[RUNNING] == 2
    assert counts["total"] == 2


def test_list_filters_by_status(store: JobStore, tmp_path: Path) -> None:
    store.enqueue(tmp_path / "a.bin", job_id="a")
    store.enqueue(tmp_path / "b.bin", job_id="b")
    claimed = store.claim("w")
    assert claimed is not None
    store.fail(claimed.job_id, "w", error="nope")

    failed = store.list(status=FAILED)
    assert [job.job_id for job in failed] == [claimed.job_id]
    assert len(store.list()) == 2


def test_enqueue_rejects_zero_attempts(store: JobStore, tmp_path: Path) -> None:
    with pytest.raises(JobError, match="max_attempts"):
        store.enqueue(tmp_path / "a.bin", max_attempts=0)


def test_resolve_queue_db_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "explicit.db"
    assert resolve_queue_db(explicit) == explicit

    monkeypatch.setenv("HATCHERY_QUEUE_DB", str(tmp_path / "env.db"))
    assert resolve_queue_db(None) == tmp_path / "env.db"
    assert resolve_queue_db(explicit) == explicit

    monkeypatch.delenv("HATCHERY_QUEUE_DB", raising=False)
    assert str(resolve_queue_db(None)) == "data/queue.db"
