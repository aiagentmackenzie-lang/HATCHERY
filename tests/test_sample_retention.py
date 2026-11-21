"""Retention: TTL, references and safe pruning (D28).

The rule under test is not "prune deletes old files". It is: *prune may delete a
sample only when it is past the explicit TTL and nothing that can still use it
references it* — a run bundle, a queued job or a running job. A reference that
cannot be resolved makes prune refuse rather than guess.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from _store_builder import make_queue_db, make_store, write_run

from engine.queue.store import JobStore
from engine.store import SampleStoreError


def _store_with_sample(
    tmp_path: Path, data: bytes = b"retained sample\n", *, clock=None
) -> tuple[object, str, Path]:
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    store = make_store(tmp_path, clock=clock or (lambda: 1000.0))
    record = store.put_bytes(data)
    return store, record.sha256, results


def test_ttl_boundary_is_exact_and_dry_run_deletes_nothing(tmp_path: Path) -> None:
    store, sha256, results = _store_with_sample(tmp_path)
    ttl = 3600

    # Exactly at the TTL the sample is still fresh; one second later it is not.
    at_boundary = store.prune(ttl=ttl, apply=False, now=1000 + ttl, results_roots=[results])
    assert at_boundary["would_delete"] == []
    assert at_boundary["kept"][0]["reason"] == "not-expired"

    expired = store.prune(ttl=ttl, apply=False, now=1000 + ttl + 1, results_roots=[results])
    assert [entry["sha256"] for entry in expired["would_delete"]] == [sha256]
    assert expired["would_delete"][0]["reason"] == "expired"
    assert store.blob_path(sha256).exists(), "a dry run must delete nothing"
    assert store.index.get(sha256) is not None

    applied = store.prune(ttl=ttl, apply=True, now=1000 + ttl + 1, results_roots=[results])
    assert [entry["sha256"] for entry in applied["deleted"]] == [sha256]
    assert not store.blob_path(sha256).exists()
    assert store.index.get(sha256) is None
    store.close()


def test_ttl_disabled_by_default_keeps_everything(tmp_path: Path) -> None:
    store, _sha256, results = _store_with_sample(tmp_path)
    report = store.prune(apply=True, now=10**9, results_roots=[results])
    assert report["ttl_enabled"] is False
    assert report["deleted"] == []
    assert report["kept"][0]["reason"] == "ttl-disabled"
    store.close()


def test_a_sample_shared_by_two_runs_survives_until_both_references_are_gone(
    tmp_path: Path,
) -> None:
    store, sha256, results = _store_with_sample(tmp_path)
    write_run(results, "run-a", sha256)
    write_run(results, "run-b", sha256)
    now = 1000 + 7200

    both = store.prune(ttl=3600, apply=True, now=now, results_roots=[results])
    assert both["deleted"] == []
    kept = both["kept"][0]
    assert kept["reason"] == "referenced"
    assert kept["reference_count"] == 2
    assert "run:run-a" in kept["referenced_by"]
    assert "run:run-b" in kept["referenced_by"]

    # One reference gone: the sample is still needed by the other run.
    import shutil

    shutil.rmtree(results / "run-a")
    one_left = store.prune(ttl=3600, apply=True, now=now, results_roots=[results])
    assert one_left["deleted"] == []
    assert one_left["kept"][0]["referenced_by"] == ["run:run-b"]

    shutil.rmtree(results / "run-b")
    # Retention restarts from the last moment the sample was observed in use,
    # so the TTL is measured from that scan, not from the original store time.
    none_left = store.prune(ttl=3600, apply=True, now=now + 3601, results_roots=[results])
    assert [entry["sha256"] for entry in none_left["deleted"]] == [sha256]
    store.close()


def test_a_queued_or_running_job_pins_a_sample(tmp_path: Path) -> None:
    store, sha256, results = _store_with_sample(tmp_path)
    queue_db = tmp_path / "queue.db"
    jobs = JobStore(queue_db)
    job = jobs.enqueue(
        tmp_path / "original.bin",
        job_id="job-1",
        sample_sha256=sha256,
        sample_store_ref=sha256,
        output_dir=tmp_path / "out",
    )

    queued = store.prune(ttl=1, apply=True, now=10**6, results_roots=[results], queue_db=queue_db)
    assert queued["deleted"] == []
    assert queued["kept"][0]["referenced_by"] == ["job:job-1"]

    claimed = jobs.claim("worker-1", lease_seconds=60, now=10**6)
    assert claimed is not None and claimed.job_id == job.job_id
    running = store.prune(ttl=1, apply=True, now=10**6 + 1, results_roots=[results], queue_db=queue_db)
    assert running["deleted"] == []
    assert running["kept"][0]["referenced_by"] == ["job:job-1"]

    assert jobs.complete(job.job_id, "worker-1", now=10**6 + 2)
    jobs.close()

    finished = store.prune(
        ttl=1, apply=True, now=10**6 + 3, results_roots=[results], queue_db=queue_db
    )
    assert [entry["sha256"] for entry in finished["deleted"]] == [sha256]
    store.close()


def test_a_legacy_queued_job_is_protected_by_hashing_its_original_path(tmp_path: Path) -> None:
    store, sha256, results = _store_with_sample(tmp_path)
    original = tmp_path / "legacy-original.bin"
    original.write_bytes(b"retained sample\n")
    # A D27 job: no content address, no store reference, only a path.
    queue_db = make_queue_db(
        tmp_path / "pre-d28.db",
        [{"job_id": "old-job", "sample_path": str(original), "status": "queued"}],
    )

    report = store.prune(
        ttl=1, apply=True, now=10**6, results_roots=[results], queue_db=queue_db
    )
    assert report["deleted"] == []
    assert report["kept"][0]["referenced_by"] == ["job:old-job"]
    assert store.blob_path(sha256).exists()
    store.close()


def test_prune_refuses_to_delete_when_a_queued_job_cannot_be_identified(
    tmp_path: Path,
) -> None:
    store, sha256, results = _store_with_sample(tmp_path)
    queue_db = make_queue_db(
        tmp_path / "pre-d28.db",
        [{"job_id": "unknown-job", "sample_path": str(tmp_path / "vanished.bin"), "status": "queued"}],
    )

    report = store.prune(
        ttl=1, apply=True, now=10**6, results_roots=[results], queue_db=queue_db
    )
    assert report["refused"], "an unidentifiable queued job must block the delete"
    assert "unknown-job" in report["refused"][0]
    assert report["deleted"] == []
    assert store.blob_path(sha256).exists()
    store.close()


def test_prune_reports_why_each_sample_was_kept_or_deleted(tmp_path: Path) -> None:
    now = [1000.0]
    store, referenced, results = _store_with_sample(tmp_path, b"referenced", clock=lambda: now[0])
    expired = store.put_bytes(b"expired and unreferenced")
    now[0] = 4000.0
    fresh = store.put_bytes(b"fresh")
    write_run(results, "run-a", referenced)

    report = store.prune(ttl=3600, apply=False, now=5000, results_roots=[results])
    decisions = {entry["sha256"]: entry for entry in report["kept"] + report["would_delete"]}
    assert decisions[referenced]["reason"] == "referenced"
    assert decisions[expired.sha256]["reason"] == "expired"
    assert decisions[fresh.sha256]["reason"] == "not-expired"
    assert report["summary"]["kept"] == 2
    assert report["summary"]["would_delete"] == 1
    store.close()


def test_prune_reconciles_an_interrupted_delete_before_deciding(tmp_path: Path) -> None:
    store, kept, results = _store_with_sample(tmp_path, b"kept after interruption")
    gone = store.put_bytes(b"deleted before the crash")
    store.index.set_state(gone.sha256, "deleting")
    store.blob_path(gone.sha256).unlink()
    store.index.set_state(kept, "deleting")

    report = store.prune(ttl=0, apply=False, now=2000, results_roots=[results])
    assert store.index.get(gone.sha256) is None
    assert store.index.get(kept).state == "active"  # type: ignore[union-attr]
    assert any(item["sha256"] == gone.sha256 for item in report["reconcile"]["dropped"])
    store.close()


def test_two_concurrent_prunes_leave_a_consistent_store(tmp_path: Path) -> None:
    store, sha256, results = _store_with_sample(tmp_path)
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def prune() -> None:
        worker_store = make_store(tmp_path, clock=lambda: 10**6)
        barrier.wait(5)
        try:
            outcomes.append(
                worker_store.prune(
                    ttl=1, apply=True, now=10**6, results_roots=[results]
                )
            )
        except SampleStoreError as exc:
            outcomes.append(exc)
        finally:
            worker_store.close()

    threads = [threading.Thread(target=prune) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    reasons = [getattr(outcome, "reason", None) for outcome in outcomes]
    # One may lose the store lock; that is the designed behaviour, not corruption.
    assert set(reasons) <= {None, "store-locked"}
    assert not store.blob_path(sha256).exists()
    assert store.index.get(sha256) is None
    assert not list((tmp_path / "samples").glob(".tmp-*"))
    assert store.verify()["ok"] is True
    store.close()


def test_a_prune_that_loses_the_race_with_a_reader_is_a_clean_not_found(
    tmp_path: Path,
) -> None:
    store, sha256, _results = _store_with_sample(tmp_path)
    # A reader resolved the record, then a prune deleted the blob underneath it.
    assert store.record(sha256) is not None
    assert store.prune(ttl=1, apply=True, now=10**6, results_roots=[tmp_path / "empty"])

    with pytest.raises(SampleStoreError) as excinfo:
        store.read(sha256)
    assert excinfo.value.reason == "not-found"
    store.close()
