"""The D28 reference interaction: a bundle prune must not make a live sample
prunable, and must release a dead one.

D28's `store prune` re-reads `<results>/<run>/bundle/analysis.json` for
`sample.sha256` and the D27 queue for queued/running jobs at decision time. The
bundle pruner therefore changes what the sample store may safely delete, so both
directions are pinned here against a real encrypted store, real SQLite indexes
and real run directories. `store prune` itself is not modified: it already does
the right thing, and this test proves the two agree.
"""

from __future__ import annotations

import json
from pathlib import Path

from _results_builder import cli_json, iso_days_ago, make_run, seal_at
from _store_builder import make_queue_db, make_store

from engine.results import resolve_policy
from engine.results.retention import prune_runs
from engine.store import SampleStore

TTL = 60.0


def _epoch(round_: int) -> float:
    """An increasing clock per prune.

    The D28 reference scan moves ``last_referenced_at`` forward, so a second
    prune at the same instant would find the sample fresh rather than expired.
    Advancing the clock is what a real operator's next run does.
    """
    return 1000.0 + (round_ + 1) * (TTL + 1)


def _prune_runs(results: Path, *, keep_last: int) -> dict:
    policy = resolve_policy(older_than="10d", keep_last=keep_last)
    return prune_runs(results, policy=policy, apply=True)


def _store_prune(store: SampleStore, results: Path, *, now: float, queue_db=None):
    return store.prune(
        ttl=TTL,
        apply=True,
        now=now,
        results_roots=[results],
        queue_db=queue_db,
    )


def test_pruning_one_of_two_runs_leaves_the_sample_protected(tmp_path: Path) -> None:
    store = make_store(tmp_path, clock=lambda: 1000.0)
    record = store.put_bytes(b"shared sample bytes")
    results = tmp_path / "results"
    results.mkdir()
    make_run(results, "run-a", sample_sha256=record.sha256, days_ago=30)
    make_run(results, "run-b", sample_sha256=record.sha256, days_ago=20)
    make_run(results, "run-c", sample_sha256="", days_ago=1)

    # Delete run-a only (the two newest are the anchor).
    plan = _prune_runs(results, keep_last=2)
    assert [item["run_id"] for item in plan["removed"]] == ["run-a"]
    assert not (results / "run-a").exists()

    # run-b still references the sample, so the store may not delete it.
    kept = _store_prune(store, results, now=_epoch(0))
    assert kept["deleted"] == []
    assert kept["kept"][0]["reason"] == "referenced"
    assert store.blob_path(record.sha256).exists()
    assert "run:run-b" in kept["kept"][0]["referenced_by"]

    # Delete run-b too. Now nothing references it, so it becomes prunable.
    plan = _prune_runs(results, keep_last=1)
    assert [item["run_id"] for item in plan["removed"]] == ["run-b"]
    prunable = _store_prune(store, results, now=_epoch(1))
    assert [entry["sha256"] for entry in prunable["deleted"]] == [record.sha256]
    assert not store.blob_path(record.sha256).exists()
    store.close()


def test_deleting_a_run_never_makes_an_in_use_sample_prunable(tmp_path: Path) -> None:
    """The dangerous direction: a queued job still needs the sample."""
    store = make_store(tmp_path, clock=lambda: 1000.0)
    record = store.put_bytes(b"queued job sample")
    results = tmp_path / "results"
    results.mkdir()
    make_run(results, "run-a", sample_sha256=record.sha256, days_ago=30)
    make_run(results, "run-b", sample_sha256="", days_ago=1)
    queue = make_queue_db(
        tmp_path / "queue.db",
        [
            {
                "job_id": "job-queued",
                "status": "queued",
                "sample_path": "/gone/original.bin",
                "sample_sha256": record.sha256,
            }
        ],
    )

    plan = _prune_runs(results, keep_last=1)
    assert [item["run_id"] for item in plan["removed"]] == ["run-a"]
    report = _store_prune(store, results, now=_epoch(0), queue_db=queue)
    assert report["deleted"] == []
    assert report["kept"][0]["reason"] == "referenced"
    assert "job:job-queued" in report["kept"][0]["referenced_by"]
    assert store.blob_path(record.sha256).exists()
    store.close()


def test_a_replay_run_nested_in_a_deleted_run_goes_with_it(tmp_path: Path) -> None:
    store = make_store(tmp_path, clock=lambda: 1000.0)
    record = store.put_bytes(b"replay-only sample")
    results = tmp_path / "results"
    results.mkdir()
    parent = make_run(results, "run-a", sample_sha256="", days_ago=30)
    nested = parent / "replay-abc123"
    (nested / "bundle").mkdir(parents=True)
    nested_doc = {
        "schema_version": "1.0",
        "task_id": "replay-run",
        "generated_at": iso_days_ago(31),
        "sample": {"sha256": record.sha256, "file_path": "/gone/x.bin"},
        "static": {},
    }
    (nested / "bundle" / "analysis.json").write_text(json.dumps(nested_doc))
    seal_at(nested, iso_days_ago(30), stage="replay")
    make_run(results, "run-b", sample_sha256="", days_ago=1)

    # Both reference the sample? No: only the nested replay does. Before the
    # prune it is protected through the nested bundle.
    before = _store_prune(store, results, now=_epoch(0))
    assert before["deleted"] == []
    assert any("run:replay-abc123" in entry.get("referenced_by", []) for entry in before["kept"])

    plan = _prune_runs(results, keep_last=1)
    assert [item["run_id"] for item in plan["removed"]] == ["run-a"]
    assert plan["removed"][0]["nested_runs"] == 1
    assert not nested.exists(), "a nested replay is part of the run directory"

    after = _store_prune(store, results, now=_epoch(1))
    assert [entry["sha256"] for entry in after["deleted"]] == [record.sha256]
    store.close()


def test_the_cli_prune_and_store_prune_agree(tmp_path: Path) -> None:
    """The same story through the two operator commands, not the API."""
    store = make_store(tmp_path, clock=lambda: 1000.0)
    record = store.put_bytes(b"cli-visible sample")
    results = tmp_path / "results"
    results.mkdir()
    make_run(results, "run-a", sample_sha256=record.sha256, days_ago=30)
    make_run(results, "run-b", sample_sha256=record.sha256, days_ago=20)
    make_run(results, "run-c", sample_sha256="", days_ago=1)
    store.close()

    code, plan = cli_json(
        ["results", "prune", "--older-than", "10d", "--keep-last", "2", "--apply",
         "--json", "--results", str(results)],
        tmp_path,
        expect=0,
    )
    assert [item["run_id"] for item in plan["removed"]] == ["run-a"]

    code, report = cli_json(
        ["store", "prune", "--ttl", str(TTL), "--apply", "--json",
         "--store", str(tmp_path / "samples"), "--results", str(results),
         "--queue", str(tmp_path / "no-queue.db")],
        tmp_path,
        expect=0,
    )
    # The CLI store prune measures the TTL against the real clock, so the sample
    # is fresh rather than expired: either reason is a keep, and it must be kept.
    assert report["deleted"] == []
    assert (tmp_path / "samples" / f"{record.sha256}.sample").exists()
