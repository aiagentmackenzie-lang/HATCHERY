"""The queue end to end, with real subprocesses and no Docker (D27).

Enqueue a real job through the CLI, run a real ``hatchery worker --once`` that
executes the real ``hatchery submit`` pipeline, then confirm the job completed and
its run is still replayable — the D26 guarantee must survive the worker producing
the run directory.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = (REPO_ROOT / "tests" / "fixtures" / "eicar.com").resolve()


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )


def _last_json_line(stdout: str) -> dict:
    for line in reversed(stdout.strip().splitlines()):
        candidate = line.strip()
        if candidate.startswith("{"):
            return json.loads(candidate)
    raise AssertionError(f"no JSON object on stdout:\n{stdout}")


def test_enqueue_worker_and_replay_round_trip(tmp_path: Path) -> None:
    queue_db = tmp_path / "queue.db"
    output_dir = tmp_path / "worker-run"

    enqueued = _run_cli(
        [
            "submit", str(SAMPLE),
            "--no-sandbox",
            "--enqueue",
            "--queue", str(queue_db),
            "--job-id", "e2e-job",
            "-o", str(output_dir),
        ],
        tmp_path,
    )
    assert enqueued.returncode == 0, enqueued.stderr[-2000:]
    payload = _last_json_line(enqueued.stdout)
    assert payload["job_id"] == "e2e-job"
    assert payload["status"] == "queued"
    assert not (output_dir / "bundle" / "analysis.json").exists(), (
        "--enqueue must not analyse anything"
    )

    # The queue lists the job as queued before any worker runs.
    listed = _run_cli(["queue", "--json", "--queue", str(queue_db)], tmp_path)
    assert listed.returncode == 0, listed.stderr[-2000:]
    listing = json.loads(listed.stdout)
    assert listing["counts"]["queued"] == 1
    assert listing["jobs"][0]["job_id"] == "e2e-job"

    # A real worker claims it, runs the real submit pipeline and records the bundle.
    worked = _run_cli(
        ["worker", "--once", "--concurrency", "1", "--queue", str(queue_db)],
        tmp_path,
    )
    assert worked.returncode == 0, worked.stdout[-3000:] + worked.stderr[-2000:]

    shown = _run_cli(["queue", "e2e-job", "--json", "--queue", str(queue_db)], tmp_path)
    job = json.loads(shown.stdout)
    assert job["status"] == "completed", job
    assert job["attempts"] == 1
    assert job["run_dir"] == str(output_dir / "bundle")
    assert (output_dir / "bundle" / "analysis.json").is_file()
    assert (output_dir / "bundle" / "events.jsonl").is_file()

    # The worker produced a run that still replays: the D26 guarantee is intact.
    replay_out = tmp_path / "replayed"
    replayed = _run_cli(
        ["replay", str(output_dir / "bundle"), "--no-sandbox", "-o", str(replay_out)],
        tmp_path,
    )
    assert replayed.returncode == 0, replayed.stdout[-3000:] + replayed.stderr[-2000:]
    section = json.loads((replay_out / "bundle" / "replay.json").read_text())
    assert section["verdict"] == "reproducible", section
    assert section["deterministic_mismatches"] == []
    assert section["sample"]["hash_verified"] is True


def test_a_worker_with_an_empty_queue_exits_cleanly(tmp_path: Path) -> None:
    result = _run_cli(
        ["worker", "--once", "--queue", str(tmp_path / "empty-queue.db")],
        tmp_path,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "Queue empty" in result.stdout


def test_worker_once_exits_nonzero_when_a_job_fails(tmp_path: Path) -> None:
    """A job that produces no bundle must fail loudly, and --once must say so."""
    queue_db = tmp_path / "queue.db"
    sample = tmp_path / "vanishing.txt"
    sample.write_text("here for now\n", encoding="utf-8")

    enqueued = _run_cli(
        ["submit", str(sample), "--no-sandbox", "--enqueue",
         "--queue", str(queue_db), "--job-id", "will-fail", "-o", str(tmp_path / "out")],
        tmp_path,
    )
    assert enqueued.returncode == 0, enqueued.stderr[-2000:]
    sample.unlink()  # the sample is gone before a worker ever sees it

    worked = _run_cli(["worker", "--once", "--queue", str(queue_db)], tmp_path)
    assert worked.returncode != 0, worked.stdout[-2000:]

    shown = _run_cli(["queue", "will-fail", "--json", "--queue", str(queue_db)], tmp_path)
    job = json.loads(shown.stdout)
    assert job["status"] == "failed"
    assert job["error"], "a failure must carry the real reason"
    assert job["run_dir"] is None
