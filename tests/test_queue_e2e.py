"""The queue end to end, with real subprocesses and no Docker (D27).

Enqueue a real job through the CLI, run a real ``hatchery worker --once`` that
executes the real ``hatchery submit`` pipeline, then confirm the job completed and
its run is still replayable — the D26 guarantee must survive the worker producing
the run directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = (REPO_ROOT / "tests" / "fixtures" / "eicar.com").resolve()
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _run_cli(
    args: list[str], cwd: Path, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # Never write the checkout's real sample store from a test.
    env.setdefault("HATCHERY_SAMPLE_STORE", str(cwd / "samples"))
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
        env=env,
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


def test_worker_executes_a_job_after_the_original_sample_is_deleted(tmp_path: Path) -> None:
    """D28: enqueue copies the bytes into the store, so the path may vanish."""
    queue_db = tmp_path / "queue.db"
    sample = tmp_path / "vanishing.com"
    sample.write_bytes(SAMPLE.read_bytes())

    enqueued = _run_cli(
        ["submit", str(sample), "--no-sandbox", "--enqueue",
         "--queue", str(queue_db), "--job-id", "survives", "-o", str(tmp_path / "out")],
        tmp_path,
    )
    assert enqueued.returncode == 0, enqueued.stderr[-2000:]
    payload = _last_json_line(enqueued.stdout)
    assert payload["sample_sha256"] == EICAR_SHA256
    assert payload["sample_store_ref"] == EICAR_SHA256

    sample.unlink()  # the original is gone before a worker ever sees it

    worked = _run_cli(["worker", "--once", "--queue", str(queue_db)], tmp_path)
    assert worked.returncode == 0, worked.stdout[-3000:] + worked.stderr[-2000:]

    job = json.loads(_run_cli(
        ["queue", "survives", "--json", "--queue", str(queue_db)], tmp_path
    ).stdout)
    assert job["status"] == "completed", job
    bundle = json.loads((tmp_path / "out" / "bundle" / "analysis.json").read_text())
    assert bundle["sample"]["sha256"] == EICAR_SHA256
    assert bundle["sample"]["store"]["reference"] == EICAR_SHA256
    assert bundle["sample"]["store"]["encryption"] == "aes-256-gcm/v1"

    # The run the worker produced still replays, from the encrypted store.
    replay_out = tmp_path / "replayed"
    replayed = _run_cli(
        ["replay", str(tmp_path / "out" / "bundle"), "--no-sandbox", "-o", str(replay_out)],
        tmp_path,
    )
    assert replayed.returncode == 0, replayed.stdout[-3000:] + replayed.stderr[-2000:]
    section = json.loads((replay_out / "bundle" / "replay.json").read_text())
    assert section["verdict"] == "reproducible", section
    assert section["sample"]["resolution"] == "sample store"


def test_worker_once_exits_nonzero_when_a_job_cannot_run(tmp_path: Path) -> None:
    """A job with no store copy and no original must fail loudly, not quietly."""
    queue_db = tmp_path / "queue.db"
    sample = tmp_path / "vanishing.txt"
    sample.write_text("here for now\n", encoding="utf-8")

    enqueued = _run_cli(
        ["submit", str(sample), "--no-sandbox", "--enqueue",
         "--queue", str(queue_db), "--job-id", "will-fail", "-o", str(tmp_path / "out")],
        tmp_path,
    )
    assert enqueued.returncode == 0, enqueued.stderr[-2000:]
    sample.unlink()
    # Remove the stored copy too: now neither source exists, which must fail.
    for blob in (tmp_path / "samples").glob("*.sample"):
        blob.unlink()

    worked = _run_cli(["worker", "--once", "--queue", str(queue_db)], tmp_path)
    assert worked.returncode != 0, worked.stdout[-2000:]

    shown = _run_cli(["queue", "will-fail", "--json", "--queue", str(queue_db)], tmp_path)
    job = json.loads(shown.stdout)
    assert job["status"] == "failed"
    assert "unusable" in (job["error"] or "")
    assert "is gone" in (job["error"] or "")
    assert job["run_dir"] is None
