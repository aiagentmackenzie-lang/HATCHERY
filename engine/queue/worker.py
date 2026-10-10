"""The queue worker: execute claimed jobs by running the existing pipeline (D27).

A worker does one thing: claim a job, run ``hatchery submit`` for it as a
subprocess, and record the outcome. It never re-implements analysis (one producer
per data path, D4) and it never trusts the exit code alone — the **bundle is the
authority**. A job is completed only when the submit process exited 0 *and* the
bundle it was supposed to write exists; otherwise the job fails with the reason.

Concurrency is bounded: at most ``--concurrency`` jobs run at once, and claiming is
atomic, so two workers never run the same job. A lease is renewed while the job
runs, so a worker that dies does not leave the job running forever — the next
worker recovers it (see :class:`engine.queue.store.JobStore`).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from engine.queue.store import FAILED, RUNNING, Job, JobStore

logger = logging.getLogger(__name__)

# The submit flags a queued job may carry. A whitelist on purpose: a job row is
# data, and a queued option the worker does not understand must not be silently
# dropped or passed through as an argument.
SUBMIT_FLAG_OPTIONS = (
    "no_sandbox",
    "emulate",
    "emulate_raw",
    "no_emulate_capa",
    "allow_host_emulation",
    "triage",
    "allow_remote_model",
)
SUBMIT_VALUE_OPTIONS = {
    "timeout": "--timeout",
    "emulate_timeout": "--emulate-timeout",
    "triage_model": "--triage-model",
}

SubmitRunner = Callable[[list[str], float], "tuple[int, str, str]"]
"""``(command, timeout) -> (returncode, stdout, stderr)``."""


def engine_root() -> Path:
    """The directory that contains the ``engine`` package."""
    return Path(__file__).resolve().parents[2]


def build_job_command(
    job: Job,
    *,
    python: Optional[str] = None,
) -> list[str]:
    """The ``hatchery submit`` command that executes a queued job.

    Paths are absolute (resolved at enqueue), so the command is independent of
    the worker's working directory.
    """
    executable = python or sys.executable
    command = [
        executable, "-m", "engine.cli", "submit", job.sample_path,
        "-o", job.output_dir,
    ]
    emulate = bool(job.args.get("emulate"))
    for key in SUBMIT_FLAG_OPTIONS:
        # An emulation-only flag without --emulate cannot take effect; refuse to
        # hand submit a flag that says nothing.
        if key == "allow_host_emulation" and not emulate:
            continue
        if job.args.get(key):
            command.append("--" + key.replace("_", "-"))
    for key, flag in SUBMIT_VALUE_OPTIONS.items():
        value = job.args.get(key)
        if value is None:
            continue
        if key == "emulate_timeout" and not emulate:
            continue
        command.extend([flag, str(value)])
    return command


@dataclass
class WorkerConfig:
    """Everything a worker needs that is not the queue database itself."""

    worker_id: str = field(default_factory=lambda: f"worker-{uuid.uuid4().hex[:8]}")
    concurrency: int = 1
    lease_seconds: float = 60.0
    heartbeat_interval: Optional[float] = None
    poll_interval: float = 2.0
    submit_timeout: float = 1800.0
    python: Optional[str] = None
    once: bool = False

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")


@dataclass
class JobOutcome:
    """What a worker did with one job."""

    job_id: str
    status: str
    run_dir: Optional[str] = None
    task_id: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "run_dir": self.run_dir,
            "task_id": self.task_id,
            "detail": self.detail,
        }


class Worker:
    """Claim and execute queued jobs, with bounded concurrency and a lease."""

    def __init__(
        self,
        store: JobStore,
        config: Optional[WorkerConfig] = None,
        *,
        runner: Optional[SubmitRunner] = None,
    ) -> None:
        self.store = store
        self.config = config or WorkerConfig()
        self._runner = runner or self._default_runner
        self._root = engine_root()

    # -- public API --------------------------------------------------------

    def run_once(self) -> list[JobOutcome]:
        """Drain the currently queued jobs in batches of ``concurrency``.

        Recovery runs first, so a job orphaned by a dead worker is claimable
        before this worker takes new work.
        """
        recovered = self.store.recover_expired()
        if recovered:
            logger.warning("Recovered %d job(s) with an expired lease: %s",
                           len(recovered), ", ".join(recovered))
        outcomes: list[JobOutcome] = []
        while True:
            batch = self._claim_batch()
            if not batch:
                break
            outcomes.extend(self._run_batch(batch))
        return outcomes

    def run_forever(self, stop_event: Optional[threading.Event] = None) -> None:
        """Process jobs until ``stop_event`` is set (or KeyboardInterrupt)."""
        stop = stop_event or threading.Event()
        logger.info(
            "Worker %s polling %s (concurrency=%d, lease=%.0fs)",
            self.config.worker_id, self.store.path, self.config.concurrency,
            self.config.lease_seconds,
        )
        while not stop.is_set():
            try:
                outcomes = self.run_once()
            except Exception as exc:  # noqa: BLE001 - the loop must survive a bad job
                logger.error("Worker loop error: %s", exc)
                outcomes = []
            if not outcomes:
                stop.wait(self.config.poll_interval)

    # -- internals ---------------------------------------------------------

    def _claim_batch(self) -> list[Job]:
        batch: list[Job] = []
        for _ in range(self.config.concurrency):
            job = self.store.claim(
                self.config.worker_id, lease_seconds=self.config.lease_seconds
            )
            if job is None:
                break
            batch.append(job)
        return batch

    def _run_batch(self, batch: list[Job]) -> list[JobOutcome]:
        if len(batch) == 1:
            return [self._execute(batch[0])]
        results: list[Optional[JobOutcome]] = [None] * len(batch)
        threads: list[threading.Thread] = []

        def target(index: int, job: Job) -> None:
            results[index] = self._execute(job)

        for index, job in enumerate(batch):
            thread = threading.Thread(target=target, args=(index, job), daemon=True)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        return [outcome for outcome in results if outcome is not None]

    def _execute(self, job: Job) -> JobOutcome:
        command = build_job_command(job, python=self.config.python)
        logger.info("Job %s: %s", job.job_id, " ".join(command))
        heartbeat = self._start_heartbeat(job)
        try:
            returncode, stdout, stderr = self._runner(command, self.config.submit_timeout)
        except Exception as exc:  # noqa: BLE001 - a runner crash is a job failure
            detail = f"the submit runner failed: {type(exc).__name__}: {exc}"
            self.store.fail(job.job_id, self.config.worker_id, error=detail)
            logger.error("Job %s failed: %s", job.job_id, detail)
            return JobOutcome(job_id=job.job_id, status=FAILED, detail=detail)
        finally:
            heartbeat.set()

        bundle_dir = Path(job.output_dir) / "bundle"
        analysis_path = bundle_dir / "analysis.json"
        bundle_exists = analysis_path.is_file()

        # Exit code 0 alone is not success. The bundle is the authority; a submit
        # that exits 0 without producing one is a failure, and so is a non-zero
        # exit even if a partial bundle was left behind.
        if returncode != 0 or not bundle_exists:
            tail = _tail(stderr or stdout)
            if not bundle_exists:
                detail = (
                    f"no bundle at {analysis_path} (submit exit {returncode})"
                    + (f": {tail}" if tail else "")
                )
            else:
                detail = f"submit exited {returncode}: {tail or 'no output'}"
            self.store.fail(
                job.job_id, self.config.worker_id, error=detail, exit_code=returncode
            )
            logger.error("Job %s failed: %s", job.job_id, detail)
            return JobOutcome(job_id=job.job_id, status=FAILED, detail=detail)

        task_id = _bundle_task_id(analysis_path)
        completed = self.store.complete(
            job.job_id, self.config.worker_id,
            run_dir=str(bundle_dir), task_id=task_id, exit_code=returncode,
        )
        if not completed:
            # The lease was taken over mid-run; the new owner's result stands.
            detail = "the job's lease was lost before completion; not recording a result"
            logger.warning("Job %s: %s", job.job_id, detail)
            return JobOutcome(job_id=job.job_id, status=RUNNING, detail=detail)
        logger.info("Job %s completed: bundle %s", job.job_id, bundle_dir)
        return JobOutcome(
            job_id=job.job_id, status="completed", run_dir=str(bundle_dir),
            task_id=task_id, detail=f"submit exit {returncode}",
        )

    def _start_heartbeat(self, job: Job) -> threading.Event:
        stop = threading.Event()
        interval = self.config.heartbeat_interval
        if interval is None:
            interval = max(self.config.lease_seconds / 3.0, 0.1)

        def beat() -> None:
            while not stop.wait(interval):
                if not self.store.heartbeat(
                    job.job_id, self.config.worker_id,
                    lease_seconds=self.config.lease_seconds,
                ):
                    # False means this worker no longer owns the running job. If
                    # the job simply finished, the completion path already
                    # recorded it; only a genuine loss is worth a warning.
                    current = self.store.get(job.job_id)
                    if (
                        current is not None
                        and current.status == RUNNING
                        and current.worker_id == self.config.worker_id
                    ):
                        logger.warning(
                            "Job %s: lease lost while running; another worker owns it now",
                            job.job_id,
                        )
                    return

        threading.Thread(target=beat, name=f"heartbeat-{job.job_id}", daemon=True).start()
        return stop

    def _default_runner(self, command: list[str], timeout: float) -> tuple[int, str, str]:
        env = dict(os.environ)
        env.setdefault("PYTHONPATH", str(self._root))
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout,
                cwd=str(self._root), env=env, check=False,
            )
        except subprocess.TimeoutExpired:
            return 124, "", f"submit timed out after {timeout:.0f}s"
        except OSError as exc:
            return 127, "", f"could not start submit: {exc}"
        return completed.returncode, completed.stdout or "", completed.stderr or ""


def _tail(text: str, limit: int = 400) -> str:
    lines = [line for line in (text or "").strip().splitlines() if line.strip()]
    if not lines:
        return ""
    return " | ".join(lines[-3:])[:limit]


def _bundle_task_id(analysis_path: Path) -> Optional[str]:
    import json

    try:
        data = json.loads(analysis_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    task_id = data.get("task_id") if isinstance(data, dict) else None
    return str(task_id) if task_id else None


__all__ = [
    "JobOutcome",
    "SUBMIT_FLAG_OPTIONS",
    "SUBMIT_VALUE_OPTIONS",
    "SubmitRunner",
    "Worker",
    "WorkerConfig",
    "build_job_command",
    "engine_root",
]
