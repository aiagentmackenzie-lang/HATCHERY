"""Durable job queue and workers (D27).

Submissions can be queued durably in SQLite and executed by a worker, so an API
request does not have to hold a subprocess open and a crash mid-analysis does not
leave a task ``running`` forever.

* :class:`~engine.queue.store.JobStore` — the single producer of job state.
* :class:`~engine.queue.worker.Worker` — claim, execute the existing ``hatchery
  submit`` pipeline, and record the outcome (the bundle is the authority).
"""

from __future__ import annotations

from engine.queue.store import (
    COMPLETED,
    DEFAULT_QUEUE_DB,
    FAILED,
    JOB_STATUSES,
    QUEUED,
    RUNNING,
    TERMINAL_STATUSES,
    Job,
    JobError,
    JobStore,
    resolve_queue_db,
)
from engine.queue.worker import (
    JobOutcome,
    Worker,
    WorkerConfig,
    build_job_command,
    engine_root,
)

__all__ = [
    "COMPLETED",
    "DEFAULT_QUEUE_DB",
    "FAILED",
    "JOB_STATUSES",
    "Job",
    "JobError",
    "JobOutcome",
    "JobStore",
    "QUEUED",
    "RUNNING",
    "TERMINAL_STATUSES",
    "Worker",
    "WorkerConfig",
    "build_job_command",
    "engine_root",
    "resolve_queue_db",
]
