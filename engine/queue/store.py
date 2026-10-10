"""Durable, SQLite-backed job store for HATCHERY (D27).

A submission can be queued and later executed by a worker on any host that can
reach the same database file. The store is pure stdlib (``sqlite3``) and is the
**only** producer of job state (D4): the API enqueues through the CLI, a worker
claims and executes, and nothing else writes a job row.

The failure model is deliberate and fail-closed (D3):

* a job is ``queued`` until a worker claims it atomically;
* a claim moves it to ``running`` and sets a lease that must be renewed;
* a ``running`` job whose lease expired was a crashed worker — it is requeued
  (never left ``running`` forever) until ``max_attempts`` is reached, at which
  point it is **failed with the reason**, not silently dropped;
* completion and failure are owner-checked, so a worker whose lease was taken
  over cannot overwrite the new owner's result.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

DEFAULT_QUEUE_DB = Path("data") / "queue.db"

QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"

JOB_STATUSES = (QUEUED, RUNNING, COMPLETED, FAILED)
TERMINAL_STATUSES = (COMPLETED, FAILED)

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id          TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'queued',
    sample_path     TEXT NOT NULL,
    sample_sha256   TEXT,
    output_dir      TEXT NOT NULL,
    args_json       TEXT NOT NULL DEFAULT '{}',
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 3,
    worker_id       TEXT,
    lease_expires_at REAL,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    updated_at      TEXT NOT NULL,
    exit_code       INTEGER,
    error           TEXT,
    run_dir         TEXT,
    task_id         TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at);
"""


class JobError(RuntimeError):
    """The requested job operation is not valid (bad id, duplicate, state)."""


def resolve_queue_db(path: Optional[Path] = None) -> Path:
    """Where the queue database lives.

    ``--queue`` wins, then ``HATCHERY_QUEUE_DB``, then ``data/queue.db`` relative
    to the working directory. An explicit path is returned unchanged so a server
    and a worker can be pointed at the same file.
    """
    if path is not None:
        return Path(path).expanduser()
    env = os.environ.get("HATCHERY_QUEUE_DB", "").strip()
    if env:
        return Path(env).expanduser()
    return DEFAULT_QUEUE_DB


def _iso(epoch: Optional[float] = None) -> str:
    moment = datetime.fromtimestamp(epoch, tz=timezone.utc) if epoch is not None else datetime.now(timezone.utc)
    return moment.isoformat()


@dataclass
class Job:
    """One unit of queued work."""

    job_id: str
    status: str
    sample_path: str
    output_dir: str
    sample_sha256: Optional[str] = None
    args: dict[str, Any] = field(default_factory=dict)
    attempts: int = 0
    max_attempts: int = 3
    worker_id: Optional[str] = None
    lease_expires_at: Optional[float] = None
    created_at: str = ""
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    updated_at: str = ""
    exit_code: Optional[int] = None
    error: Optional[str] = None
    run_dir: Optional[str] = None
    task_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "sample_path": self.sample_path,
            "sample_sha256": self.sample_sha256,
            "output_dir": self.output_dir,
            "args": self.args,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "worker_id": self.worker_id,
            "lease_expires_at": self.lease_expires_at,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "updated_at": self.updated_at,
            "exit_code": self.exit_code,
            "error": self.error,
            "run_dir": self.run_dir,
            "task_id": self.task_id,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Job":
        try:
            args = json.loads(row["args_json"] or "{}")
        except (TypeError, ValueError):
            args = {}
        if not isinstance(args, dict):
            args = {}
        return cls(
            job_id=row["job_id"],
            status=row["status"],
            sample_path=row["sample_path"],
            output_dir=row["output_dir"],
            sample_sha256=row["sample_sha256"],
            args=args,
            attempts=int(row["attempts"] or 0),
            max_attempts=int(row["max_attempts"] or 3),
            worker_id=row["worker_id"],
            lease_expires_at=row["lease_expires_at"],
            created_at=row["created_at"] or "",
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            updated_at=row["updated_at"] or "",
            exit_code=row["exit_code"],
            error=row["error"],
            run_dir=row["run_dir"],
            task_id=row["task_id"],
        )


class JobStore:
    """The queue's single writer.

    ``sqlite3`` is opened with a write lock taken by ``BEGIN IMMEDIATE`` for every
    mutation, so two processes cannot claim the same job even though only one
    process is a worker. Every connection is safe across threads (the worker
    heartbeats from a monitor thread) behind an in-process lock.
    """

    def __init__(self, path: Path | str = DEFAULT_QUEUE_DB) -> None:
        raw = str(path)
        if raw != ":memory:":
            Path(raw).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.path = raw
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            raw, timeout=30.0, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 30000")
        if raw != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(SCHEMA)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "JobStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextmanager
    def _write_txn(self) -> Iterator[None]:
        # BEGIN IMMEDIATE takes the database write lock at statement start, so
        # two concurrent claimers serialise: the second sees the row no longer
        # 'queued' and claims nothing.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")

    # -- writes ------------------------------------------------------------

    def enqueue(
        self,
        sample_path: Path | str,
        *,
        output_dir: Optional[Path | str] = None,
        args: Optional[dict[str, Any]] = None,
        sample_sha256: Optional[str] = None,
        max_attempts: int = 3,
        job_id: Optional[str] = None,
        requeue: bool = False,
        now: Optional[float] = None,
    ) -> Job:
        """Add a job, or re-queue an existing terminal one when ``requeue``.

        The sample path and the output directory are resolved to absolute paths
        at enqueue time: a worker may run in a different working directory, and a
        job whose relative paths depend on where it was queued would be a trap.
        """
        if max_attempts < 1:
            raise JobError("max_attempts must be at least 1")
        moment = now if now is not None else time.time()
        job_id = job_id or uuid.uuid4().hex[:12]
        if not job_id.strip():
            raise JobError("job_id must not be empty")
        sample = Path(str(sample_path)).expanduser()
        sample_abs = str(sample.resolve())
        out = Path(str(output_dir)).expanduser() if output_dir else (Path("results") / job_id)
        out_abs = str(out.resolve())
        payload = json.dumps(args or {})

        with self._lock, self._write_txn():
            existing = self._conn.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if existing is not None:
                if not requeue:
                    raise JobError(
                        f"job {job_id} already exists with status "
                        f"{existing['status']!r}; pass requeue=True to re-queue it"
                    )
                if existing["status"] == RUNNING and (
                    existing["lease_expires_at"] is None
                    or float(existing["lease_expires_at"]) >= moment
                ):
                    raise JobError(
                        f"job {job_id} is running under a live lease; refusing to "
                        "re-queue it"
                    )
                self._conn.execute(
                    """
                    UPDATE jobs SET
                        status = ?, attempts = 0, worker_id = NULL,
                        lease_expires_at = NULL, started_at = NULL, finished_at = NULL,
                        exit_code = NULL, error = NULL, run_dir = NULL, task_id = NULL,
                        sample_path = ?, output_dir = ?, args_json = ?,
                        sample_sha256 = COALESCE(?, sample_sha256), updated_at = ?
                    WHERE job_id = ?
                    """,
                    (QUEUED, sample_abs, out_abs, payload, sample_sha256, _iso(moment), job_id),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO jobs (
                        job_id, status, sample_path, sample_sha256, output_dir,
                        args_json, attempts, max_attempts, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                    """,
                    (
                        job_id, QUEUED, sample_abs, sample_sha256, out_abs,
                        payload, max_attempts, _iso(moment), _iso(moment),
                    ),
                )
        job = self.get(job_id)
        if job is None:  # pragma: no cover - the row was just written
            raise JobError(f"job {job_id} disappeared immediately after enqueue")
        return job

    def claim(
        self,
        worker_id: str,
        *,
        lease_seconds: float = 60.0,
        now: Optional[float] = None,
    ) -> Optional[Job]:
        """Atomically take the oldest queued job and mark it running.

        Returns ``None`` when the queue holds no claimable job. A job whose
        ``attempts`` already reached ``max_attempts`` is not claimable; recovery
        is responsible for failing it.
        """
        moment = now if now is not None else time.time()
        if lease_seconds <= 0:
            raise JobError("lease_seconds must be positive")
        lease_until = moment + float(lease_seconds)
        with self._lock, self._write_txn():
            row = self._conn.execute(
                """
                SELECT job_id FROM jobs
                WHERE status = ? AND attempts < max_attempts
                ORDER BY created_at ASC, rowid ASC LIMIT 1
                """,
                (QUEUED,),
            ).fetchone()
            if row is None:
                return None
            job_id = str(row["job_id"])
            cursor = self._conn.execute(
                """
                UPDATE jobs SET
                    status = ?, worker_id = ?, attempts = attempts + 1,
                    lease_expires_at = ?, started_at = COALESCE(started_at, ?),
                    updated_at = ?, error = NULL
                WHERE job_id = ? AND status = ?
                """,
                (RUNNING, worker_id, lease_until, _iso(moment), _iso(moment), job_id, QUEUED),
            )
            if cursor.rowcount != 1:
                return None
        return self.get(job_id)

    def heartbeat(
        self,
        job_id: str,
        worker_id: str,
        *,
        lease_seconds: float = 60.0,
        now: Optional[float] = None,
    ) -> bool:
        """Renew a running job's lease. False means this worker no longer owns it."""
        moment = now if now is not None else time.time()
        if lease_seconds <= 0:
            raise JobError("lease_seconds must be positive")
        with self._lock, self._write_txn():
            cursor = self._conn.execute(
                """
                UPDATE jobs SET lease_expires_at = ?, updated_at = ?
                WHERE job_id = ? AND worker_id = ? AND status = ?
                """,
                (moment + float(lease_seconds), _iso(moment), job_id, worker_id, RUNNING),
            )
        return cursor.rowcount == 1

    def complete(
        self,
        job_id: str,
        worker_id: str,
        *,
        run_dir: Optional[str] = None,
        task_id: Optional[str] = None,
        exit_code: int = 0,
        now: Optional[float] = None,
    ) -> bool:
        """Mark a job completed. Owner-checked; a lost lease cannot overwrite."""
        moment = now if now is not None else time.time()
        with self._lock, self._write_txn():
            cursor = self._conn.execute(
                """
                UPDATE jobs SET
                    status = ?, finished_at = ?, updated_at = ?, worker_id = NULL,
                    lease_expires_at = NULL, run_dir = ?, task_id = ?,
                    exit_code = ?, error = NULL
                WHERE job_id = ? AND worker_id = ? AND status = ?
                """,
                (COMPLETED, _iso(moment), _iso(moment), run_dir, task_id, exit_code,
                 job_id, worker_id, RUNNING),
            )
        return cursor.rowcount == 1

    def fail(
        self,
        job_id: str,
        worker_id: str,
        *,
        error: str,
        exit_code: Optional[int] = None,
        now: Optional[float] = None,
    ) -> bool:
        """Mark a job failed with the real reason. Owner-checked."""
        moment = now if now is not None else time.time()
        with self._lock, self._write_txn():
            cursor = self._conn.execute(
                """
                UPDATE jobs SET
                    status = ?, finished_at = ?, updated_at = ?, worker_id = NULL,
                    lease_expires_at = NULL, exit_code = ?, error = ?
                WHERE job_id = ? AND worker_id = ? AND status = ?
                """,
                (FAILED, _iso(moment), _iso(moment), exit_code, error[:2000],
                 job_id, worker_id, RUNNING),
            )
        return cursor.rowcount == 1

    def recover_expired(self, *, now: Optional[float] = None) -> list[str]:
        """Requeue or fail jobs whose worker died holding the lease.

        Fail-closed: an expired lease is never left ``running``. The job is
        requeued while it has attempts left; once ``attempts`` reaches
        ``max_attempts`` it is failed with the reason, so a crash loop ends
        loudly instead of silently.
        """
        moment = now if now is not None else time.time()
        touched: list[str] = []
        with self._lock, self._write_txn():
            rows = self._conn.execute(
                """
                SELECT job_id, attempts, max_attempts FROM jobs
                WHERE status = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?
                ORDER BY created_at ASC
                """,
                (RUNNING, moment),
            ).fetchall()
            for row in rows:
                job_id = str(row["job_id"])
                attempts = int(row["attempts"] or 0)
                max_attempts = int(row["max_attempts"] or 3)
                if attempts < max_attempts:
                    self._conn.execute(
                        """
                        UPDATE jobs SET
                            status = ?, worker_id = NULL, lease_expires_at = NULL,
                            updated_at = ?, error = ?
                        WHERE job_id = ? AND status = ?
                        """,
                        (
                            QUEUED,
                            _iso(moment),
                            f"worker lease expired on attempt {attempts}; requeued",
                            job_id,
                            RUNNING,
                        ),
                    )
                else:
                    self._conn.execute(
                        """
                        UPDATE jobs SET
                            status = ?, worker_id = NULL, lease_expires_at = NULL,
                            finished_at = ?, updated_at = ?, error = ?
                        WHERE job_id = ? AND status = ?
                        """,
                        (
                            FAILED,
                            _iso(moment),
                            _iso(moment),
                            f"worker lease expired after {attempts} attempt(s); "
                            "failing rather than running forever",
                            job_id,
                            RUNNING,
                        ),
                    )
                touched.append(job_id)
        return touched

    # -- reads -------------------------------------------------------------

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return Job.from_row(row) if row is not None else None

    def list(
        self, *, status: Optional[str] = None, limit: int = 100
    ) -> list[Job]:
        with self._lock:
            if status is None:
                rows = self._conn.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?",
                    (int(limit),),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM jobs WHERE status = ?
                    ORDER BY created_at DESC, rowid DESC LIMIT ?
                    """,
                    (status, int(limit)),
                ).fetchall()
        return [Job.from_row(row) for row in rows]

    def counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM jobs GROUP BY status"
            ).fetchall()
        counts = {status: 0 for status in JOB_STATUSES}
        for row in rows:
            counts[str(row["status"])] = int(row["n"])
        counts["total"] = sum(counts[status] for status in JOB_STATUSES)
        return counts


__all__ = [
    "COMPLETED",
    "DEFAULT_QUEUE_DB",
    "FAILED",
    "JOB_STATUSES",
    "Job",
    "JobError",
    "JobStore",
    "QUEUED",
    "RUNNING",
    "SCHEMA",
    "TERMINAL_STATUSES",
    "resolve_queue_db",
]
