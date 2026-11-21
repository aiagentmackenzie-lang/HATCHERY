"""Shared fixtures for the D28 sample-store tests.

Real :class:`SampleStore`, real index, real queue database, temporary roots.
Nothing here mocks the component under test.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Optional

from engine.store import SampleStore
from engine.store.crypto import SampleKey, key_id_for

KEY_BYTES = bytes(range(32))
KEY = SampleKey(KEY_BYTES, "test:key-a", key_id_for(KEY_BYTES))
OTHER_KEY_BYTES = bytes(range(1, 33))
OTHER_KEY = SampleKey(OTHER_KEY_BYTES, "test:key-b", key_id_for(OTHER_KEY_BYTES))

# The D27 jobs table, before D28 added sample_store_ref.
PRE_D28_SCHEMA = """
CREATE TABLE jobs (
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
CREATE INDEX idx_jobs_status ON jobs(status, created_at);
"""


def make_store(
    base: Path,
    *,
    key: Optional[SampleKey] = KEY,
    clock: Optional[Any] = None,
    max_bytes: int = 64 * 1024 * 1024,
) -> SampleStore:
    """A store rooted at ``<base>/samples`` with its index inside that root."""
    return SampleStore(base / "samples", key=key, clock=clock, max_bytes=max_bytes)


def write_run(results_root: Path, run_id: str, sha256: str, *, nested: bool = False) -> Path:
    """Write a minimal analysis bundle that references ``sha256``."""
    base = results_root / run_id
    if nested:
        base = base / "replay-deadbeef"
    bundle = base / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "analysis.json").write_text(
        json.dumps(
            {
                "task_id": run_id,
                "sample": {"sha256": sha256, "file_path": f"/gone/{run_id}.bin"},
                "static": {},
            }
        ),
        encoding="utf-8",
    )
    return bundle


def write_legacy_blob(root: Path, data: bytes, *, name: Optional[str] = None) -> tuple[str, Path]:
    """Write a pre-D28 plaintext blob exactly where the old store put it."""
    import hashlib

    sha256 = hashlib.sha256(data).hexdigest()
    root.mkdir(parents=True, exist_ok=True)
    path = root / (name or f"{sha256}.sample")
    path.write_bytes(data)
    return sha256, path


def make_queue_db(path: Path, rows: Iterable[dict[str, Any]]) -> Path:
    """Create a pre-D28 queue database with the given job rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(PRE_D28_SCHEMA)
        now = "2026-11-21T00:00:00+00:00"
        for row in rows:
            values = {
                "job_id": row["job_id"],
                "status": row.get("status", "queued"),
                "sample_path": row["sample_path"],
                "sample_sha256": row.get("sample_sha256"),
                "output_dir": row.get("output_dir", "/tmp/out"),
                "args_json": json.dumps(row.get("args", {"no_sandbox": True})),
                "attempts": row.get("attempts", 0),
                "max_attempts": row.get("max_attempts", 3),
                "created_at": row.get("created_at", now),
                "updated_at": row.get("updated_at", now),
            }
            conn.execute(
                """
                INSERT INTO jobs (job_id, status, sample_path, sample_sha256,
                                  output_dir, args_json, attempts, max_attempts,
                                  created_at, updated_at)
                VALUES (:job_id, :status, :sample_path, :sample_sha256, :output_dir,
                        :args_json, :attempts, :max_attempts, :created_at, :updated_at)
                """,
                values,
            )
        conn.commit()
    finally:
        conn.close()
    return path


def epoch_now() -> float:
    return time.time()
