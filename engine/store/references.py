"""Who still needs a stored sample (D28).

Retention must never delete a sample a run or a job still depends on, and it
must not keep one alive because the index *thinks* something needs it. The
authoritative references therefore live where they always did:

* a **run bundle** — ``<results>/<run>/bundle/analysis.json`` with
  ``sample.sha256`` (D26 replays against it);
* a **queued or running job** in the D27 queue, identified by its store
  reference or, for a job enqueued before D28, by hashing the original sample
  path it still points at.

This module only reads those two sources and aggregates them by content address.
It writes nothing. The store caches the scan result for reporting, and prunes on
the fresh scan, so a stale cache can never decide on its own.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence
from urllib.parse import quote

from engine.store.crypto import MAX_DECLARED_PLAINTEXT

logger = logging.getLogger(__name__)

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
JOB_STATUSES_WITH_CLAIM = ("queued", "running")


@dataclass(frozen=True)
class Reference:
    """One reason a sample must be kept."""

    kind: str  # "run" | "job"
    identifier: str
    path: str
    sha256: str

    def label(self) -> str:
        return f"{self.kind}:{self.identifier}"

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "path": self.path,
            "sha256": self.sha256,
            "label": self.label(),
        }


@dataclass
class ReferenceScan:
    """The result of one reference scan."""

    by_sha: dict[str, list[Reference]] = field(default_factory=dict)
    bundles_scanned: int = 0
    jobs_scanned: int = 0
    warnings: list[str] = field(default_factory=list)
    unreadable_jobs: list[str] = field(default_factory=list)

    def add(self, reference: Reference) -> None:
        self.by_sha.setdefault(reference.sha256, []).append(reference)

    def count(self, sha256: str) -> int:
        return len(self.by_sha.get(sha256, ()))

    def references(self, sha256: str) -> list[Reference]:
        return list(self.by_sha.get(sha256, ()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundles_scanned": self.bundles_scanned,
            "jobs_scanned": self.jobs_scanned,
            "referenced_samples": len(self.by_sha),
            "references": [
                reference.to_dict()
                for references in self.by_sha.values()
                for reference in references
            ],
            "warnings": list(self.warnings),
            "unreadable_jobs": list(self.unreadable_jobs),
        }


def _sha256_file(path: Path, *, max_bytes: int = MAX_DECLARED_PLAINTEXT) -> str:
    """Hash a file without following a symlink or reading it unbounded."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise ValueError("is a symlink; refusing to follow it")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("is not a regular file")
    if info.st_size > max_bytes:
        raise ValueError(f"is {info.st_size} bytes, above the {max_bytes}-byte limit")
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bundle_dirs(results_root: Path) -> Iterable[Path]:
    """Every ``bundle/`` directory under a results root.

    One level for ``results/<task>/bundle`` and two for a replay run
    (``results/<task>/replay-xxxx/bundle``). Deeper nesting is not a layout the
    engine writes, and walking the whole tree would make prune scale with the
    size of the results directory.
    """
    for pattern in ("*/bundle", "*/*/bundle"):
        yield from results_root.glob(pattern)


def scan_results(results_roots: Sequence[Path], scan: ReferenceScan) -> None:
    seen: set[str] = set()
    for root in results_roots:
        if not root.is_dir():
            continue
        for bundle_dir in _bundle_dirs(root):
            analysis = bundle_dir / "analysis.json"
            if not analysis.is_file():
                continue
            key = str(analysis.resolve())
            if key in seen:
                continue
            seen.add(key)
            scan.bundles_scanned += 1
            try:
                if analysis.stat().st_size > MAX_BUNDLE_BYTES:
                    scan.warnings.append(
                        f"bundle {analysis} is larger than {MAX_BUNDLE_BYTES} bytes; "
                        "skipped (its sample is not protected by this scan)"
                    )
                    continue
                data = json.loads(analysis.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                scan.warnings.append(f"bundle {analysis} could not be read: {exc}")
                continue
            sample = data.get("sample") if isinstance(data, dict) else None
            sample = sample if isinstance(sample, dict) else {}
            sha = str(sample.get("sha256") or "").strip().lower()
            if not sha:
                scan.warnings.append(
                    f"bundle {analysis} records no sample.sha256; it protects nothing"
                )
                continue
            run_dir = bundle_dir.parent
            scan.add(
                Reference(
                    kind="run",
                    identifier=run_dir.name,
                    path=str(bundle_dir),
                    sha256=sha,
                )
            )


def _queue_columns(conn: sqlite3.Connection) -> set[str]:
    return {str(row[1]) for row in conn.execute("PRAGMA table_info(jobs)")}


def scan_queue(queue_db: Optional[Path], scan: ReferenceScan, *, max_bytes: int) -> None:
    """Protect the samples of jobs that are queued or running.

    A D28 job carries its content address and store reference. A pre-D28 job
    carries only the original path, so the path is hashed here — safely, with a
    symlink refusal and a size bound — and reported as a legacy job reference.
    A queued job whose sample cannot be read at all is recorded as *unreadable*;
    prune refuses to delete anything while that is true, because it cannot know
    what that job needs.
    """
    if queue_db is None or not Path(queue_db).is_file():
        return
    uri = f"file:{quote(str(Path(queue_db).expanduser().resolve()))}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        scan.warnings.append(f"queue database {queue_db} could not be opened read-only: {exc}")
        return
    try:
        columns = _queue_columns(conn)
        if not columns:
            scan.warnings.append(f"queue database {queue_db} has no jobs table")
            return
        select = ["job_id", "status", "sample_path", "sample_sha256"]
        if "sample_store_ref" in columns:
            select.append("sample_store_ref")
        rows = conn.execute(
            f"SELECT {', '.join(select)} FROM jobs WHERE status IN (?, ?)",
            JOB_STATUSES_WITH_CLAIM,
        ).fetchall()
    except sqlite3.Error as exc:
        scan.warnings.append(f"queue database {queue_db} could not be read: {exc}")
        return
    finally:
        conn.close()

    for row in rows:
        job_id, status, sample_path = str(row[0]), str(row[1]), str(row[2] or "")
        candidates = [str(row[3] or "").strip().lower()]
        if len(row) > 4:
            candidates.append(str(row[4] or "").strip().lower())
        sha = next((value for value in candidates if value), "")
        scan.jobs_scanned += 1
        if sha:
            scan.add(
                Reference(kind="job", identifier=job_id, path=str(queue_db), sha256=sha)
            )
            continue
        if not sample_path:
            scan.unreadable_jobs.append(
                f"job {job_id} ({status}) has neither a content address nor a sample path"
            )
            continue
        try:
            sha = _sha256_file(Path(sample_path), max_bytes=max_bytes)
        except (OSError, ValueError) as exc:
            scan.unreadable_jobs.append(
                f"job {job_id} ({status}) points at {sample_path}, which {exc}; "
                "its sample cannot be identified"
            )
            continue
        scan.add(
            Reference(kind="job", identifier=job_id, path=sample_path, sha256=sha)
        )
        scan.warnings.append(
            f"job {job_id} ({status}) predates the sample store; it still points at "
            f"{sample_path} and was protected by hashing that path"
        )


def collect_references(
    *,
    results_roots: Sequence[Path],
    queue_db: Optional[Path],
    max_bytes: int = MAX_DECLARED_PLAINTEXT,
) -> ReferenceScan:
    """Read every reference the store must respect."""
    scan = ReferenceScan()
    scan_results(results_roots, scan)
    scan_queue(queue_db, scan, max_bytes=max_bytes)
    return scan


__all__ = [
    "JOB_STATUSES_WITH_CLAIM",
    "Reference",
    "ReferenceScan",
    "collect_references",
    "scan_queue",
    "scan_results",
]
