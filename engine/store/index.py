"""The persistent sample index (D28).

The index is a sidecar SQLite database inside the store. It answers questions
the blobs cannot: when a sample was stored, when it was last referenced by a run
or a job, which envelope version and key id it carries, and what the last scan
decided about it. The **blobs are the truth** and the index is a cache of facts
about them — :meth:`engine.store.store.SampleStore.reconcile` rebuilds any row
whose blob disagrees with it, so a crash between writing a blob and writing its
row cannot hide a sample.

Durability follows D27: WAL, a busy timeout, and ``BEGIN IMMEDIATE`` for every
mutation, so a prune, a worker and a status read can share the file. The index
is not authoritative for *references* — the results bundles and the queue are —
so a stale ``reference_state`` can never protect or delete the wrong sample on
its own.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from engine.store.errors import INDEX_ERROR, SampleStoreError

INDEX_SCHEMA_VERSION = 1
INDEX_FILENAME = "index.db"

ACTIVE = "active"
DELETING = "deleting"

REFERENCE_UNKNOWN = "unknown"
REFERENCE_REFERENCED = "referenced"
REFERENCE_UNREFERENCED = "unreferenced"

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256            TEXT PRIMARY KEY,
    size              INTEGER NOT NULL,
    blob              TEXT NOT NULL,
    stored_at         TEXT NOT NULL,
    last_referenced_at TEXT,
    encryption_version INTEGER NOT NULL DEFAULT 0,
    key_id            TEXT,
    reference_state   TEXT NOT NULL DEFAULT 'unknown',
    reference_count   INTEGER NOT NULL DEFAULT 0,
    state             TEXT NOT NULL DEFAULT 'active',
    last_checked_at   TEXT,
    last_error        TEXT
);

CREATE INDEX IF NOT EXISTS idx_samples_state ON samples(state);
CREATE INDEX IF NOT EXISTS idx_samples_reference ON samples(reference_state);
"""


def iso(epoch: Optional[float] = None) -> str:
    moment = (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        if epoch is not None
        else datetime.now(timezone.utc)
    )
    return moment.isoformat()


def epoch(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


@dataclass
class SampleRecord:
    """One stored sample, as the index knows it."""

    sha256: str
    size: int
    blob: str
    stored_at: str
    encryption_version: int = 0
    key_id: Optional[str] = None
    last_referenced_at: Optional[str] = None
    reference_state: str = REFERENCE_UNKNOWN
    reference_count: int = 0
    state: str = ACTIVE
    last_checked_at: Optional[str] = None
    last_error: Optional[str] = None

    @property
    def encrypted(self) -> bool:
        return self.encryption_version > 0

    @property
    def stored_epoch(self) -> float:
        return epoch(self.stored_at) or 0.0

    def anchor_epoch(self) -> float:
        """The most recent moment this sample was known to be needed."""
        candidates = [self.stored_epoch, epoch(self.last_referenced_at) or 0.0]
        return max(candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "blob": self.blob,
            "stored_at": self.stored_at,
            "last_referenced_at": self.last_referenced_at,
            "encryption_version": self.encryption_version,
            "encryption": "aes-256-gcm/v1" if self.encrypted else "plaintext-legacy",
            "key_id": self.key_id,
            "reference_state": self.reference_state,
            "reference_count": self.reference_count,
            "state": self.state,
            "last_checked_at": self.last_checked_at,
            "last_error": self.last_error,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "SampleRecord":
        return cls(
            sha256=str(row["sha256"]),
            size=int(row["size"]),
            blob=str(row["blob"]),
            stored_at=str(row["stored_at"]),
            encryption_version=int(row["encryption_version"] or 0),
            key_id=row["key_id"],
            last_referenced_at=row["last_referenced_at"],
            reference_state=str(row["reference_state"] or REFERENCE_UNKNOWN),
            reference_count=int(row["reference_count"] or 0),
            state=str(row["state"] or ACTIVE),
            last_checked_at=row["last_checked_at"],
            last_error=row["last_error"],
        )


class SampleIndex:
    """The only writer of the sample index.

    ``readonly`` opens the file with SQLite's ``mode=ro`` and never creates,
    migrates or writes it. A read-only *consumer* — replay — must not create
    store state just by looking for a sample, so a missing index behaves as an
    empty one and the blobs are still addressable.
    """

    def __init__(self, path: Path | str, *, readonly: bool = False) -> None:
        raw = str(path)
        self.readonly = readonly
        self._lock = threading.RLock()
        if readonly:
            self.path = raw
            if raw != ":memory:" and not Path(raw).is_file():
                self._conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.executescript(SCHEMA)
                return
            uri = f"file:{quote(str(Path(raw).expanduser().resolve()))}?mode=ro"
            self._conn = sqlite3.connect(
                uri, uri=True, timeout=60.0, isolation_level=None, check_same_thread=False
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA busy_timeout = 60000")
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > INDEX_SCHEMA_VERSION:
                raise SampleStoreError(
                    INDEX_ERROR,
                    f"the sample index {self.path} declares schema version {version}; "
                    f"this build understands {INDEX_SCHEMA_VERSION}.",
                )
            return
        if raw != ":memory:":
            Path(raw).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.path = raw
        self._conn = sqlite3.connect(
            raw, timeout=60.0, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 60000")
        if raw != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._check_version()
        self._conn.executescript(SCHEMA)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SampleIndex":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _check_version(self) -> None:
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        if version > INDEX_SCHEMA_VERSION:
            raise SampleStoreError(
                INDEX_ERROR,
                f"the sample index {self.path} declares schema version {version}; "
                f"this build understands {INDEX_SCHEMA_VERSION}. Refusing to "
                "modify an index written by a newer build.",
            )
        if version < INDEX_SCHEMA_VERSION:
            self._conn.execute(f"PRAGMA user_version = {INDEX_SCHEMA_VERSION}")

    # -- writes ------------------------------------------------------------

    def upsert(
        self,
        *,
        sha256: str,
        size: int,
        blob: str,
        stored_at: str,
        encryption_version: int,
        key_id: Optional[str] = None,
        last_checked_at: Optional[str] = None,
    ) -> None:
        """Insert or refresh a row, preserving the original store time.

        ``stored_at`` and ``last_referenced_at`` are kept on conflict: re-storing
        the same bytes must not reset the retention clock.
        """
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO samples (
                    sha256, size, blob, stored_at, encryption_version, key_id,
                    reference_state, reference_count, state, last_checked_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL)
                ON CONFLICT(sha256) DO UPDATE SET
                    size = excluded.size,
                    blob = excluded.blob,
                    encryption_version = excluded.encryption_version,
                    key_id = excluded.key_id,
                    state = ?,
                    last_checked_at = excluded.last_checked_at,
                    last_error = NULL
                """,
                (
                    sha256, int(size), blob, stored_at, int(encryption_version), key_id,
                    REFERENCE_UNKNOWN, ACTIVE, last_checked_at,
                    ACTIVE,
                ),
            )

    def delete(self, sha256: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM samples WHERE sha256 = ?", (sha256,))

    def set_state(self, sha256: str, state: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE samples SET state = ? WHERE sha256 = ?", (state, sha256)
            )

    def set_reference(
        self,
        sha256: str,
        *,
        count: int,
        now: Optional[float] = None,
    ) -> None:
        """Record the result of a reference scan.

        ``last_referenced_at`` only moves forward, so a scan that misses a
        transient bundle cannot shorten a sample's life.
        """
        moment = now if now is not None else None
        with self._lock:
            if count > 0:
                self._conn.execute(
                    """
                    UPDATE samples SET reference_state = ?, reference_count = ?,
                        last_referenced_at = COALESCE(?, last_referenced_at)
                    WHERE sha256 = ?
                    """,
                    (REFERENCE_REFERENCED, count, iso(moment), sha256),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE samples SET reference_state = ?, reference_count = 0
                    WHERE sha256 = ?
                    """,
                    (REFERENCE_UNREFERENCED, sha256),
                )

    def set_checked(
        self,
        sha256: str,
        *,
        now: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE samples SET last_checked_at = ?, last_error = ? WHERE sha256 = ?",
                (iso(now), error[:2000] if error else None, sha256),
            )

    def set_error(self, sha256: str, error: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE samples SET last_error = ? WHERE sha256 = ?",
                (error[:2000], sha256),
            )

    # -- reads -------------------------------------------------------------

    def get(self, sha256: str) -> Optional[SampleRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM samples WHERE sha256 = ?", (sha256,)
            ).fetchone()
        return SampleRecord.from_row(row) if row is not None else None

    def all(self) -> list[SampleRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM samples ORDER BY stored_at ASC, sha256 ASC"
            ).fetchall()
        return [SampleRecord.from_row(row) for row in rows]

    def sha256s(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute("SELECT sha256 FROM samples").fetchall()
        return [str(row["sha256"]) for row in rows]


__all__ = [
    "ACTIVE",
    "DELETING",
    "INDEX_FILENAME",
    "INDEX_SCHEMA_VERSION",
    "REFERENCE_REFERENCED",
    "REFERENCE_UNKNOWN",
    "REFERENCE_UNREFERENCED",
    "SampleIndex",
    "SampleRecord",
    "epoch",
    "iso",
]
