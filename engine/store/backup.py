"""Recoverable backups of the sample store and the durable queue (D29).

The state that cannot be regenerated is the encrypted sample store (blobs plus
index) and the D27 queue database. This module writes a self-describing backup
of exactly that, restores it into an empty root, and refuses to lie about either.

What it guarantees:

* **Every live database is copied with SQLite's backup API.** A file copy of a
  WAL database can be torn; ``sqlite3.Connection.backup`` takes a consistent
  snapshot while a writer is active.
* **Every blob is hashed while it is copied**, and the manifest is written
  **last** through a temporary file and an atomic rename. An interrupted backup
  has no manifest, so it cannot be mistaken for a complete one.
* **The manifest says what it does not contain.** Key ids present, whether a key
  is included, whether the backup is restorable without the operator's key, the
  schema versions, counts, sizes and what is deliberately excluded.
* **The key is excluded by default.** ``include_key=True`` writes the key ring
  ``0600`` inside the backup, records that a secret is present, and is the
  caller's job to warn about loudly. No key material is ever written to the
  manifest, a log line or an exception message — only key ids.
* **Restore treats the backup as hostile input.** Every path is validated
  (relative, no traversal, no symlink), every size is bounds-checked, every file
  hash is checked against the manifest, every blob is authenticated and its
  plaintext hash checked against the content address **before** a byte is
  written. A corrupt or newer backup writes nothing.

There is no plaintext path here: blobs are copied as ciphertext bytes, and the
only decryption (during restore verification) happens in memory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Optional
from urllib.parse import quote

from engine.store.crypto import (
    ENVELOPE_VERSION,
    HEADER_LEN,
    KEY_RING_NAME,
    KEY_RING_VERSION,
    MAGIC,
    MAX_DECLARED_PLAINTEXT,
    decrypt,
    is_envelope,
    key_ring_path,
    resolve_key_ring,
    verify_plaintext_hash,
    write_key_ring_file,
)
from engine.store.errors import (
    BACKUP_EXISTS,
    BACKUP_FAILED,
    MANIFEST_INVALID,
    MANIFEST_MISSING,
    MANIFEST_NEWER,
    NO_KEY,
    RESTORE_BLOB_MISMATCH,
    RESTORE_PATH_REFUSED,
    RESTORE_SCHEMA_NEWER,
    RESTORE_TARGET_NOT_EMPTY,
    SampleStoreError,
)
from engine.store.index import INDEX_FILENAME, INDEX_SCHEMA_VERSION
from engine.store.store import DEFAULT_MAX_SAMPLE_BYTES

BACKUP_FORMAT = "hatchery-backup"
MANIFEST_VERSION = 1
MANIFEST_NAME = "manifest.json"
BLOB_DIR = "store/blobs"
INDEX_RELPATH = f"store/{INDEX_FILENAME}"
QUEUE_RELPATH = "queue/queue.db"
SECRET_RELPATH = "secrets/sample-keyring"
CHUNK = 1024 * 1024

# Restore bounds: a hostile manifest cannot ask us to read a 4 TiB file.
MAX_INDEX_BYTES = 8 * 1024 * 1024 * 1024
MAX_QUEUE_BYTES = 8 * 1024 * 1024 * 1024
MAX_SECRET_BYTES = 256 * 1024
MAX_BLOB_BYTES = DEFAULT_MAX_SAMPLE_BYTES + HEADER_LEN + 64

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _now_iso(epoch: Optional[float] = None) -> str:
    moment = (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        if epoch is not None
        else datetime.now(timezone.utc)
    )
    return moment.isoformat()


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover - platforms without directory fds
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover
        pass
    finally:
        os.close(fd)


def _hash_stream(handle: Any, sink: Any = None) -> tuple[str, int]:
    """Hash a stream in bounded chunks, optionally writing it to ``sink``."""
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = handle.read(CHUNK)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
        if sink is not None:
            sink.write(chunk)
    return digest.hexdigest(), size


def _sqlite_backup(source: Path, destination: Path) -> None:
    """Copy a live SQLite database with the backup API (never a file copy)."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".tmp-db-{destination.name}-{os.getpid()}"
    try:
        source_conn = sqlite3.connect(str(source), timeout=60.0)
        try:
            destination_conn = sqlite3.connect(str(temporary))
            try:
                source_conn.backup(destination_conn)
                destination_conn.execute("PRAGMA journal_mode = DELETE")
                destination_conn.commit()
            finally:
                destination_conn.close()
        finally:
            source_conn.close()
        os.chmod(temporary, 0o600)
        with open(temporary, "rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        _fsync_dir(destination.parent)
    finally:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:  # pragma: no cover
            pass


def _sqlite_readonly(path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(str(path.resolve()))}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=30.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    return connection


def _db_user_version(path: Path) -> int:
    connection = _sqlite_readonly(path)
    try:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])
    finally:
        connection.close()


def _has_table(path: Path, table: str) -> bool:
    connection = _sqlite_readonly(path)
    try:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def _db_integrity(path: Path) -> str:
    connection = _sqlite_readonly(path)
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
        return str(row[0]) if row is not None else "unknown"
    finally:
        connection.close()


def _manifest_hash(path: Path) -> tuple[str, int]:
    with open(path, "rb") as handle:
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _write_manifest(output: Path, manifest: dict[str, Any]) -> None:
    """Write the manifest last: temp, fsync, atomic rename, directory fsync."""
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = output / f".tmp-manifest-{os.getpid()}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, output / MANIFEST_NAME)
    _fsync_dir(output)


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


def _queue_schema_version() -> int:
    # Imported lazily: engine.queue imports the worker, which imports this package.
    from engine.queue.store import QUEUE_SCHEMA_VERSION

    return int(QUEUE_SCHEMA_VERSION)


def create_backup(
    store_root: Path | str,
    output_dir: Path | str,
    *,
    include_key: bool = False,
    queue_db: Optional[Path | str] = None,
    now: Optional[float] = None,
    warn: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    """Write a self-describing backup. The manifest is written last.

    ``store_root`` must already exist. A legacy plaintext blob is refused: a
    backup must not be the thing that copies plaintext malware somewhere new —
    run ``hatchery store migrate`` first.
    """
    store = Path(store_root).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()
    if not store.is_dir():
        raise SampleStoreError(BACKUP_FAILED, f"the sample store {store} does not exist")
    if output.exists() and not output.is_dir():
        raise SampleStoreError(BACKUP_FAILED, f"the backup path {output} is not a directory")
    if (output / MANIFEST_NAME).exists():
        raise SampleStoreError(
            BACKUP_EXISTS,
            f"{output} already holds a complete backup ({MANIFEST_NAME}); "
            "choose a new directory rather than overwriting it",
        )
    output.mkdir(parents=True, exist_ok=True)
    (output / "store").mkdir(exist_ok=True)
    blob_dir = output / BLOB_DIR
    blob_dir.mkdir(parents=True, exist_ok=True)
    created = _now_iso(now)

    # The lock serialises prune/migrate/verify; a concurrent put only adds
    # blobs, so a consistent index snapshot taken here can never point at a blob
    # a prune removed underneath it.
    from engine.store.store import SampleStore

    sample_store = SampleStore(store)
    try:
        with sample_store.operation_lock(wait_seconds=60.0):
            sample_store.reconcile(now=now)
            index_rows: Optional[list[str]] = None
            index_entry: Optional[dict[str, Any]] = None
            index_present = (store / INDEX_FILENAME).is_file()
            warnings: list[str] = []
            if index_present:
                if not _has_table(store / INDEX_FILENAME, "samples"):
                    raise SampleStoreError(
                        BACKUP_FAILED,
                        f"the sample index {store / INDEX_FILENAME} has no `samples` "
                        "table; it is not a HATCHERY index. Refusing to back up an "
                        "unknown database.",
                    )
                index_version = _db_user_version(store / INDEX_FILENAME)
                if index_version > INDEX_SCHEMA_VERSION:
                    raise SampleStoreError(
                        RESTORE_SCHEMA_NEWER,
                        f"the sample index declares schema version {index_version}; "
                        f"this build understands {INDEX_SCHEMA_VERSION}. The backup is "
                        "refused rather than made unrecoverable.",
                    )
                destination = output / INDEX_RELPATH
                _sqlite_backup(store / INDEX_FILENAME, destination)
                digest, size = _manifest_hash(destination)
                index_entry = {
                    "path": INDEX_RELPATH,
                    "kind": "sqlite-index",
                    "sha256": digest,
                    "size": size,
                    "schema_version": index_version,
                }
                connection = _sqlite_readonly(destination)
                try:
                    index_rows = [
                        str(row["sha256"])
                        for row in connection.execute("SELECT sha256 FROM samples")
                    ]
                finally:
                    connection.close()

            candidates = (
                index_rows if index_rows is not None
                else [
                    entry.name[: -len(".sample")]
                    for entry in sorted(store.iterdir())
                    if entry.name.endswith(".sample")
                ]
            )
            files: list[dict[str, Any]] = []
            key_ids: set[str] = set()
            total_blob_bytes = 0
            for sha256 in sorted(set(candidates)):
                if not _SHA256.match(sha256):
                    raise SampleStoreError(
                        RESTORE_PATH_REFUSED,
                        f"the store index names an address that is not a sha256: {sha256!r}",
                    )
                entry = sample_store.blob_header(sha256)
                if not entry["key_id"]:
                    raise SampleStoreError(
                        BACKUP_FAILED,
                        f"the store still holds plaintext sample {sha256}; run "
                        "`hatchery store migrate` before backing it up. A backup must "
                        "not copy plaintext.",
                    )
                if entry["encryption_version"] != ENVELOPE_VERSION:
                    raise SampleStoreError(
                        RESTORE_SCHEMA_NEWER,
                        f"blob {sha256} uses envelope version "
                        f"{entry['encryption_version']}, which this build does not "
                        "understand; refusing to make a backup it cannot restore.",
                    )
                key_ids.add(str(entry["key_id"]))
                relative = f"{BLOB_DIR}/{sha256}.sample"
                digest, size = _copy_hashed(store / f"{sha256}.sample", output / relative)
                total_blob_bytes += size
                files.append(
                    {
                        "path": relative,
                        "kind": "blob",
                        "sha256": digest,
                        "size": size,
                        "content_address": sha256,
                        "envelope_version": entry["encryption_version"],
                        "key_id": entry["key_id"],
                    }
                )
            if index_entry is not None:
                files.append(index_entry)

            queue_entry: Optional[dict[str, Any]] = None
            queue_counts: dict[str, int] = {}
            queue_schema: Optional[int] = None
            queue_source = Path(queue_db).expanduser().resolve() if queue_db else None
            if queue_source is not None and queue_source.is_file() and queue_source.stat().st_size == 0:
                warnings.append(
                    f"{queue_source} is empty and holds no queue; it was not included "
                    "in the backup"
                )
                queue_source = None
            if queue_source is not None and queue_source.is_file():
                if not _has_table(queue_source, "jobs"):
                    raise SampleStoreError(
                        BACKUP_FAILED,
                        f"{queue_source} has no `jobs` table; it is not a HATCHERY "
                        "queue database. Pass --queue explicitly or remove the file.",
                    )
                queue_schema = _db_user_version(queue_source)
                if queue_schema > _queue_schema_version():
                    raise SampleStoreError(
                        RESTORE_SCHEMA_NEWER,
                        f"the queue {queue_source} declares schema version {queue_schema}; "
                        f"this build understands {_queue_schema_version()}.",
                    )
                destination = output / QUEUE_RELPATH
                _sqlite_backup(queue_source, destination)
                digest, size = _manifest_hash(destination)
                queue_entry = {
                    "path": QUEUE_RELPATH,
                    "kind": "sqlite-queue",
                    "sha256": digest,
                    "size": size,
                    "schema_version": queue_schema,
                }
                files.append(queue_entry)
                connection = _sqlite_readonly(destination)
                try:
                    for row in connection.execute(
                        "SELECT status, COUNT(*) AS n FROM jobs GROUP BY status"
                    ):
                        queue_counts[str(row["status"])] = int(row["n"])
                finally:
                    connection.close()

            ring = resolve_key_ring(store, create=False)
            active_key_id = ring.active.key_id if ring is not None else None
            secret_entry: Optional[dict[str, Any]] = None
            if include_key:
                if ring is None:
                    raise SampleStoreError(
                        NO_KEY,
                        "--include-key was requested but no key is configured, so "
                        "there is nothing to include",
                    )
                secret_path = output / SECRET_RELPATH
                write_key_ring_file(secret_path, ring)
                digest, size = _manifest_hash(secret_path)
                secret_entry = {
                    "path": SECRET_RELPATH,
                    "kind": "key-ring",
                    "sha256": digest,
                    "size": size,
                    "key_ids": ring.ids(),
                    "active_key_id": ring.active.key_id,
                }
                files.append(secret_entry)
                if warn is not None:
                    warn(
                        "the sample-encryption key ring is INCLUDED in this backup "
                        f"({SECRET_RELPATH}, mode 0600). Anyone who can read the "
                        "backup can decrypt every sample in it. Store it accordingly "
                        "and never commit it."
                    )

            counts = {
                "samples": len([item for item in files if item["kind"] == "blob"]),
                "queue_jobs": sum(queue_counts.values()),
            }
            manifest: dict[str, Any] = {
                "format": BACKUP_FORMAT,
                "manifest_version": MANIFEST_VERSION,
                "created_at": created,
                "source": {
                    "store_root": str(store),
                    "queue_db": str(queue_source) if queue_source else None,
                },
                "schema": {
                    "manifest": MANIFEST_VERSION,
                    "store_index": INDEX_SCHEMA_VERSION if index_present else None,
                    "queue": queue_schema,
                    "envelope": ENVELOPE_VERSION,
                    "key_ring": KEY_RING_VERSION,
                },
                "counts": {
                    **counts,
                    "blobs_bytes": total_blob_bytes,
                    "index_present": index_present,
                    "queue_present": queue_entry is not None,
                    "queue_by_status": queue_counts,
                },
                "sizes": {
                    "blobs_bytes": total_blob_bytes,
                    "index_bytes": index_entry["size"] if index_entry else 0,
                    "queue_bytes": queue_entry["size"] if queue_entry else 0,
                    "secret_bytes": secret_entry["size"] if secret_entry else 0,
                },
                "key": {
                    "active_key_id": active_key_id,
                    "key_ids": sorted(key_ids | set(ring.ids() if ring else [])),
                    "included": secret_entry is not None,
                    "secret_path": SECRET_RELPATH if secret_entry is not None else None,
                    "restorable_without_operator_key": bool(
                        secret_entry is not None or counts["samples"] == 0
                    ),
                    "warning": (
                        "This backup INCLUDES the key material. It is a secret."
                        if secret_entry is not None
                        else (
                            "The key is NOT included. Restoring needs the operator's "
                            "key (HATCHERY_SAMPLE_KEY / HATCHERY_SAMPLE_KEY_FILE or the "
                            "ring from the original store)."
                            if counts["samples"]
                            else "The backup holds no samples, so no key is needed."
                        )
                    ),
                },
                "warnings": warnings,
                "excluded": [
                    "the sample-encryption key (unless --include-key)",
                    "result bundles under results/ (plaintext, regenerable only by a re-run)",
                    "uploads/ intake copies (the operator's files)",
                    "the replay single-use plaintext staging file (never persisted in the store)",
                ],
                "files": files,
            }
            # Last: an interrupted backup has no manifest at all.
            _write_manifest(output, manifest)
    finally:
        sample_store.close()

    return {
        "ok": True,
        "backup": str(output),
        "manifest": str(output / MANIFEST_NAME),
        **manifest,
    }


def _copy_hashed(source: Path, destination: Path) -> tuple[str, int]:
    """Stream-copy a blob, hashing it, with temp + fsync + atomic rename."""
    info = os.lstat(source)
    if stat.S_ISLNK(info.st_mode):
        raise SampleStoreError(RESTORE_PATH_REFUSED, f"the blob {source} is a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise SampleStoreError(RESTORE_PATH_REFUSED, f"the blob {source} is not a regular file")
    if info.st_size > MAX_BLOB_BYTES:
        raise SampleStoreError(
            BACKUP_FAILED, f"the blob {source} is larger than the supported envelope limit"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".tmp-blob-{destination.name}-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        source_flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
        source_fd = os.open(source, source_flags)
        with os.fdopen(source_fd, "rb") as reader, os.fdopen(fd, "wb") as writer:
            digest, size = _hash_stream(reader, writer)
            writer.flush()
            os.fsync(writer.fileno())
            fd = -1
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        _fsync_dir(destination.parent)
        return digest, size
    finally:
        if fd >= 0:  # pragma: no cover - exception between open and fdopen
            os.close(fd)
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:  # pragma: no cover
            pass


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

_ALLOWED_SINGLE = {INDEX_RELPATH: "sqlite-index", QUEUE_RELPATH: "sqlite-queue",
                   SECRET_RELPATH: "key-ring"}


def _safe_member(root: Path, relative: str, kind: str) -> Path:
    """Validate a manifest path: relative, no traversal, no symlink, in-root."""
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not relative or ".." in pure.parts or "." in pure.parts:
        raise SampleStoreError(
            RESTORE_PATH_REFUSED,
            f"the manifest names an unsafe path {relative!r}; refusing to restore",
        )
    expected_kind = _ALLOWED_SINGLE.get(relative)
    if relative.startswith(f"{BLOB_DIR}/"):
        name = relative[len(BLOB_DIR) + 1 :]
        if not name.endswith(".sample") or not _SHA256.match(name[: -len(".sample")]):
            raise SampleStoreError(
                RESTORE_PATH_REFUSED,
                f"the manifest names a blob path that is not <sha256>.sample: {relative!r}",
            )
        if kind != "blob":
            raise SampleStoreError(
                RESTORE_PATH_REFUSED, f"the manifest entry {relative!r} has kind {kind!r}"
            )
    elif expected_kind is None or kind != expected_kind:
        raise SampleStoreError(
            RESTORE_PATH_REFUSED,
            f"the manifest names an unexpected file {relative!r} (kind {kind!r})",
        )
    candidate = root / relative
    # Refuse a symlink at any component, not only the leaf.
    current = root
    for part in pure.parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            raise SampleStoreError(
                MANIFEST_INVALID,
                f"the backup is incomplete: {relative!r} is missing",
            ) from None
        if stat.S_ISLNK(info.st_mode):
            raise SampleStoreError(
                RESTORE_PATH_REFUSED,
                f"the backup contains a symlink at {current}; refusing to follow it",
            )
    if not stat.S_ISREG(os.lstat(candidate).st_mode):
        raise SampleStoreError(
            RESTORE_PATH_REFUSED, f"{relative!r} is not a regular file"
        )
    return candidate


def _validate_manifest(root: Path) -> dict[str, Any]:
    path = root / MANIFEST_NAME
    if not path.is_file():
        raise SampleStoreError(
            MANIFEST_MISSING,
            f"{root} has no {MANIFEST_NAME}; an interrupted backup is not a complete one",
        )
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SampleStoreError(MANIFEST_INVALID, f"the manifest could not be read: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != BACKUP_FORMAT:
        raise SampleStoreError(MANIFEST_INVALID, "this is not a HATCHERY backup manifest")
    version = manifest.get("manifest_version")
    if not isinstance(version, int) or version < 1:
        raise SampleStoreError(MANIFEST_INVALID, "the manifest has no valid version")
    if version > MANIFEST_VERSION:
        raise SampleStoreError(
            MANIFEST_NEWER,
            f"the backup declares manifest version {version}; this build understands "
            f"{MANIFEST_VERSION}. Refusing to restore a newer backup.",
        )
    schema = manifest.get("schema")
    if not isinstance(schema, dict):
        raise SampleStoreError(MANIFEST_INVALID, "the manifest has no schema block")
    understood = {
        "manifest": MANIFEST_VERSION,
        "store_index": INDEX_SCHEMA_VERSION,
        "queue": _queue_schema_version(),
        "envelope": ENVELOPE_VERSION,
        "key_ring": KEY_RING_VERSION,
    }
    for name, supported in understood.items():
        declared = schema.get(name)
        if declared is None:
            continue
        if not isinstance(declared, int) or declared < 0:
            raise SampleStoreError(MANIFEST_INVALID, f"the manifest schema.{name} is invalid")
        if declared > supported:
            raise SampleStoreError(
                RESTORE_SCHEMA_NEWER,
                f"the backup's {name} schema version {declared} is newer than this "
                f"build understands ({supported}); refusing to import it.",
            )
    files = manifest.get("files")
    if not isinstance(files, list):
        raise SampleStoreError(MANIFEST_INVALID, "the manifest has no file list")
    key = manifest.get("key")
    if not isinstance(key, dict):
        raise SampleStoreError(MANIFEST_INVALID, "the manifest has no key block")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise SampleStoreError(MANIFEST_INVALID, "a manifest file entry is not an object")
        relative = entry.get("path")
        kind = entry.get("kind")
        digest = entry.get("sha256")
        size = entry.get("size")
        if not isinstance(relative, str) or not isinstance(kind, str):
            raise SampleStoreError(MANIFEST_INVALID, "a manifest file entry has no path/kind")
        if relative in seen:
            raise SampleStoreError(
                MANIFEST_INVALID, f"the manifest lists {relative!r} twice"
            )
        seen.add(relative)
        if not isinstance(digest, str) or not re.match(r"^[0-9a-f]{64}$", digest):
            raise SampleStoreError(
                MANIFEST_INVALID, f"the manifest entry {relative!r} has no valid sha256"
            )
        if not isinstance(size, int) or size < 0:
            raise SampleStoreError(
                MANIFEST_INVALID, f"the manifest entry {relative!r} has no valid size"
            )
        if kind == "blob" and size > MAX_BLOB_BYTES:
            raise SampleStoreError(
                MANIFEST_INVALID, f"the manifest entry {relative!r} is implausibly large"
            )
        if kind in ("sqlite-index", "sqlite-queue") and size > max(MAX_INDEX_BYTES, MAX_QUEUE_BYTES):
            raise SampleStoreError(
                MANIFEST_INVALID, f"the manifest entry {relative!r} is implausibly large"
            )
        if kind == "key-ring" and size > MAX_SECRET_BYTES:
            raise SampleStoreError(
                MANIFEST_INVALID, f"the manifest entry {relative!r} is implausibly large"
            )
        if kind == "blob":
            content = entry.get("content_address")
            expected = relative.rsplit("/", 1)[-1][: -len(".sample")]
            if content != expected:
                raise SampleStoreError(
                    MANIFEST_INVALID,
                    f"the manifest blob {relative!r} names content address {content!r}",
                )
    counts = manifest.get("counts")
    if not isinstance(counts, dict):
        raise SampleStoreError(MANIFEST_INVALID, "the manifest has no counts block")
    blobs = sum(1 for entry in files if entry["kind"] == "blob")
    if counts.get("samples") != blobs:
        raise SampleStoreError(
            MANIFEST_INVALID,
            f"the manifest says {counts.get('samples')} samples but lists {blobs} blobs",
        )
    if not isinstance(manifest.get("created_at"), str):
        raise SampleStoreError(MANIFEST_INVALID, "the manifest has no created_at")
    included = key.get("included")
    if not isinstance(included, bool):
        raise SampleStoreError(MANIFEST_INVALID, "the manifest key.included is not a boolean")
    has_secret = any(entry["kind"] == "key-ring" for entry in files)
    if included != has_secret:
        raise SampleStoreError(
            MANIFEST_INVALID,
            "the manifest says the key is "
            f"{'included' if included else 'excluded'}, but the file list disagrees",
        )
    if not isinstance(key.get("restorable_without_operator_key"), bool):
        raise SampleStoreError(
            MANIFEST_INVALID,
            "the manifest does not say whether the backup is restorable without a key",
        )
    return manifest


def _read_key_file_0600(path: Path) -> bytes:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SampleStoreError(RESTORE_PATH_REFUSED, f"the restored key ring {path} is not a regular file")
    if info.st_mode & 0o077:
        raise SampleStoreError(
            RESTORE_PATH_REFUSED, f"the backup key ring {path} is not 0600"
        )
    return path.read_bytes()


def restore_backup(
    backup_dir: Path | str,
    target_root: Path | str,
    *,
    force: bool = False,
    queue_target: Optional[Path | str] = None,
    store_target: Optional[Path | str] = None,
    now: Optional[float] = None,
) -> dict[str, Any]:
    """Restore a backup into an empty (or ``--force``) root, fail closed.

    Layout: ``<target>/samples`` is the store and ``<target>/queue.db`` is the
    restored queue (override with ``store_target``/``queue_target``). Nothing is
    written until every manifest, path, size, hash and envelope check has passed.
    A blob whose key is not available is *restored* but reported — the restore
    does not claim success while anything is undecryptable.
    """
    backup = Path(backup_dir).expanduser().resolve()
    target = Path(target_root).expanduser().resolve()
    manifest = _validate_manifest(backup)

    store_root = Path(store_target).expanduser().resolve() if store_target else target / "samples"
    queue_path = (
        Path(queue_target).expanduser().resolve() if queue_target else target / "queue.db"
    )

    # --- validate every entry before writing anything --------------------
    verified: list[dict[str, Any]] = []
    blob_records: list[dict[str, Any]] = []
    for entry in manifest["files"]:
        relative = str(entry["path"])
        source = _safe_member(backup, relative, str(entry["kind"]))
        actual_size = os.lstat(source).st_size
        if actual_size != int(entry["size"]):
            raise SampleStoreError(
                RESTORE_BLOB_MISMATCH,
                f"{relative} is {actual_size} bytes but the manifest says {entry['size']}; "
                "the backup is torn or was modified",
            )
        digest, size = _manifest_hash(source)
        if digest != entry["sha256"] or size != actual_size:
            raise SampleStoreError(
                RESTORE_BLOB_MISMATCH,
                f"{relative} has sha256 {digest}, but the manifest records "
                f"{entry['sha256']}; refusing to import a modified backup",
            )
        verified.append(entry)
        if entry["kind"] == "blob":
            blob_records.append({**entry, "source": str(source)})

    # Index and queue: integrity, schema and row counts (never re-derive rows).
    index_entry = next((e for e in verified if e["kind"] == "sqlite-index"), None)
    queue_entry = next((e for e in verified if e["kind"] == "sqlite-queue"), None)
    index_sha256s: set[str] = set()
    if index_entry is not None:
        source = backup / index_entry["path"]
        if _db_integrity(source) != "ok":
            raise SampleStoreError(MANIFEST_INVALID, "the backup's sample index failed integrity_check")
        version = _db_user_version(source)
        if version > INDEX_SCHEMA_VERSION:
            raise SampleStoreError(
                RESTORE_SCHEMA_NEWER,
                f"the backup's sample index declares schema version {version}; this "
                f"build understands {INDEX_SCHEMA_VERSION}",
            )
        connection = _sqlite_readonly(source)
        try:
            index_sha256s = {
                str(row["sha256"])
                for row in connection.execute("SELECT sha256 FROM samples")
            }
        finally:
            connection.close()
        blob_addresses = {str(entry["content_address"]) for entry in blob_records}
        if index_sha256s != blob_addresses:
            raise SampleStoreError(
                MANIFEST_INVALID,
                "the backup's index and blobs disagree "
                f"({len(index_sha256s)} rows, {len(blob_addresses)} blobs); it is not "
                "a consistent backup",
            )
    if queue_entry is not None:
        source = backup / queue_entry["path"]
        if _db_integrity(source) != "ok":
            raise SampleStoreError(MANIFEST_INVALID, "the backup's queue failed integrity_check")
        version = _db_user_version(source)
        if version > _queue_schema_version():
            raise SampleStoreError(
                RESTORE_SCHEMA_NEWER,
                f"the backup's queue declares schema version {version}; this build "
                f"understands {_queue_schema_version()}",
            )

    # Keys: from the backup (if included) or the operator's configuration.
    secret_entry = next((e for e in verified if e["kind"] == "key-ring"), None)
    ring = None
    secret_bytes: Optional[bytes] = None
    if secret_entry is not None:
        secret_bytes = _read_key_file_0600(backup / secret_entry["path"])
        from engine.store.crypto import parse_key_ring

        ring = parse_key_ring(
            secret_bytes.decode("utf-8"),
            source=f"backup:{secret_entry['path']}",
            path=None,
        )
    else:
        # Resolve against the *target* so the operator's env/file can supply the
        # key. A generated key must never be created just to verify a restore.
        ring = resolve_key_ring(store_root, create=False)

    # Authenticate every blob and check its plaintext hash before writing it.
    undecryptable: list[dict[str, Any]] = []
    for record in blob_records:
        source = Path(record["source"])
        with open(source, "rb") as handle:
            header = handle.read(HEADER_LEN)
        if not is_envelope(header):
            raise SampleStoreError(
                RESTORE_BLOB_MISMATCH, f"{record['path']} is not a HATCHERY envelope"
            )
        version = header[len(MAGIC)]
        if version != ENVELOPE_VERSION:
            raise SampleStoreError(
                RESTORE_SCHEMA_NEWER,
                f"{record['path']} uses envelope version {version}; this build "
                f"understands {ENVELOPE_VERSION}",
            )
        key_id = header[len(MAGIC) + 1 : len(MAGIC) + 1 + 8].hex()
        if key_id != record.get("key_id"):
            raise SampleStoreError(
                RESTORE_BLOB_MISMATCH,
                f"{record['path']} names key id {key_id}, but the manifest says "
                f"{record.get('key_id')}",
            )
        if ring is None or ring.get(key_id) is None:
            undecryptable.append(
                {
                    "sha256": record["content_address"],
                    "key_id": key_id,
                    "reason": "key-missing",
                    "message": (
                        f"restored, but key id {key_id} is not configured; supply "
                        "HATCHERY_SAMPLE_KEY/HATCHERY_SAMPLE_KEY_FILE (or restore a "
                        "backup made with --include-key) to decrypt this sample"
                    ),
                }
            )
            continue
        try:
            with open(source, "rb") as handle:
                blob = handle.read()
            plaintext = decrypt(
                blob,
                ring.get(key_id) or ring.active,
                max_bytes=MAX_DECLARED_PLAINTEXT,
                address=str(record["content_address"]),
            )
            verify_plaintext_hash(plaintext, str(record["content_address"]))
        except SampleStoreError as exc:
            raise SampleStoreError(
                RESTORE_BLOB_MISMATCH,
                f"{record['path']} failed verification ({exc.reason}: {exc.message}); "
                "refusing to import a corrupt store",
            ) from exc

    # --- target checks ----------------------------------------------------
    if target.exists():
        existing = [entry for entry in target.iterdir()]
        if existing and not force:
            raise SampleStoreError(
                RESTORE_TARGET_NOT_EMPTY,
                f"{target} is not empty; restore into a new root or pass --force "
                "(which still never overwrites a blob whose bytes differ)",
            )
    else:
        target.mkdir(parents=True, exist_ok=True)

    planned: list[tuple[Path, Path, str, bytes]] = []
    for record in verified:
        kind = record["kind"]
        if kind == "blob":
            destination = store_root / f"{record['content_address']}.sample"
        elif kind == "sqlite-index":
            destination = store_root / INDEX_FILENAME
        elif kind == "sqlite-queue":
            destination = queue_path
        else:
            destination = store_root / KEY_RING_NAME
        source = backup / str(record["path"])
        if destination.exists():
            if destination.is_file() and _manifest_hash(destination)[0] == record["sha256"]:
                planned.append((source, destination, str(record["sha256"]), b"identical"))
                continue
            raise SampleStoreError(
                RESTORE_BLOB_MISMATCH,
                f"{destination} already exists with different bytes; refusing to "
                "overwrite it, even with --force",
            )
        planned.append((source, destination, str(record["sha256"]), b"write"))

    # --- write ------------------------------------------------------------
    written: list[str] = []
    store_root.mkdir(parents=True, exist_ok=True)
    for source, destination, expected, action in planned:
        if action == b"identical":
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.parent / f".tmp-restore-{destination.name}-{os.getpid()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temporary, flags, 0o600)
        try:
            with open(source, "rb") as reader, os.fdopen(fd, "wb") as writer:
                digest, _ = _hash_stream(reader, writer)
                writer.flush()
                os.fsync(writer.fileno())
                fd = -1
            if digest != expected:
                raise SampleStoreError(
                    RESTORE_BLOB_MISMATCH,
                    f"{source} changed while it was being restored",
                )
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            _fsync_dir(destination.parent)
        finally:
            if fd >= 0:  # pragma: no cover
                os.close(fd)
            try:
                if temporary.exists():
                    temporary.unlink()
            except OSError:  # pragma: no cover
                pass
        written.append(str(destination))

    # If the backup carried its ring, it is now the target store's ring exactly
    # as it was in the source. If it did not, the operator's key is used as-is.
    if secret_bytes is not None:
        ring_path = key_ring_path(store_root)
        if not ring_path.exists():
            write_key_ring_file(ring_path, ring)  # type: ignore[arg-type]

    # --- post-restore verification ---------------------------------------
    from engine.store.store import SampleStore

    restored = SampleStore(store_root)
    failures: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    try:
        if secret_bytes is not None:
            restored._set_ring(ring)  # type: ignore[arg-type, union-attr]
        report = restored.verify()
        entries = report["entries"]
        failures = list(report["failures"])
        verify_ok = bool(report["ok"])
        state = restored.rotation_state()
    finally:
        restored.close()

    # A queued/running job whose restored sample is absent is not silently
    # requeued with no sample; it is reported so an operator can see it now.
    missing_jobs: list[dict[str, Any]] = []
    queue_jobs = 0
    if queue_entry is not None and queue_path.is_file():
        connection = _sqlite_readonly(queue_path)
        try:
            queue_jobs = int(
                connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            )
            from engine.queue.store import QUEUED, RUNNING

            for row in connection.execute(
                "SELECT job_id, status, sample_store_ref FROM jobs WHERE status IN (?, ?)",
                (QUEUED, RUNNING),
            ):
                ref = row["sample_store_ref"]
                if not ref or not (store_root / f"{ref}.sample").is_file():
                    missing_jobs.append(
                        {
                            "job_id": str(row["job_id"]),
                            "status": str(row["status"]),
                            "reason": "not-found" if ref else "no-store-reference",
                            "sample_store_ref": ref,
                        }
                    )
        finally:
            connection.close()

    undecryptable_ids = {item["sha256"] for item in undecryptable}
    failure_ids = {
        str(item.get("sha256")) for item in failures
        if str(item.get("reason")) not in ("key-missing", "no-key", "unknown-key-id")
    }
    ok = (
        verify_ok
        and not undecryptable_ids
        and not failure_ids
        and not missing_jobs
    )
    return {
        "ok": ok,
        "backup": str(backup),
        "target": str(target),
        "store_root": str(store_root),
        "queue_db": str(queue_path) if queue_entry is not None else None,
        "written": written,
        "samples": len(blob_records),
        "queue_jobs": queue_jobs,
        "key": {
            "included_in_backup": secret_bytes is not None,
            "active_key_id": ring.active.key_id if ring is not None else None,
            "key_ids": ring.ids() if ring is not None else [],
        },
        "undecryptable": undecryptable,
        "missing_sample_jobs": missing_jobs,
        "verify": {
            "ok": verify_ok,
            "checked": len(entries),
            "failed": len(failures),
            "entries": entries,
        },
        "rotation": state,
        "message": (
            "restored and verified"
            if ok
            else "restored, but not everything could be verified; see undecryptable/"
            "verify/missing_sample_jobs. Nothing was deleted."
        ),
        "created_at": _now_iso(now),
    }


__all__ = [
    "BACKUP_FORMAT",
    "MANIFEST_NAME",
    "MANIFEST_VERSION",
    "create_backup",
    "restore_backup",
]
