"""The content-addressed, encrypted sample store (D28).

One implementation, used by direct submission, ``--enqueue``, the worker,
replay and the ``hatchery store`` maintenance commands. There is deliberately no
second store: the previous revision had a plaintext ``samples/<sha256>.sample``
copy with no index, no expiry and no reference tracking, so a queued job broke
when the original path was deleted and nobody could say which stored samples a
bundle still needed.

Guarantees:

* **Content addressed.** The address is the SHA-256 of the plaintext; the blob
  name is ``<sha256>.sample`` and the plaintext hash is re-checked on every read.
* **Encrypted at rest.** A write encrypts in memory and writes an authenticated
  envelope (see :mod:`engine.store.crypto`). No write path emits plaintext, and
  the only temporary file a write creates contains ciphertext.
* **Atomic.** Write to a ``.tmp-`` file, ``fsync``, rename over the target,
  ``fsync`` the directory, then upsert the index row. A crash leaves either the
  old blob or the new one, never a half-written sample; ``reconcile`` repairs
  any index row that disagrees with the blobs on disk.
* **Reference aware.** A sample referenced by a run bundle or a queued/running
  job is never pruned. References are re-read from the results tree and the
  queue database at prune time; the index only caches the last scan.
* **Fail closed.** Missing, expired, wrong-key, tampered, truncated and
  unknown-version samples each raise a distinct reason. Nothing falls back to
  plaintext silently.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional, Sequence

from engine.store.crypto import (
    ENVELOPE_LABEL,
    HEADER_LEN,
    KEY_FILE_NAME,
    LEGACY_LABEL,
    MAX_DECLARED_PLAINTEXT,
    SampleKey,
    decrypt,
    encrypt,
    is_envelope,
    resolve_key,
    verify_plaintext_hash,
)
from engine.store.errors import (
    EMPTY,
    EXPIRED,
    INDEX_ERROR,
    INVALID_SHA256,
    LEGACY_HASH_MISMATCH,
    NOT_A_FILE,
    NOT_EXPIRED,
    NOT_FOUND,
    NO_KEY,
    REFERENCED,
    STORE_LOCKED,
    SYMLINK,
    TOO_LARGE,
    TTL_DISABLED,
    SampleStoreError,
)
from engine.store.index import (
    ACTIVE,
    DELETING,
    INDEX_FILENAME,
    SampleIndex,
    SampleRecord,
    iso,
)
from engine.store.references import Reference, ReferenceScan, collect_references
from engine.store.roots import resolve_results_roots, resolve_store_root

logger = logging.getLogger(__name__)

BLOB_SUFFIX = ".sample"
TEMP_PREFIX = ".tmp-"
LOCK_FILENAME = ".store.lock"
DEFAULT_MAX_SAMPLE_BYTES = 256 * 1024 * 1024
TEMP_GRACE_SECONDS = 3600.0
TTL_ENV = "HATCHERY_SAMPLE_TTL"

INVALID_TTL = "invalid-ttl"
PLAINTEXT_LEGACY = "plaintext-legacy"


def is_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def validate_sha256(value: str) -> str:
    candidate = str(value or "").strip().lower()
    if not is_sha256(candidate):
        raise SampleStoreError(
            INVALID_SHA256,
            "a sample address is 64 lowercase hex characters (the plaintext sha256)",
        )
    return candidate


def resolve_ttl(value: Optional[float] = None) -> float:
    """TTL in seconds. ``0`` (the default) disables retention entirely."""
    if value is not None:
        return max(0.0, float(value))
    configured = os.environ.get(TTL_ENV, "").strip()
    if not configured:
        return 0.0
    try:
        return max(0.0, float(configured))
    except ValueError as exc:
        raise SampleStoreError(
            INVALID_TTL, f"{TTL_ENV}={configured!r} is not a number of seconds"
        ) from exc


@dataclass(frozen=True)
class StoredSample:
    """Plaintext bytes for one content address, plus how they were obtained."""

    sha256: str
    data: bytes
    encryption: str
    record: SampleRecord


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


class SampleStore:
    """The one sample store."""

    def __init__(
        self,
        root: Optional[Path | str] = None,
        *,
        index_path: Optional[Path | str] = None,
        clock: Optional[Any] = None,
        max_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
        key: Optional[SampleKey] = None,
        create: bool = True,
    ) -> None:
        # A read-only store (replay) must not create the directory, the index or
        # a key just by looking for a sample.
        self.readonly = not create
        self.root = resolve_store_root(root)
        if not self.readonly:
            self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve()
        self.max_bytes = int(max_bytes)
        self._clock = clock or time.time
        self._explicit_key = key
        self._key_cache: Optional[SampleKey] = None
        self._key_lock = threading.Lock()
        self.generated_key_notice: Optional[str] = None
        self.index_path = Path(index_path) if index_path else self.root / INDEX_FILENAME
        self.index = SampleIndex(self.index_path, readonly=self.readonly)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self.index.close()

    def __enter__(self) -> "SampleStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def now(self, moment: Optional[float] = None) -> float:
        return self._clock() if moment is None else float(moment)

    def _require_writable(self, operation: str) -> None:
        if self.readonly:
            raise SampleStoreError(
                INDEX_ERROR,
                f"{operation} needs a writable store; this store was opened read-only",
            )

    # -- keys --------------------------------------------------------------

    def key(self, *, create: bool = False) -> Optional[SampleKey]:
        if self.readonly:
            create = False
        if self._explicit_key is not None:
            return self._explicit_key
        with self._key_lock:
            if self._key_cache is not None:
                return self._key_cache
            resolved = resolve_key(self.root, create=create)
            if resolved is not None:
                self._key_cache = resolved
                if resolved.generated:
                    self.generated_key_notice = (
                        f"generated a new local sample-encryption key at "
                        f"{resolved.source.split(':', 1)[-1]} (mode 0600). It is the only "
                        "key that can decrypt samples written from now on; back it up, or "
                        "set HATCHERY_SAMPLE_KEY/HATCHERY_SAMPLE_KEY_FILE to use your own."
                    )
            return resolved

    def key_status(self) -> dict[str, Any]:
        # A misconfigured key is an error, not "no key": pretending it is absent
        # would turn a 0600 mistake or a bad env value into a silent refusal.
        key = self.key(create=False)
        if key is None:
            return {
                "configured": False,
                "source": None,
                "key_id": None,
                "note": (
                    "no key is configured; the next write generates a local key at "
                    f"{self.root / KEY_FILE_NAME} (0600). Set HATCHERY_SAMPLE_KEY or "
                    "HATCHERY_SAMPLE_KEY_FILE to use an operator-held key."
                ),
            }
        generated_file = key.source.startswith("generated:")
        inside_store = key.source.startswith("file:") and str(self.root) in key.source
        warning = None
        if generated_file or inside_store:
            warning = (
                "the key is stored beside the encrypted samples: it protects against "
                "plaintext at rest (backups, snapshots, accidental copies), not against "
                "an attacker who can read the store directory. Point "
                "HATCHERY_SAMPLE_KEY_FILE outside the store for a stronger posture."
            )
        return {
            "configured": True,
            "source": key.source,
            "key_id": key.key_id,
            "warning": warning,
        }

    # -- addressing --------------------------------------------------------

    def blob_path(self, sha256: str) -> Path:
        return self.root / f"{validate_sha256(sha256)}{BLOB_SUFFIX}"

    def has(self, sha256: str) -> bool:
        try:
            return self.blob_path(sha256).is_file()
        except SampleStoreError:
            return False

    # -- writes ------------------------------------------------------------

    def put_bytes(self, data: bytes, *, source: Optional[str] = None) -> SampleRecord:
        """Encrypt and store ``data``; returns its index record.

        The bytes are encrypted in memory. The temporary file written on the way
        to the final name contains ciphertext, so a crash cannot leave a
        plaintext sample on disk.
        """
        self._require_writable("storing a sample")
        data = bytes(data)
        if not data:
            raise SampleStoreError(EMPTY, "refusing to store an empty sample")
        if len(data) > self.max_bytes:
            raise SampleStoreError(
                TOO_LARGE,
                f"the sample is {len(data)} bytes, above the "
                f"{self.max_bytes}-byte store limit",
            )
        sha256 = hashlib.sha256(data).hexdigest()
        key = self.key(create=True)
        if key is None:  # pragma: no cover - create=True always resolves
            raise SampleStoreError(NO_KEY, "no sample-encryption key is available")
        envelope = encrypt(data, key)
        self._write_atomic(sha256, envelope)
        moment = self.now()
        self.index.upsert(
            sha256=sha256,
            size=len(data),
            blob=self.blob_path(sha256).name,
            stored_at=iso(moment),
            encryption_version=1,
            key_id=key.key_id,
            last_checked_at=iso(moment),
        )
        record = self.index.get(sha256)
        if record is None:  # pragma: no cover - the row was just written
            raise SampleStoreError(INDEX_ERROR, "the sample index did not retain the new row")
        logger.info(
            "Stored sample %s (%d bytes, %s%s)",
            sha256[:16], len(data), ENVELOPE_LABEL,
            f", source {source}" if source else "",
        )
        return record

    def put_file(self, source_path: Path | str) -> SampleRecord:
        """Read a host file and store it. Refuses symlinks and oversized input."""
        self._require_writable("storing a sample")
        path = Path(source_path)
        try:
            info = os.lstat(path)
        except FileNotFoundError as exc:
            raise SampleStoreError(NOT_FOUND, f"the sample file {path} does not exist") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SampleStoreError(SYMLINK, f"{path} is a symlink; refusing to follow it")
        if not stat.S_ISREG(info.st_mode):
            raise SampleStoreError(NOT_A_FILE, f"{path} is not a regular file")
        if info.st_size > self.max_bytes:
            raise SampleStoreError(
                TOO_LARGE,
                f"{path} is {info.st_size} bytes, above the "
                f"{self.max_bytes}-byte store limit",
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise SampleStoreError(NOT_FOUND, f"{path} could not be opened: {exc}") from exc
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(self.max_bytes + 1)
        if len(data) > self.max_bytes:
            raise SampleStoreError(TOO_LARGE, f"{path} grew past the store limit while reading")
        return self.put_bytes(data, source=str(path))

    def _write_atomic(self, sha256: str, envelope: bytes) -> None:
        target = self.blob_path(sha256)
        temporary = self.root / f"{TEMP_PREFIX}{sha256[:16]}-{os.getpid()}-{time.time_ns()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(envelope)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
            _fsync_dir(self.root)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    # -- reads -------------------------------------------------------------

    def _lstat_blob(self, sha256: str) -> os.stat_result:
        path = self.blob_path(sha256)
        try:
            info = os.lstat(path)
        except FileNotFoundError as exc:
            raise SampleStoreError(
                NOT_FOUND, f"no stored sample with sha256 {sha256}"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise SampleStoreError(SYMLINK, f"the stored blob for {sha256} is a symlink")
        if not stat.S_ISREG(info.st_mode):
            raise SampleStoreError(NOT_A_FILE, f"the stored blob for {sha256} is not a regular file")
        return info

    def _sniff(self, sha256: str) -> int:
        """0 for legacy plaintext, 1 for an envelope. The blob is the truth."""
        path = self.blob_path(sha256)
        try:
            with path.open("rb") as handle:
                header = handle.read(len(b"HATCHERY-SAMPLE\x00") + 1)
        except OSError as exc:
            raise SampleStoreError(NOT_FOUND, f"the stored blob for {sha256} is unreadable: {exc}") from exc
        return 1 if is_envelope(header) else 0

    def record(self, sha256: str) -> Optional[SampleRecord]:
        """The index row, or one derived from the blob when the index has none.

        The derivation is persisted only by a writable store; a read-only
        consumer gets the same view without creating an index.
        """
        sha256 = validate_sha256(sha256)
        row = self.index.get(sha256)
        if row is not None or not self.has(sha256):
            return row
        return self._record_from_blob(sha256)

    def read(self, sha256: str, *, verify: bool = True) -> StoredSample:
        """Decrypt in memory and verify the plaintext hash.

        Raises :class:`SampleStoreError` with a distinct ``reason`` for a
        missing blob, a symlink, an oversized file, a missing key, a wrong key,
        a tampered envelope, a truncated envelope, an unknown version and a
        content-address mismatch.
        """
        sha256 = validate_sha256(sha256)
        info = self._lstat_blob(sha256)
        if info.st_size > self.max_bytes + HEADER_LEN + 1024:
            raise SampleStoreError(
                TOO_LARGE,
                f"the stored blob for {sha256} is {info.st_size} bytes, above the "
                f"{self.max_bytes}-byte read limit",
            )
        blob = self.blob_path(sha256).read_bytes()
        if is_envelope(blob):
            key = self.key(create=False)
            if key is None:
                raise SampleStoreError(
                    NO_KEY,
                    "the sample is encrypted but no key is configured; set "
                    "HATCHERY_SAMPLE_KEY or HATCHERY_SAMPLE_KEY_FILE",
                )
            plaintext = decrypt(blob, key, max_bytes=min(self.max_bytes, MAX_DECLARED_PLAINTEXT))
            encryption = ENVELOPE_LABEL
        else:
            if len(blob) > self.max_bytes:
                raise SampleStoreError(TOO_LARGE, f"the stored blob for {sha256} is too large")
            plaintext = blob
            encryption = LEGACY_LABEL
        if verify:
            try:
                verify_plaintext_hash(plaintext, sha256)
            except SampleStoreError as exc:
                if exc.reason == "hash-mismatch" and encryption == LEGACY_LABEL:
                    raise SampleStoreError(LEGACY_HASH_MISMATCH, exc.message) from exc
                raise
        record = self.record(sha256)
        if record is None:  # pragma: no cover - the blob exists, so it resolves
            record = self._record_from_blob(sha256)
        return StoredSample(sha256=sha256, data=plaintext, encryption=encryption, record=record)

    def _adopt(self, sha256: str) -> SampleRecord:
        """Create the index row for a blob that exists (crash or legacy import)."""
        return self._record_from_blob(sha256)

    def _record_from_blob(self, sha256: str) -> SampleRecord:
        info = self._lstat_blob(sha256)
        encryption_version = self._sniff(sha256)
        key_id = None
        if encryption_version:
            with self.blob_path(sha256).open("rb") as handle:
                header = handle.read(HEADER_LEN)
            key_id = header[len(b"HATCHERY-SAMPLE\x00") + 1 :][:8].hex()
        size = info.st_size if not encryption_version else max(info.st_size - HEADER_LEN - 16, 0)
        record = SampleRecord(
            sha256=sha256,
            size=size,
            blob=self.blob_path(sha256).name,
            stored_at=iso(info.st_mtime),
            encryption_version=encryption_version,
            key_id=key_id,
        )
        if self.readonly:
            return record
        self.index.upsert(
            sha256=sha256,
            size=size,
            blob=record.blob,
            stored_at=record.stored_at,
            encryption_version=encryption_version,
            key_id=key_id,
            last_checked_at=None,
        )
        stored = self.index.get(sha256)
        if stored is None:  # pragma: no cover
            raise SampleStoreError(INDEX_ERROR, "could not index an existing blob")
        return stored

    # -- consistency -------------------------------------------------------

    def reconcile(self, *, now: Optional[float] = None, temp_grace_seconds: float = TEMP_GRACE_SECONDS) -> dict[str, Any]:
        """Make the index agree with the blobs, and clean abandoned temporaries.

        Blobs are the truth. A blob with no row is adopted; a row with no blob is
        dropped (loudly); a row whose recorded encryption disagrees with the
        blob's magic is repaired. Temporary files are ciphertext; a stale one is
        removed, a fresh one is assumed to be a concurrent write and left alone.
        """
        self._require_writable("reconcile")
        moment = self.now(now)
        report: dict[str, Any] = {
            "adopted": [],
            "repaired": [],
            "dropped": [],
            "temporary_removed": [],
            "temporary_in_progress": [],
            "symlinks": [],
            "ignored": [],
        }
        known = set(self.index.sha256s())
        for entry in sorted(self.root.iterdir()):
            name = entry.name
            if name in (INDEX_FILENAME, f"{INDEX_FILENAME}-wal", f"{INDEX_FILENAME}-shm"):
                continue
            if name in (KEY_FILE_NAME, LOCK_FILENAME):
                continue
            if name.startswith(TEMP_PREFIX):
                try:
                    age = moment - entry.lstat().st_mtime
                except OSError:
                    continue
                if age > temp_grace_seconds:
                    try:
                        entry.unlink()
                        report["temporary_removed"].append(name)
                    except OSError as exc:
                        report["ignored"].append(f"{name} (could not remove: {exc})")
                else:
                    report["temporary_in_progress"].append(name)
                continue
            if not name.endswith(BLOB_SUFFIX) or not is_sha256(name[: -len(BLOB_SUFFIX)]):
                report["ignored"].append(name)
                continue
            sha256 = name[: -len(BLOB_SUFFIX)]
            if entry.is_symlink():
                report["symlinks"].append(name)
                continue
            if not entry.is_file():
                report["ignored"].append(name)
                continue
            try:
                sniffed = self._sniff(sha256)
            except SampleStoreError as exc:
                report["ignored"].append(f"{name} ({exc.reason})")
                continue
            if sha256 not in known:
                self._adopt(sha256)
                report["adopted"].append(sha256)
            else:
                row = self.index.get(sha256)
                if row is not None and row.encryption_version != sniffed:
                    self._adopt(sha256)
                    report["repaired"].append(sha256)
        for row in self.index.all():
            if self.blob_path(row.sha256).exists():
                if row.state == DELETING:
                    # A prune was interrupted before the unlink. The blob is
                    # still there, so revert to active: the next prune makes a
                    # fresh decision from a fresh reference scan.
                    self.index.set_state(row.sha256, ACTIVE)
                    report["repaired"].append(row.sha256)
                continue
            self.index.delete(row.sha256)
            report["dropped"].append(
                {"sha256": row.sha256, "reason": row.state, "last_error": row.last_error}
            )
        return report

    def verify(self, *, sha256: Optional[str] = None, now: Optional[float] = None) -> dict[str, Any]:
        """Decrypt and hash-check every entry (or one). Never prints key material."""
        self._require_writable("verify")
        moment = self.now(now)
        self.reconcile(now=moment)
        rows = [self.index.get(validate_sha256(sha256))] if sha256 else self.index.all()
        entries: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        legacy: list[str] = []
        for row in rows:
            if row is None:
                missing: dict[str, Any] = {
                    "sha256": sha256, "status": "missing", "reason": NOT_FOUND
                }
                entries.append(missing)
                failures.append(missing)
                continue
            entry: dict[str, Any] = {
                "sha256": row.sha256,
                "size": row.size,
                "encryption": "aes-256-gcm/v1" if row.encrypted else LEGACY_LABEL,
                "key_id": row.key_id,
            }
            try:
                stored = self.read(row.sha256)
            except SampleStoreError as exc:
                entry.update({"status": "failed", "reason": exc.reason, "message": exc.message})
                failures.append(entry)
                self.index.set_checked(row.sha256, now=moment, error=f"{exc.reason}: {exc.message}")
            else:
                entry.update(
                    {
                        "status": "ok",
                        "encryption": stored.encryption,
                        "verified_sha256": stored.sha256,
                    }
                )
                if stored.encryption == LEGACY_LABEL:
                    legacy.append(row.sha256)
                    entry["status"] = "legacy"
                    entry["reason"] = PLAINTEXT_LEGACY
                    entry["message"] = (
                        "the sample is still stored in plaintext; run "
                        "`hatchery store migrate` to encrypt it"
                    )
                self.index.set_checked(row.sha256, now=moment, error=None)
            entries.append(entry)
        ok = not failures and not legacy
        return {
            "ok": ok,
            "store_root": str(self.root),
            "checked": len(entries),
            "passed": sum(1 for entry in entries if entry.get("status") == "ok"),
            "failed": len(failures),
            "legacy": len(legacy),
            "legacy_sha256": legacy,
            "entries": entries,
            "failures": failures,
        }

    # -- migration ---------------------------------------------------------

    def migrate(self, *, apply: bool = True, queue_db: Optional[Path] = None, now: Optional[float] = None) -> dict[str, Any]:
        """Encrypt a legacy plaintext store, idempotently and resumably.

        Each entry is decrypted/verified, re-encrypted and written with the
        atomic rename. A crash leaves either the plaintext blob (still readable)
        or the encrypted one (also readable), and the next run reconciles the
        index from the blob's magic bytes — so a second run skips what is done
        and retries what is not.
        """
        self._require_writable("migrate")
        moment = self.now(now)
        reconcile = self.reconcile(now=moment)
        legacy = [row for row in self.index.all() if not row.encrypted]
        report: dict[str, Any] = {
            "applied": bool(apply),
            "store_root": str(self.root),
            "legacy_found": len(legacy),
            "encrypted": [],
            "would_encrypt": [row.sha256 for row in legacy],
            "failed": [],
            "adopted_queue_jobs": [],
            "skipped_queue_jobs": [],
            "reconcile": reconcile,
        }
        if not apply:
            return report
        if legacy:
            key = self.key(create=True)
            if key is None:  # pragma: no cover
                raise SampleStoreError(NO_KEY, "migration needs a sample-encryption key")
            report["key"] = {"source": key.source, "key_id": key.key_id, "generated": key.generated}
        for row in legacy:
            try:
                stored = self.read(row.sha256)
                record = self.put_bytes(stored.data, source=f"migrate:{row.sha256[:16]}")
            except SampleStoreError as exc:
                report["failed"].append(
                    {"sha256": row.sha256, "reason": exc.reason, "message": exc.message}
                )
                self.index.set_checked(row.sha256, now=moment, error=f"{exc.reason}: {exc.message}")
            else:
                report["encrypted"].append(
                    {"sha256": record.sha256, "size": record.size,
                     "key_id": record.key_id, "was": PLAINTEXT_LEGACY}
                )
        if self.generated_key_notice:
            report["key_notice"] = self.generated_key_notice
        if queue_db is not None:
            adopted = self.adopt_queue_jobs(queue_db, now=moment)
            report["adopted_queue_jobs"] = adopted["adopted"]
            report["skipped_queue_jobs"] = adopted["skipped"]
            report["failed"].extend(adopted["failed"])
        return report

    def adopt_queue_jobs(self, queue_db: Path, *, now: Optional[float] = None) -> dict[str, Any]:
        """Give pre-D28 queued jobs a store reference, preserving id and state.

        The queue remains the single writer of job state: this calls
        :meth:`engine.queue.store.JobStore.attach_sample`, it does not touch the
        database directly. A running job is left alone — its worker owns the
        claim and will adopt the sample itself.
        """
        from engine.queue.store import QUEUED, JobStore  # local import: no cycle

        moment = self.now(now)
        adopted: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        jobs = JobStore(queue_db)
        try:
            for job in jobs.list(limit=100000):
                if job.status != QUEUED:
                    if job.status == "running" and not job.sample_store_ref:
                        skipped.append({"job_id": job.job_id, "reason": "running"})
                    continue
                if job.sample_store_ref:
                    continue
                try:
                    if job.sample_sha256 and self.has(job.sample_sha256):
                        record = self.record(job.sample_sha256)
                        sha256 = job.sample_sha256
                        if record is None:  # pragma: no cover
                            raise SampleStoreError(NOT_FOUND, "sample is not in the store")
                    else:
                        record = self.put_file(job.sample_path)
                        sha256 = record.sha256
                except SampleStoreError as exc:
                    failed.append({"job_id": job.job_id, "reason": exc.reason, "message": exc.message})
                    continue
                jobs.attach_sample(job.job_id, sha256=sha256, store_ref=sha256, now=moment)
                adopted.append({"job_id": job.job_id, "sha256": sha256})
        finally:
            jobs.close()
        return {"adopted": adopted, "skipped": skipped, "failed": failed}

    # -- retention ---------------------------------------------------------

    @contextmanager
    def operation_lock(self) -> Iterator[None]:
        """Serialise prune/migrate/verify across processes.

        A non-blocking ``flock`` on ``<store>/.store.lock``. Reading a sample
        does not take it: a prune never invalidates bytes a replay already
        decrypted, and a prune that wins the race simply removes a blob a reader
        then reports as missing — fail-closed, not corrupt.
        """
        lock_path = self.root / LOCK_FILENAME
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            try:
                import fcntl
            except ImportError:  # pragma: no cover - non-POSIX
                yield
                return
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise SampleStoreError(
                        STORE_LOCKED,
                        f"another store operation holds {lock_path}; retry when it finishes",
                    ) from exc
                raise
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _scan(self, *, results_roots: Optional[Sequence[Path]], queue_db: Optional[Path], now: float) -> ReferenceScan:
        roots = list(results_roots) if results_roots else resolve_results_roots()
        scan = collect_references(results_roots=roots, queue_db=queue_db, max_bytes=self.max_bytes)
        for sha256 in {row.sha256 for row in self.index.all()} | set(scan.by_sha):
            self.index.set_reference(sha256, count=scan.count(sha256), now=now)
        return scan

    def _entry_view(
        self,
        row: SampleRecord,
        *,
        scan: ReferenceScan,
        ttl: float,
        now: float,
    ) -> dict[str, Any]:
        references: list[Reference] = scan.references(row.sha256)
        age = max(0.0, now - row.anchor_epoch()) if row.anchor_epoch() else 0.0
        if references:
            decision, reason = "keep", REFERENCED
        elif ttl <= 0:
            decision, reason = "keep", TTL_DISABLED
        elif age <= ttl:
            decision, reason = "keep", NOT_EXPIRED
        else:
            decision, reason = "delete", EXPIRED
        view: dict[str, Any] = {
            "sha256": row.sha256,
            "size": row.size,
            "encryption": "aes-256-gcm/v1" if row.encrypted else LEGACY_LABEL,
            "key_id": row.key_id,
            "stored_at": row.stored_at,
            "last_referenced_at": row.last_referenced_at,
            "age_seconds": round(age, 3),
            "reference_count": len(references),
            "referenced_by": [reference.label() for reference in references],
            "expired": reason == EXPIRED,
            "decision": decision,
            "reason": reason,
        }
        if reason == NOT_EXPIRED:
            view["expires_in_seconds"] = round(ttl - age, 3)
        return view

    def status(
        self,
        *,
        ttl: Optional[float] = None,
        now: Optional[float] = None,
        results_roots: Optional[Sequence[Path]] = None,
        queue_db: Optional[Path] = None,
    ) -> dict[str, Any]:
        self._require_writable("status")
        moment = self.now(now)
        ttl_seconds = resolve_ttl(ttl)
        reconcile = self.reconcile(now=moment)
        scan = self._scan(results_roots=results_roots, queue_db=queue_db, now=moment)
        entries = [
            self._entry_view(row, scan=scan, ttl=ttl_seconds, now=moment)
            for row in self.index.all()
        ]
        encrypted = [entry for entry in entries if entry["encryption"] == ENVELOPE_LABEL]
        legacy = [entry for entry in entries if entry["encryption"] == LEGACY_LABEL]
        reclaimable = [entry for entry in entries if entry["decision"] == "delete"]
        return {
            "store_root": str(self.root),
            "index": str(self.index_path),
            "key": self.key_status(),
            "ttl_seconds": ttl_seconds,
            "ttl_enabled": ttl_seconds > 0,
            "samples": len(entries),
            "bytes": sum(int(entry["size"]) for entry in entries),
            "encrypted": len(encrypted),
            "legacy_plaintext": len(legacy),
            "expired": sum(1 for entry in entries if entry["expired"]),
            "referenced": sum(1 for entry in entries if entry["reference_count"]),
            "reclaimable": len(reclaimable),
            "reclaimable_bytes": sum(int(entry["size"]) for entry in reclaimable),
            "references": {
                "bundles_scanned": scan.bundles_scanned,
                "jobs_scanned": scan.jobs_scanned,
                "unreadable_jobs": list(scan.unreadable_jobs),
            },
            "warnings": list(scan.warnings) + list(reconcile["symlinks"]),
            "reconcile": reconcile,
            "entries": entries,
        }

    def prune(
        self,
        *,
        ttl: Optional[float] = None,
        apply: bool = False,
        now: Optional[float] = None,
        results_roots: Optional[Sequence[Path]] = None,
        queue_db: Optional[Path] = None,
    ) -> dict[str, Any]:
        """Delete expired, unreferenced samples — dry-run unless ``apply``.

        Fail closed on ambiguity: if a queued or running job's sample cannot be
        identified, ``apply`` refuses rather than deleting something that job
        might need.
        """
        self._require_writable("prune")
        moment = self.now(now)
        ttl_seconds = resolve_ttl(ttl)
        report: dict[str, Any] = {
            "applied": bool(apply),
            "ttl_seconds": ttl_seconds,
            "ttl_enabled": ttl_seconds > 0,
            "store_root": str(self.root),
            "deleted": [],
            "would_delete": [],
            "kept": [],
            "errors": [],
            "refused": [],
            "reconcile": {},
            "references": {},
        }
        with self.operation_lock():
            report["reconcile"] = self.reconcile(now=moment)
            scan = self._scan(results_roots=results_roots, queue_db=queue_db, now=moment)
            rows = self.index.all()
            entries = [self._entry_view(row, scan=scan, ttl=ttl_seconds, now=moment) for row in rows]
            report["references"] = {
                "bundles_scanned": scan.bundles_scanned,
                "jobs_scanned": scan.jobs_scanned,
                "unreadable_jobs": list(scan.unreadable_jobs),
            }
            if apply and scan.unreadable_jobs:
                report["refused"] = list(scan.unreadable_jobs)
                report["kept"] = entries
                report["summary"] = {
                    "kept": len(entries), "deleted": 0, "would_delete": 0,
                    "refused": len(scan.unreadable_jobs),
                }
                return report
            victims = [entry for entry in entries if entry["decision"] == "delete"]
            report["kept"] = [entry for entry in entries if entry["decision"] != "delete"]
            if not apply:
                report["would_delete"] = victims
                report["summary"] = {
                    "kept": len(report["kept"]),
                    "deleted": 0,
                    "would_delete": len(victims),
                    "refused": 0,
                }
                return report
            for entry in victims:
                self._delete_entry(entry, report)
            report["summary"] = {
                "kept": len(report["kept"]),
                "deleted": len(report["deleted"]),
                "would_delete": 0,
                "errors": len(report["errors"]),
            }
        return report

    def _delete_entry(self, entry: dict[str, Any], report: dict[str, Any]) -> None:
        sha256 = str(entry["sha256"])
        path = self.blob_path(sha256)
        # Mark first: an interrupted delete leaves a row a later reconcile can
        # finish (blob gone) or revert (blob still there).
        self.index.set_state(sha256, DELETING)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass  # another prune already removed it; the index row is the leftover
        except OSError as exc:
            self.index.set_state(sha256, ACTIVE)
            report["errors"].append(
                {"sha256": sha256, "reason": "delete-failed", "message": str(exc)}
            )
            return
        self.index.delete(sha256)
        _fsync_dir(self.root)
        deleted = dict(entry)
        deleted["deleted"] = True
        report["deleted"].append(deleted)
        logger.info("Pruned sample %s (%s)", sha256[:16], entry.get("reason"))

    # -- convenience -------------------------------------------------------

    def legacy_plaintext_count(self) -> int:
        return sum(1 for row in self.index.all() if not row.encrypted)


__all__ = [
    "BLOB_SUFFIX",
    "DEFAULT_MAX_SAMPLE_BYTES",
    "INVALID_TTL",
    "LOCK_FILENAME",
    "PLAINTEXT_LEGACY",
    "SampleStore",
    "StoredSample",
    "TEMP_GRACE_SECONDS",
    "TEMP_PREFIX",
    "TTL_ENV",
    "is_sha256",
    "resolve_ttl",
    "validate_sha256",
]
