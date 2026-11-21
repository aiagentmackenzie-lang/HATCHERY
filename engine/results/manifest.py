"""Result-bundle integrity: the hash manifest at the run root (D33).

A run directory is the artifact an analyst hands to a client. This module makes
"What is in this bundle, and is it the bundle HATCHERY wrote?" a checkable claim
instead of an assumption — without becoming a second producer of analysis data
(D4) and without becoming a second source of truth for what the run *found*.

The manifest is a **hash manifest**, not a signature:

* it records the SHA-256 of every file under the run root, written **last**, so
  an interrupted stage has no manifest rather than a half-manifested run;
* it is deterministic (UTF-8, sorted paths, ``json.dumps(sort_keys=True,
  separators=(",", ":"))`` + newline), so ``sha256(manifest bytes)`` is
  reproducible and ``--expect-manifest`` means something;
* it describes files and provenance only — never a verdict, an IOC, an
  extracted string or a sample byte.

It is **not** MAC'd or signed. The only key available to the process that
writes a bundle is readable by any attacker who can write the bundle, so a MAC
would defend against a strictly weaker attacker than the one that matters. The
compensating control is the anchor: record the manifest hash when you deliver
the run and pass it to ``hatchery results verify --expect-manifest``. A rewrite
of an artifact *and* its manifest is then caught; a deleted manifest is
unambiguous. Without an anchor, an attacker who rewrites both is not detected.

The manifest lives at ``results/<run>/manifest.json``, never inside ``bundle/``,
because ``bundle/`` is ingested by the API and read by replay and clustering: an
extra file there would be a change to their input. It never compares the
directory name to the recorded run id, so a run copied to another machine (or to
``/tmp/delivery/``) still verifies.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

FORMAT = "hatchery.result-manifest"
MANIFEST_FILENAME = "manifest.json"
MANIFEST_VERSION = 1
MANIFEST_TEMP_PREFIX = ".manifest.tmp-"
ANALYSIS_REL = "bundle/analysis.json"

#: The stages that call the one manifest writer. ``seal`` is the operator's
#: explicit re-seal of a run written before the manifest existed; it is recorded
#: as itself rather than pretending a stage ran that did not.
STAGES = ("submit", "triage", "push", "replay", "seal")

#: A seal must not become an unbounded operation.
MAX_FILES = 50_000
MAX_BYTES = 4 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
HASH_CHUNK = 1024 * 1024

#: Every classification a verification can report. None of them is ``ok``.
CLASSIFICATIONS = frozenset(
    {
        "modified",
        "missing",
        "extra",
        "truncated",
        "symlink",
        "manifest-missing",
        "manifest-invalid",
        "manifest-version",
        "unsealed",
        "replaced",
    }
)


class ManifestError(RuntimeError):
    """A seal or a seal request that cannot be honoured.

    ``reason`` is a stable, named code (never a free-text guess) so a caller can
    map it to an exit code and a test can pin it.
    """

    def __init__(self, reason: str, message: str, path: Optional[str] = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.path = path

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "message": self.message, "path": self.path}


# ---------------------------------------------------------------------------
# Paths, hashing and the file set
# ---------------------------------------------------------------------------


def resolve_run_root(path: str | os.PathLike[str]) -> Path:
    """The run directory for a path that may be a run dir or its ``bundle/``.

    Both are natural things for an operator to type, and ``replay`` already
    accepts both. Nothing here compares the directory's name to anything.
    """
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise ManifestError(
            "not-found", f"{candidate} does not exist", str(candidate)
        )
    if not candidate.is_dir():
        raise ManifestError(
            "not-a-run", f"{candidate} is not a directory", str(candidate)
        )
    if (candidate / ANALYSIS_REL).is_file():
        return candidate
    if (candidate / MANIFEST_FILENAME).is_file():
        return candidate
    if (
        candidate.name == "bundle"
        and (candidate / "analysis.json").is_file()
    ):
        return candidate.parent
    # An empty directory is still a legal (if useless) target: verify reports
    # what is missing rather than guessing that the operator meant a parent.
    return candidate


def is_nested_run(directory: Path) -> bool:
    """True when ``directory`` is a nested unit, not part of its parent's files.

    A replay writes ``results/<run>/replay-xxxx/`` — a bundle and a manifest on
    success, or just ``replay.json`` when the replay was inconclusive. Both are
    the child's state, not the parent's: including them in the parent manifest
    would make every legitimately replayed run a false ``extra`` break in the run
    it was replayed from. A failed replay's record is therefore reported as a
    nested unit with its own (unsealed) state rather than silently ignored.
    """
    return (
        directory.name.startswith("replay-")
        or (directory / ANALYSIS_REL).is_file()
        or (directory / MANIFEST_FILENAME).is_file()
    )


def safe_relative_path(value: Any) -> bool:
    """A manifest path must be a relative POSIX path with no traversal.

    Rejecting ``..``, an absolute path, a backslash and a NUL is what stops a
    crafted manifest from pointing the verifier at a file outside the run
    directory. It is validated *before* anything is hashed.
    """
    if not isinstance(value, str) or not value:
        return False
    if "\x00" in value or "\\" in value:
        return False
    if value.startswith("/") or value in (".", ".."):
        return False
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return value != MANIFEST_FILENAME


def hash_file(path: Path) -> tuple[int, str]:
    """Size and SHA-256 of a regular file, never following a symlink."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise ManifestError(
            "symlink", f"{path} is a symlink; refusing to hash through it", str(path)
        )
    if not stat.S_ISREG(info.st_mode):
        raise ManifestError(
            "unsupported-file-type",
            f"{path} is not a regular file; refusing to seal it",
            str(path),
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    size = 0
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK), b""):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _walk_files(run_root: Path) -> tuple[list[tuple[str, Path]], list[str]]:
    """Every regular file under the run root, plus stale seal temporaries.

    The run's own ``manifest.json`` is excluded (it is the seal, not content),
    as are this writer's temporaries. Direct child directories that are runs
    themselves (nested replays) are excluded entirely; a symlink anywhere is a
    refusal, never a file to hash through.
    """
    files: list[tuple[str, Path]] = []
    temporaries: list[str] = []
    errors: list[OSError] = []

    def onerror(exc: OSError) -> None:  # pragma: no cover - exercised by chmod tests
        errors.append(exc)

    root_str = str(run_root)
    for dirpath, dirnames, filenames in os.walk(
        root_str, topdown=True, followlinks=False, onerror=onerror
    ):
        if errors:
            _raise_unreadable(errors[0], run_root)
        here = Path(dirpath)
        keep: list[str] = []
        for name in sorted(dirnames):
            child = here / name
            if here == run_root and is_nested_run(child):
                continue
            if child.is_symlink():
                rel = child.relative_to(run_root).as_posix()
                raise ManifestError(
                    "symlink",
                    f"{rel} is a symlink; a run directory that contains a symlink "
                    "cannot be sealed",
                    rel,
                )
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = here / name
            rel = full.relative_to(run_root).as_posix()
            if here == run_root and name == MANIFEST_FILENAME:
                continue
            if here == run_root and name.startswith(MANIFEST_TEMP_PREFIX):
                temporaries.append(rel)
                continue
            if full.is_symlink():
                raise ManifestError(
                    "symlink",
                    f"{rel} is a symlink; a run directory that contains a symlink "
                    "cannot be sealed",
                    rel,
                )
            files.append((rel, full))
    if errors:
        _raise_unreadable(errors[0], run_root)
    return files, temporaries


def _raise_unreadable(exc: OSError, run_root: Path) -> None:
    raise ManifestError(
        "unreadable",
        f"cannot read {exc.filename or run_root}: {exc}",
        str(exc.filename or run_root),
    )


def collect_files(run_root: Path) -> list[dict[str, Any]]:
    """The file list a manifest records, sorted by path and bounded."""
    if not run_root.is_dir():
        raise ManifestError(
            "not-a-run", f"{run_root} is not a directory", str(run_root)
        )
    files, _temporaries = _walk_files(run_root)
    if len(files) > MAX_FILES:
        raise ManifestError(
            "too-many-files",
            f"{run_root} holds more than {MAX_FILES} files; refusing to seal an "
            "unbounded run directory",
            str(run_root),
        )
    entries: list[dict[str, Any]] = []
    total = 0
    for rel, full in sorted(files, key=lambda item: item[0]):
        size, digest = hash_file(full)
        total += size
        if total > MAX_BYTES:
            raise ManifestError(
                "too-large",
                f"{run_root} is larger than {MAX_BYTES} bytes; refusing to seal an "
                "unbounded run directory",
                str(run_root),
            )
        entries.append({"path": rel, "size": size, "sha256": digest})
    return entries


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hatchery_version() -> str:
    try:
        from importlib.metadata import version

        return version("hatchery")
    except Exception:  # pragma: no cover - a source tree without metadata
        return "unknown"


def _analysis_facts(run_root: Path) -> dict[str, Any]:
    """Provenance read from the one producer (D4): ids and the content address.

    Nothing analysis-shaped is copied into the manifest. The sample's sha256 is
    its content address — the same value the sample store is keyed by — and the
    store reference says which blob the run was analysed from. No verdict, IOC,
    count or extracted string is read here.
    """
    path = run_root / ANALYSIS_REL
    if not path.is_file():
        raise ManifestError(
            "no-analysis",
            f"{path} does not exist; a run without an analysis bundle cannot be "
            "sealed",
            str(path),
        )
    if path.is_symlink():
        raise ManifestError(
            "symlink", f"{path} is a symlink; refusing to follow it", str(path)
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestError(
            "unparseable-analysis",
            f"{path} could not be read as JSON: {exc}",
            str(path),
        ) from exc
    if not isinstance(data, dict):
        raise ManifestError(
            "unparseable-analysis",
            f"{path} is not a JSON object",
            str(path),
        )
    sample = data.get("sample")
    sample = sample if isinstance(sample, dict) else {}
    address = str(sample.get("sha256") or "").strip().lower()
    store = sample.get("store")
    store = store if isinstance(store, dict) else {}
    store_ref = str(store.get("reference") or "").strip().lower()
    sample_block = (
        {"sha256": address, "store_ref": store_ref or None} if address else None
    )
    return {
        "task_id": str(data.get("task_id") or ""),
        "created_at": str(data.get("generated_at") or ""),
        "sample": sample_block,
    }


def build_manifest(
    run_root: Path,
    *,
    stage: str,
    sealed_at: Optional[str] = None,
) -> dict[str, Any]:
    """The manifest document for a run as it is on disk now."""
    if stage not in STAGES:
        raise ManifestError(
            "bad-stage",
            f"stage {stage!r} is not one of {', '.join(STAGES)}",
        )
    run_root = Path(run_root)
    facts = _analysis_facts(run_root)
    files = collect_files(run_root)
    total = sum(int(entry["size"]) for entry in files)
    return {
        "format": FORMAT,
        "manifest_version": MANIFEST_VERSION,
        "run_id": run_root.name,
        "task_id": facts["task_id"],
        "created_at": facts["created_at"] or _now_iso(),
        "stage": stage,
        "sealed_at": sealed_at or _now_iso(),
        "hatchery_version": hatchery_version(),
        "algorithm": "sha256",
        "sample": facts["sample"],
        "files": files,
        "file_count": len(files),
        "total_bytes": total,
    }


def serialize(manifest: dict[str, Any]) -> bytes:
    """Deterministic bytes: sorted keys, compact separators, one trailing newline."""
    return (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover - a directory we cannot open to fsync
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_manifest(run_root: Path, manifest: dict[str, Any]) -> tuple[Path, str]:
    """Write the manifest last: temp + fsync + rename + directory fsync, 0600."""
    raw = serialize(manifest)
    target = run_root / MANIFEST_FILENAME
    if target.is_symlink() or (target.exists() and not target.is_file()):
        # A rename onto a symlink would replace the link itself, which is safe,
        # but a symlink here is an attack shape we refuse to work around.
        raise ManifestError(
            "manifest-symlink",
            f"{target} is not a regular file; refusing to write a manifest over it",
            str(target),
        )
    temporary = run_root / f"{MANIFEST_TEMP_PREFIX}{os.getpid()}-{uuid.uuid4().hex[:8]}"
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, target)
        _fsync_dir(run_root)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return target, hashlib.sha256(raw).hexdigest()


def seal_run(run_root: Path, *, stage: str) -> dict[str, Any]:
    """Write the manifest for a run as of ``stage``. The one writer.

    Every stage that writes or mutates a run directory ends here — submit,
    triage, push and replay — because a manifest written only at submit time
    would report ``modified`` after a legitimate triage, and a false break makes
    the whole feature untrustworthy. A crash before this returns leaves no
    manifest: never a half-manifested run reported complete.
    """
    run_root = Path(run_root)
    manifest = build_manifest(run_root, stage=stage)
    path, digest = write_manifest(run_root, manifest)
    logger.info(
        "Sealed %s at stage %s: %d files, %d bytes, manifest sha256 %s",
        run_root,
        stage,
        manifest["file_count"],
        manifest["total_bytes"],
        digest,
    )
    return {
        "run_id": run_root.name,
        "run_dir": str(run_root),
        "manifest_path": str(path),
        "manifest_sha256": digest,
        "stage": stage,
        "sealed_at": manifest["sealed_at"],
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _read_manifest_file(run_root: Path) -> tuple[Optional[bytes], Optional[str]]:
    """Read the manifest bytes without following a symlink.

    Returns ``(bytes, None)`` when the manifest is absent and ``(None, reason)``
    when it exists but cannot be a manifest we wrote.
    """
    path = run_root / MANIFEST_FILENAME
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, "manifest-invalid"
    if stat.S_ISLNK(info.st_mode):
        return None, "symlink"
    if not stat.S_ISREG(info.st_mode):
        return None, "manifest-invalid"
    if info.st_size > MAX_MANIFEST_BYTES:
        return None, "manifest-invalid"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        return handle.read(MAX_MANIFEST_BYTES + 1), None


def _manifest_document(raw: bytes) -> dict[str, Any]:
    """Parse and structurally validate a manifest. Raises :class:`ManifestError`."""
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ManifestError(
            "manifest-invalid", f"the manifest is not valid JSON: {exc}", MANIFEST_FILENAME
        ) from exc
    if not isinstance(document, dict):
        raise ManifestError(
            "manifest-invalid", "the manifest is not a JSON object", MANIFEST_FILENAME
        )
    if document.get("format") != FORMAT:
        raise ManifestError(
            "manifest-invalid",
            f"the manifest format is {document.get('format')!r}, expected {FORMAT!r}",
            MANIFEST_FILENAME,
        )
    version = document.get("manifest_version")
    if version != MANIFEST_VERSION:
        raise ManifestError(
            "manifest-version",
            f"manifest version {version!r} is not supported by this build "
            f"(expected {MANIFEST_VERSION})",
            MANIFEST_FILENAME,
        )
    files = document.get("files")
    if not isinstance(files, list):
        raise ManifestError(
            "manifest-invalid", "the manifest has no file list", MANIFEST_FILENAME
        )
    seen: set[str] = set()
    total = 0
    for entry in files:
        if not isinstance(entry, dict):
            raise ManifestError(
                "manifest-invalid", "a file entry is not an object", MANIFEST_FILENAME
            )
        rel = entry.get("path")
        if not safe_relative_path(rel):
            raise ManifestError(
                "manifest-invalid",
                f"file path {rel!r} is not a relative path inside the run directory",
                MANIFEST_FILENAME,
            )
        assert isinstance(rel, str)
        if rel in seen:
            raise ManifestError(
                "manifest-invalid",
                f"file path {rel!r} appears more than once",
                MANIFEST_FILENAME,
            )
        seen.add(rel)
        size = entry.get("size")
        digest = entry.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ManifestError(
                "manifest-invalid",
                f"file {rel!r} has an invalid size",
                MANIFEST_FILENAME,
            )
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ManifestError(
                "manifest-invalid",
                f"file {rel!r} has an invalid sha256",
                MANIFEST_FILENAME,
            )
        total += size
    if not seen:
        raise ManifestError(
            "manifest-invalid", "the manifest describes no files", MANIFEST_FILENAME
        )
    if ANALYSIS_REL not in seen:
        raise ManifestError(
            "manifest-invalid",
            f"the manifest does not describe {ANALYSIS_REL}; it is not a manifest "
            "for a HATCHERY run",
            MANIFEST_FILENAME,
        )
    if document.get("file_count") != len(files) or document.get("total_bytes") != total:
        raise ManifestError(
            "manifest-invalid",
            "the manifest's file count or byte total disagrees with its file list",
            MANIFEST_FILENAME,
        )
    return document


def _scan_actual(
    run_root: Path,
) -> tuple[dict[str, int], list[tuple[str, str]], list[str]]:
    """What is actually on disk: sizes, breaks, stale temporaries.

    A symlink is a break wherever it appears — recorded or not — and its target
    is never read. Direct child directories that are themselves runs (nested
    replays) are not part of this run's file set.
    """
    sizes: dict[str, int] = {}
    breaks: list[tuple[str, str]] = []
    temporaries: list[str] = []
    errors: list[OSError] = []

    def onerror(exc: OSError) -> None:
        errors.append(exc)

    root_str = str(run_root)
    for dirpath, dirnames, filenames in os.walk(
        root_str, topdown=True, followlinks=False, onerror=onerror
    ):
        if errors:
            exc = errors[0]
            failed_path = Path(exc.filename or root_str)
            try:
                shown = failed_path.relative_to(run_root).as_posix()
            except ValueError:  # pragma: no cover - an error outside the root
                shown = str(failed_path)
            breaks.append((shown, "modified"))
            errors.clear()
        here = Path(dirpath)
        keep: list[str] = []
        for name in sorted(dirnames):
            child = here / name
            if here == run_root and is_nested_run(child):
                continue
            if child.is_symlink():
                breaks.append(
                    (child.relative_to(run_root).as_posix(), "symlink")
                )
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = here / name
            rel = full.relative_to(run_root).as_posix()
            if here == run_root and name == MANIFEST_FILENAME:
                continue
            if here == run_root and name.startswith(MANIFEST_TEMP_PREFIX):
                temporaries.append(rel)
                continue
            try:
                info = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISLNK(info.st_mode):
                breaks.append((rel, "symlink"))
                continue
            if not stat.S_ISREG(info.st_mode):
                breaks.append((rel, "modified"))
                continue
            sizes[rel] = info.st_size
    return sizes, breaks, temporaries


def _verify_nested(run_root: Path) -> list[dict[str, Any]]:
    nested: list[dict[str, Any]] = []
    try:
        children = sorted(
            (child for child in run_root.iterdir() if child.is_dir() and not child.is_symlink()),
            key=lambda child: child.name,
        )
    except OSError:  # pragma: no cover - an unreadable run root
        return nested
    for child in children:
        if not is_nested_run(child):
            continue
        report = verify_run(child, _depth=1)
        nested.append(
            {
                "run_id": child.name,
                "ok": report["ok"],
                "state": report["state"],
                "classification": report["classification"],
                "path": (
                    f"{child.name}/{report['path']}" if report["path"] else None
                ),
                "manifest_sha256": report["manifest_sha256"],
                "stage": report["stage"],
            }
        )
    return nested


def verify_run(
    path: str | os.PathLike[str],
    *,
    expect_manifest: Optional[str] = None,
    _depth: int = 0,
) -> dict[str, Any]:
    """Recompute every hash in a run and name the first break.

    States: ``intact`` (manifest present, valid and every file matches),
    ``unsealed`` (no manifest at all — a legacy run; never ``ok``), ``broken``
    (anything else, with a classification and the path of the first break).

    ``--expect-manifest`` compares the recorded anchor to the manifest's own
    SHA-256 *first*, so an artifact rewritten together with a regenerated
    manifest is ``replaced`` rather than merely intact.
    """
    run_root = Path(path).expanduser()
    report: dict[str, Any] = {
        "ok": False,
        "state": "unsealed",
        "classification": None,
        "path": None,
        "run_id": run_root.name,
        "run_dir": str(run_root),
        "manifest_sha256": None,
        "manifest_version": None,
        "format": None,
        "stage": None,
        "sealed_at": None,
        "created_at": None,
        "task_id": None,
        "hatchery_version": None,
        "file_count": 0,
        "total_bytes": 0,
        "hashed": 0,
        "expected_manifest": (expect_manifest or "").strip().lower() or None,
        "anchor": None,
        "nested_runs": [],
        "stale_temporaries": [],
        "error": None,
    }

    if not run_root.is_dir():
        report.update(state="broken", classification="missing", path=run_root.name,
                      error=f"{run_root} is not a directory")
        return report

    raw, problem = _read_manifest_file(run_root)
    if raw is None and problem is None:
        if report["expected_manifest"]:
            report.update(
                state="broken",
                classification="manifest-missing",
                path=MANIFEST_FILENAME,
                error="no manifest.json in the run directory; the recorded anchor "
                "cannot be confirmed",
            )
        else:
            report.update(
                state="unsealed",
                error="no manifest.json: this run was written before the manifest "
                "existed, or the manifest was deleted. It is not intact — it is "
                "unsealed. Run `hatchery results seal <run>` to make it verifiable.",
            )
        if _depth == 0:
            report["nested_runs"] = _verify_nested(run_root)
        return report
    if raw is None:
        report.update(
            state="broken",
            classification=problem or "manifest-invalid",
            path=MANIFEST_FILENAME,
            error="the manifest is not a regular file",
        )
        if _depth == 0:
            report["nested_runs"] = _verify_nested(run_root)
        return report

    digest = hashlib.sha256(raw).hexdigest()
    report["manifest_sha256"] = digest

    expected = report["expected_manifest"]
    if expected:
        report["anchor"] = {
            "expected": expected,
            "actual": digest,
            "match": expected == digest,
        }
        if expected != digest:
            report.update(
                state="broken",
                classification="replaced",
                path=MANIFEST_FILENAME,
                error=(
                    "the manifest does not match the recorded anchor: this run "
                    "directory is not the one that was delivered (an artifact and "
                    "its manifest may have been rewritten together)"
                ),
            )
            if _depth == 0:
                report["nested_runs"] = _verify_nested(run_root)
            return report

    try:
        document = _manifest_document(raw)
    except ManifestError as exc:
        report.update(
            state="broken",
            classification=exc.reason,
            path=MANIFEST_FILENAME,
            error=exc.message,
        )
        if _depth == 0:
            report["nested_runs"] = _verify_nested(run_root)
        return report

    report.update(
        manifest_version=document.get("manifest_version"),
        format=document.get("format"),
        stage=document.get("stage"),
        sealed_at=document.get("sealed_at"),
        created_at=document.get("created_at"),
        task_id=document.get("task_id"),
        hatchery_version=document.get("hatchery_version"),
        run_id=str(document.get("run_id") or run_root.name),
        file_count=int(document.get("file_count") or 0),
        total_bytes=int(document.get("total_bytes") or 0),
    )

    declared = {
        str(entry["path"]): entry for entry in document["files"]  # type: ignore[index]
    }
    sizes, breaks, temporaries = _scan_actual(run_root)
    report["stale_temporaries"] = temporaries

    for rel, size in sizes.items():
        if rel not in declared:
            breaks.append((rel, "extra"))
            continue
        entry = declared[rel]
        recorded_size = int(entry["size"])
        if size < recorded_size:
            breaks.append((rel, "truncated"))
            continue
        if size != recorded_size:
            breaks.append((rel, "modified"))
            continue
        try:
            actual_size, actual_digest = hash_file(run_root / rel)
        except ManifestError as exc:
            breaks.append((rel, exc.reason if exc.reason == "symlink" else "modified"))
            continue
        report["hashed"] += 1
        if actual_size != recorded_size or actual_digest != entry["sha256"]:
            breaks.append((rel, "modified"))

    for rel in declared:
        if rel not in sizes and not any(item[0] == rel for item in breaks):
            breaks.append((rel, "missing"))

    if breaks:
        # Deterministic: the same tree always names the same first break.
        first_path, classification = sorted(breaks, key=lambda item: (item[0], item[1]))[0]
        report.update(
            state="broken",
            classification=classification,
            path=first_path,
            error=f"{classification} at {first_path}",
        )
        if _depth == 0:
            report["nested_runs"] = _verify_nested(run_root)
        return report

    report.update(ok=True, state="intact", error=None)
    if _depth == 0:
        nested = _verify_nested(run_root)
        report["nested_runs"] = nested
        broken = [item for item in nested if item["state"] == "broken"]
        if broken:
            report.update(
                ok=False,
                state="broken",
                classification=broken[0]["classification"],
                path=broken[0]["path"],
                error=f"a nested replay run is {broken[0]['classification']}",
            )
    return report


# ---------------------------------------------------------------------------
# The operator's explicit seal
# ---------------------------------------------------------------------------


def ensure_sealed(
    path: str | os.PathLike[str],
    *,
    replace: bool = False,
) -> dict[str, Any]:
    """``hatchery results seal``: make a legacy run verifiable, idempotently.

    A valid existing manifest is returned unchanged (its hash printed) and
    nothing is rewritten. An existing manifest that does not match the tree is
    refused — rewriting it silently would hide exactly the tamper it exists to
    report — unless ``--replace`` is passed, in which case the old hash is
    returned so the caller can say that any anchor to it is void.
    """
    run_root = resolve_run_root(path)
    manifest_path = run_root / MANIFEST_FILENAME
    previous: Optional[str] = None
    if manifest_path.exists() or manifest_path.is_symlink():
        existing = verify_run(run_root)
        if existing["ok"]:
            return {
                "run_id": run_root.name,
                "run_dir": str(run_root),
                "manifest_path": str(manifest_path),
                "manifest_sha256": existing["manifest_sha256"],
                "stage": existing["stage"],
                "sealed_at": existing["sealed_at"],
                "file_count": existing["file_count"],
                "total_bytes": existing["total_bytes"],
                "written": False,
                "previous_manifest_sha256": None,
            }
        previous = existing["manifest_sha256"]
        if not replace:
            raise ManifestError(
                "manifest-mismatch",
                f"{manifest_path} does not match the run "
                f"({existing['classification']} at {existing['path']}). Refusing to "
                "rewrite it; pass --replace to re-seal anyway (any anchor to the old "
                "manifest becomes void).",
                str(manifest_path),
            )
    result = seal_run(run_root, stage="seal")
    result["written"] = True
    result["previous_manifest_sha256"] = previous
    return result


def manifest_state(path: str | os.PathLike[str]) -> dict[str, Any]:
    """The seal state of a run, as the compact record a replay carries (D5).

    ``state`` is ``verified`` (manifest present and every file matches),
    ``unsealed`` (no manifest — a legacy run) or ``broken`` (a classification
    and a path). The replay records the *source* run's manifest hash and state so
    the verdict says which bytes it replayed; the verdict itself stays about
    reproducibility, which is why the seal state is a separate field.
    """
    report = verify_run(path, _depth=1)
    state = {"intact": "verified", "unsealed": "unsealed", "broken": "broken"}[
        report["state"]
    ]
    return {
        "state": state,
        "manifest_sha256": report["manifest_sha256"],
        "stage": report["stage"],
        "sealed_at": report["sealed_at"],
        "classification": report["classification"],
        "path": report["path"],
        "message": report["error"] if state != "verified" else None,
    }


__all__ = [
    "ANALYSIS_REL",
    "CLASSIFICATIONS",
    "FORMAT",
    "MANIFEST_FILENAME",
    "MANIFEST_TEMP_PREFIX",
    "MANIFEST_VERSION",
    "MAX_BYTES",
    "MAX_FILES",
    "ManifestError",
    "STAGES",
    "build_manifest",
    "collect_files",
    "ensure_sealed",
    "hash_file",
    "hatchery_version",
    "is_nested_run",
    "manifest_state",
    "resolve_run_root",
    "safe_relative_path",
    "seal_run",
    "serialize",
    "verify_run",
    "write_manifest",
]
