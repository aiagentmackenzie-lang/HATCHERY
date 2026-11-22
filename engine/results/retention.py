"""Result-bundle retention, the growth guard and the prune record (D33).

D28 protected the *sample* at rest and D32 made the *access log* finite and
verifiable. A run directory — the artifact an analyst hands to a client — was
the last evidence store with no guarantees of its own: plaintext, unbounded, and
trusted because nobody had looked. This module makes it finite, and makes every
decision to delete explainable, without ever running on its own.

The rules, in the same shape D28 and D32 already use so an operator learns one
retention model:

* **Off by default.** With no policy there is no expiry; nothing in submit, the
  worker or the API calls this module, and there is no timer or background task.
* **Dry run unless ``--apply``.** The dry run prints exactly what ``--apply``
  will do, one decision per run with a reason.
* **A run is the unit.** A replay written inside a run directory
  (``results/<run>/replay-xxxx/``) is deleted with it; the record says how many
  nested runs went.
* **An anchor is always kept.** ``--keep-last`` defaults to 1 and is clamped to
  at least 1, so a policy can never delete every run. ``clamped`` says when the
  anchor, rather than the policy, decided.
* **Fail closed.** A run with no manifest, an invalid manifest or an unparseable
  ``analysis.json`` is never deleted: ``--apply`` refuses the whole plan and
  exits non-zero, exactly as D28 refuses when a queued job's sample cannot be
  identified. Seal the corpus first, then prune.
* **Rename, then remove.** The directory is renamed to ``<run>.deleting-<ts>``
  before it is removed, so a reader mid-replay fails cleanly instead of reading
  a half-deleted tree, and a crash leaves a stray the next prune completes.
* **Nothing deletes itself to save space.** The growth guard only warns.

Every prune appends one line to ``results/.prune-log.jsonl`` (``0600``,
append-only). It is an operator convenience, **not** tamper-evident: the audit
chain covers API actions, not local CLI maintenance, and this is the same
boundary D28 and D29 already have.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import re
import shutil
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from engine.results.manifest import (
    ANALYSIS_REL,
    MANIFEST_FILENAME,
    is_nested_run,
    verify_run,
)

logger = logging.getLogger(__name__)

RESULTS_LOCK_FILENAME = ".results.lock"
PRUNE_LOG_FILENAME = ".prune-log.jsonl"
DELETING_MARKER = ".deleting-"

RETENTION_DAYS_ENV = "HATCHERY_RESULTS_RETENTION_DAYS"
KEEP_LAST_ENV = "HATCHERY_RESULTS_KEEP_LAST"
WARN_RUNS_ENV = "HATCHERY_RESULTS_WARN_RUNS"
WARN_BYTES_ENV = "HATCHERY_RESULTS_WARN_BYTES"

DEFAULT_KEEP_LAST = 1
DEFAULT_WARN_RUNS = 2000
DEFAULT_WARN_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB

_DELETING_RE = re.compile(r"^(?P<run>.+)\.deleting-(?P<stamp>\d{8}T\d{6}Z)$")
_DURATION_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[smhdw]?)$")
_UNIT_SECONDS = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0, "w": 604800.0}


class ResultsLocked(RuntimeError):
    """Another maintenance operation holds ``results/.results.lock``."""

    def __init__(self) -> None:
        super().__init__("results-locked: another results operation is running")
        self.reason = "results-locked"


class RetentionError(RuntimeError):
    """A policy or a results root that cannot be honoured."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def parse_duration(value: Optional[str | float]) -> Optional[float]:
    """``30d``, ``12h``, ``90s``, ``2w`` or a plain number of seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return max(0.0, float(value))
    text = str(value).strip().lower()
    if not text:
        return None
    match = _DURATION_RE.match(text)
    if not match:
        raise RetentionError(
            "invalid-duration",
            f"{value!r} is not a duration (use seconds or s/m/h/d/w, e.g. 30d)",
        )
    return float(match.group("value")) * _UNIT_SECONDS[match.group("unit")]


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RetentionError(
            "invalid-policy", f"{name}={raw!r} is not an integer"
        ) from exc


def resolve_policy(
    *,
    older_than: Optional[str | float] = None,
    keep_last: Optional[int] = None,
) -> dict[str, Any]:
    """The retention policy for one invocation.

    Command arguments win over ``HATCHERY_RESULTS_RETENTION_DAYS`` /
    ``HATCHERY_RESULTS_KEEP_LAST``; both are the command's defaults only, never a
    background setting. ``keep_last`` is clamped to at least 1 and ``clamped``
    reports it.
    """
    older_source = "argument"
    if older_than is None:
        configured = os.environ.get(RETENTION_DAYS_ENV, "").strip()
        if configured:
            older_source = "env"
            try:
                older_than = float(configured) * _UNIT_SECONDS["d"]
            except ValueError as exc:
                raise RetentionError(
                    "invalid-policy",
                    f"{RETENTION_DAYS_ENV}={configured!r} is not a number of days",
                ) from exc
        else:
            older_source = "default"
    keep_source = "argument"
    if keep_last is None:
        if os.environ.get(KEEP_LAST_ENV, "").strip():
            keep_source = "env"
        else:
            keep_source = "default"
        keep_last = _env_int(KEEP_LAST_ENV, DEFAULT_KEEP_LAST)

    requested = int(keep_last)
    effective = max(1, requested)
    seconds = parse_duration(older_than)
    return {
        "older_than_seconds": seconds,
        "older_than": (
            None if seconds is None else _human_seconds(seconds)
        ),
        "keep_last": effective,
        "keep_last_requested": requested,
        "clamped_keep_last": requested < 1,
        "source": {"older_than": older_source, "keep_last": keep_source},
        "enabled": seconds is not None,
    }


def _human_seconds(seconds: float) -> str:
    for unit, size in (("w", 604800.0), ("d", 86400.0), ("h", 3600.0), ("m", 60.0)):
        if seconds >= size and seconds % size == 0:
            return f"{int(seconds // size)}{unit}"
    return f"{int(seconds)}s"


# ---------------------------------------------------------------------------
# Lock and prune log
# ---------------------------------------------------------------------------


@contextmanager
def results_lock(root: Path, *, wait_seconds: float = 0.0) -> Iterator[None]:
    """A non-blocking ``flock`` on ``results/.results.lock``.

    Two prunes serialise; the second reports ``results-locked`` instead of
    interleaving. A reader is not blocked — the rename-before-remove sequence is
    what protects it.
    """
    path = Path(root) / RESULTS_LOCK_FILENAME
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - non-POSIX
            yield
            return
        deadline = time.monotonic() + max(0.0, wait_seconds)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise ResultsLocked() from exc
                time.sleep(0.05)
        try:
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:  # pragma: no cover - unlock of a closing fd
                pass
    finally:
        os.close(fd)


def append_prune_log(root: Path, entry: dict[str, Any]) -> Path:
    """Append one JSON object per prune invocation to ``.prune-log.jsonl``."""
    path = Path(root) / PRUNE_LOG_FILENAME
    line = (
        json.dumps(entry, sort_keys=True, default=str, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        if stat.S_IMODE(os.lstat(path).st_mode) != 0o600:
            os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - a filesystem without chmod
        pass
    return path


def read_prune_log(root: Path, *, limit: int = 50) -> dict[str, Any]:
    path = Path(root) / PRUNE_LOG_FILENAME
    if not path.is_file():
        return {"path": str(path), "entries": 0, "last": None}
    entries = 0
    last: Optional[dict[str, Any]] = None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                entries += 1
                if entries > limit:
                    continue
                try:
                    last = json.loads(line)
                except ValueError:
                    continue
    except OSError:  # pragma: no cover - an unreadable prune log
        return {"path": str(path), "entries": 0, "last": None}
    return {"path": str(path), "entries": entries, "last": last}


# ---------------------------------------------------------------------------
# Scanning a results root
# ---------------------------------------------------------------------------


def _tree_bytes(path: Path) -> int:
    """Bytes in regular files under a directory, never following a symlink."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames[:] = [name for name in dirnames if not (Path(dirpath) / name).is_symlink()]
        for name in filenames:
            full = Path(dirpath) / name
            try:
                info = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


def _nested_runs(path: Path) -> int:
    try:
        return sum(
            1
            for child in path.iterdir()
            if child.is_dir() and not child.is_symlink() and is_nested_run(child)
        )
    except OSError:  # pragma: no cover - an unreadable run directory
        return 0


def _is_run(path: Path) -> bool:
    """A directory is a run if it holds a bundle, or a manifest.

    A directory with neither is not a run — a stray ``results/results`` or an
    operator's notes directory is ignored, not refused. A run that was
    interrupted before its bundle existed has no manifest and is not prunable;
    it is ignored for the same reason (and nothing deletes it).
    """
    return (
        (path / "bundle").is_dir()
        or (path / MANIFEST_FILENAME).is_file()
        or (path / ANALYSIS_REL).is_file()
    )


@dataclass
class RunRecord:
    """One run directory as the pruner sees it."""

    run_id: str
    path: Path
    bytes: int = 0
    files: int = 0
    nested_runs: int = 0
    nested_unsealed: int = 0
    sealed_at: Optional[str] = None
    sealed_epoch: Optional[float] = None
    stage: Optional[str] = None
    state: str = "unsealed"
    classification: Optional[str] = None
    break_path: Optional[str] = None
    message: Optional[str] = None
    task_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "path": str(self.path),
            "bytes": self.bytes,
            "files": self.files,
            "nested_runs": self.nested_runs,
            "nested_unsealed": self.nested_unsealed,
            "sealed_at": self.sealed_at,
            "stage": self.stage,
            "state": self.state,
            "classification": self.classification,
            "break_path": self.break_path,
            "message": self.message,
            "task_id": self.task_id,
        }


def read_run(path: Path, *, now: Optional[float] = None) -> RunRecord:
    """Describe one run: its size, its seal state and its age."""
    moment = time.time() if now is None else float(now)
    record = RunRecord(run_id=path.name, path=path)
    record.bytes = _tree_bytes(path)
    record.nested_runs = _nested_runs(path)
    record.files = sum(
        1
        for _dirpath, _dirnames, filenames in os.walk(path, followlinks=False)
        for _name in filenames
    )
    report = verify_run(path)
    record.state = report["state"]
    record.classification = report["classification"]
    record.break_path = report["path"]
    record.nested_unsealed = sum(
        1
        for nested in report.get("nested_runs") or []
        if nested.get("state") == "unsealed"
    )
    record.sealed_at = report["sealed_at"]
    record.stage = report["stage"]
    record.task_id = report["task_id"]
    if report["state"] == "broken":
        record.message = report.get("error")
    elif report["state"] == "unsealed":
        record.message = report.get("error")
    if report["state"] == "intact" and report["sealed_at"]:
        try:
            stamp = str(report["sealed_at"]).replace("Z", "+00:00")
            record.sealed_epoch = datetime.fromisoformat(stamp).timestamp()
        except ValueError:
            record.sealed_epoch = None
    if record.sealed_epoch is None:
        try:
            record.sealed_epoch = path.stat().st_mtime
        except OSError:
            record.sealed_epoch = moment
    return record


def scan_root(root: Path) -> dict[str, Any]:
    """Every run, stray deletion and ignored entry under a results root."""
    root = Path(root).expanduser()
    runs: list[RunRecord] = []
    strays: list[dict[str, Any]] = []
    ignored: list[str] = []
    if not root.is_dir():
        return {"root": root, "exists": False, "runs": runs, "strays": strays,
                "ignored": ignored}
    for entry in sorted(root.iterdir(), key=lambda item: item.name):
        if entry.is_symlink() or not entry.is_dir():
            if not entry.name.startswith("."):
                ignored.append(entry.name)
            continue
        if entry.name.startswith("."):
            continue
        if _DELETING_RE.match(entry.name) or DELETING_MARKER in entry.name:
            match = _DELETING_RE.match(entry.name)
            strays.append(
                {
                    "name": entry.name,
                    "run_id": match.group("run") if match else entry.name,
                    "path": str(entry),
                    "bytes": _tree_bytes(entry),
                    "reason": "deleting-in-progress",
                }
            )
            continue
        if not _is_run(entry):
            ignored.append(entry.name)
            continue
        runs.append(read_run(entry))
    return {
        "root": root,
        "exists": True,
        "runs": runs,
        "strays": strays,
        "ignored": ignored,
    }


def _describe_age(seconds: Optional[float]) -> Optional[float]:
    return None if seconds is None else round(seconds, 3)


def plan_prune(
    root: Path,
    *,
    policy: dict[str, Any],
    now: Optional[float] = None,
    scan: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Decide, per run, without touching anything on disk."""
    moment = time.time() if now is None else float(now)
    scanned = scan if scan is not None else scan_root(root)
    runs: list[RunRecord] = scanned["runs"]
    decisions: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []

    for run in runs:
        age = None if run.sealed_epoch is None else moment - run.sealed_epoch
        decision: dict[str, Any] = {
            **run.to_dict(),
            "age_seconds": _describe_age(age),
            "decision": "keep",
            "reason": "not-expired",
        }
        if run.state == "unsealed":
            decision.update(reason="no-manifest")
            refused.append(
                {
                    "run_id": run.run_id,
                    "reason": "no-manifest",
                    "message": "no manifest.json; the run cannot be verified, so it "
                    "is never deleted. Seal it first: hatchery results seal <run>",
                }
            )
        elif run.state == "broken" and run.classification == "nested-unsealed":
            # The parent's own files match, but it ships a nested unit with no
            # manifest. Deleting the run would delete evidence nobody could
            # verify, which D33 forbids in those words.
            decision.update(reason="nested-unsealed")
            refused.append(
                {
                    "run_id": run.run_id,
                    "reason": "nested-unsealed",
                    "classification": "nested-unsealed",
                    "path": run.break_path,
                    "message": run.message
                    or "a nested replay unit has no manifest; seal the corpus "
                    "with `hatchery results seal <results-root> --all` first",
                }
            )
        elif run.state != "intact":
            decision.update(reason="manifest-invalid")
            refused.append(
                {
                    "run_id": run.run_id,
                    "reason": "manifest-invalid",
                    "classification": run.classification,
                    "path": run.break_path,
                    "message": run.message
                    or "the manifest does not match the run directory",
                }
            )
        else:
            try:
                analysis = json.loads(
                    (run.path / ANALYSIS_REL).read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as exc:
                analysis = None
                decision.update(reason="unparseable")
                refused.append(
                    {
                        "run_id": run.run_id,
                        "reason": "unparseable",
                        "message": f"bundle/analysis.json could not be read: {exc}",
                    }
                )
            if analysis is not None:
                seconds = policy["older_than_seconds"]
                if seconds is None or age is None or age < seconds:
                    decision.update(reason="not-expired")
                else:
                    decision.update(decision="delete", reason="expired")
        decision["_epoch"] = run.sealed_epoch or 0.0
        decisions.append(decision)

    # Oldest first: a prune report reads like the timeline it is deciding about,
    # and the dry-run order is the apply order.
    decisions.sort(key=lambda item: (item["_epoch"], item["run_id"]))
    for item in decisions:
        item.pop("_epoch", None)

    # The anchor: the newest keep_last runs are never deleted, whatever the
    # policy says. A policy that would delete every run is clamped, not refused.
    ranked = sorted(
        (run for run in runs),
        key=lambda run: (run.sealed_epoch or 0.0, str(run.run_id)),
        reverse=True,
    )
    anchor_ids = {run.run_id for run in ranked[: policy["keep_last"]]}
    clamped = bool(policy.get("clamped_keep_last"))
    for decision in decisions:
        if decision["run_id"] in anchor_ids and decision["decision"] == "delete":
            decision.update(decision="keep", reason="kept-last")
            clamped = True
    if policy["older_than_seconds"] is not None and runs and not clamped:
        # Did the policy alone want to delete every run? Then the anchor, not the
        # policy, is what left something behind — say so instead of silently
        # keeping a run the operator asked to remove.
        if not any(item["reason"] == "not-expired" for item in decisions):
            clamped = True

    anchor_run = _anchor_view(ranked[0]) if ranked else None
    victims = [item for item in decisions if item["decision"] == "delete"]
    return {
        "results_root": str(scanned["root"]),
        "exists": bool(scanned["exists"]),
        "policy": policy,
        "runs": len(runs),
        "bytes": sum(run.bytes for run in runs),
        "nested_replay_runs": sum(run.nested_runs for run in runs),
        "strays": scanned["strays"],
        "ignored": scanned["ignored"],
        "decisions": decisions,
        "would_remove": [item["run_id"] for item in victims],
        "would_free_bytes": sum(int(item["bytes"]) for item in victims),
        "refused": refused,
        "blocked": bool(refused),
        "clamped": clamped,
        "anchor": anchor_run,
        "thresholds": growth_report(
            run_count=len(runs), total_bytes=sum(run.bytes for run in runs)
        ),
    }


def _anchor_view(run: RunRecord) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "sealed_at": run.sealed_at,
        "bytes": run.bytes,
    }


def _delete_now(path: Path, *, stamp: str) -> Path:
    """Rename the run out of the namespace, then remove it (D33)."""
    renamed = path.with_name(f"{path.name}{DELETING_MARKER}{stamp}")
    if renamed.exists():
        raise OSError(f"{renamed} already exists; refusing to overwrite a stray")
    os.rename(path, renamed)
    _fsync_dir(path.parent)
    shutil.rmtree(renamed)
    _fsync_dir(path.parent)
    return renamed


def _resume_stray(path: Path) -> None:
    shutil.rmtree(path)
    _fsync_dir(path.parent)


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _stamp(now: Optional[float] = None) -> str:
    moment = datetime.fromtimestamp(
        time.time() if now is None else float(now), tz=timezone.utc
    )
    return moment.strftime("%Y%m%dT%H%M%SZ")


def prune_runs(
    root: Path,
    *,
    policy: dict[str, Any],
    apply: bool = False,
    now: Optional[float] = None,
) -> dict[str, Any]:
    """Apply (or dry-run) the retention policy. Never runs on its own.

    ``--apply`` deletes exactly what ``plan_prune`` reported, after finishing any
    interrupted deletion and in rename-then-remove order. If any run cannot be
    verified, nothing is deleted and the report says why.
    """
    root = Path(root).expanduser()
    if not root.is_dir():
        raise RetentionError(
            "no-results-root", f"{root} is not a directory"
        )
    moment = time.time() if now is None else float(now)
    try:
        with results_lock(root):
            plan = plan_prune(root, policy=policy, now=moment)
            plan["applied"] = bool(apply)
            plan["removed"] = []
            plan["resumed_strays"] = []
            plan["bytes_freed"] = 0
            plan["errors"] = []
            plan["lock"] = {"path": str(root / RESULTS_LOCK_FILENAME), "acquired": True}
            if apply:
                for stray in plan["strays"]:
                    try:
                        _resume_stray(Path(stray["path"]))
                        plan["resumed_strays"].append(stray["name"])
                        plan["bytes_freed"] += int(stray.get("bytes") or 0)
                    except OSError as exc:
                        plan["errors"].append(
                            {"path": stray["path"], "message": str(exc)}
                        )
                if not plan["blocked"]:
                    stamp = _stamp(moment)
                    for decision in plan["decisions"]:
                        if decision["decision"] != "delete":
                            continue
                        try:
                            _delete_now(Path(decision["path"]), stamp=stamp)
                        except OSError as exc:
                            plan["errors"].append(
                                {
                                    "run_id": decision["run_id"],
                                    "path": decision["path"],
                                    "message": str(exc),
                                }
                            )
                            continue
                        plan["removed"].append(
                            {
                                "run_id": decision["run_id"],
                                "bytes": decision["bytes"],
                                "nested_runs": decision["nested_runs"],
                            }
                        )
                        plan["bytes_freed"] += int(decision["bytes"])
            plan["summary"] = {
                "delete": len(
                    [item for item in plan["decisions"] if item["decision"] == "delete"]
                ),
                "keep": len(
                    [item for item in plan["decisions"] if item["decision"] == "keep"]
                ),
                "would_delete": len(plan["would_remove"]),
                "removed": len(plan["removed"]),
                "refused": len(plan["refused"]),
                "errors": len(plan["errors"]),
                "bytes_freed": plan["bytes_freed"],
            }
            log_entry = {
                "at": datetime.fromtimestamp(moment, tz=timezone.utc).isoformat(),
                "applied": bool(apply),
                "policy": policy,
                "root": str(root),
                "runs": plan["runs"],
                "removed": plan["removed"],
                "bytes_freed": plan["bytes_freed"],
                "kept": [
                    {
                        "run_id": item["run_id"],
                        "reason": item["reason"],
                        "bytes": item["bytes"],
                    }
                    for item in plan["decisions"]
                    if item["decision"] == "keep"
                ],
                "refused": plan["refused"],
                "resumed_strays": plan["resumed_strays"],
                "clamped": plan["clamped"],
                "anchor": plan["anchor"],
            }
            log_path = append_prune_log(root, log_entry)
            plan["prune_log"] = {"path": str(log_path), "appended": True}
    except ResultsLocked as exc:
        return {
            "results_root": str(root),
            "applied": bool(apply),
            "policy": policy,
            "locked": True,
            "reason": "results-locked",
            "error": str(exc),
            "removed": [],
            "bytes_freed": 0,
            "summary": {"removed": 0, "bytes_freed": 0},
            "prune_log": {"path": str(root / PRUNE_LOG_FILENAME), "appended": False},
        }
    plan["locked"] = False
    return plan


# ---------------------------------------------------------------------------
# Growth guard and status
# ---------------------------------------------------------------------------


def growth_report(*, run_count: int, total_bytes: int) -> dict[str, Any]:
    """Warn about growth. Never delete anything to fix it."""
    warn_runs = _env_int(WARN_RUNS_ENV, DEFAULT_WARN_RUNS)
    warn_bytes = _env_int(WARN_BYTES_ENV, DEFAULT_WARN_BYTES)
    crossed: list[str] = []
    if warn_runs > 0 and run_count >= warn_runs:
        crossed.append("runs")
    if warn_bytes > 0 and total_bytes >= warn_bytes:
        crossed.append("bytes")
    return {
        "runs": run_count,
        "bytes": total_bytes,
        "warn_runs": warn_runs,
        "warn_bytes": warn_bytes,
        "crossed": crossed,
        "warned": bool(crossed),
        "enforced": False,
    }


def status_report(
    root: Path,
    *,
    policy: Optional[dict[str, Any]] = None,
    now: Optional[float] = None,
) -> dict[str, Any]:
    """Report what is there, what a prune would do, and whether it is growin.

    Read-only: no lock is taken and nothing is written, so an operator can check
    growth while a prune is running.
    """
    chosen = policy or resolve_policy()
    scanned = scan_root(root)
    plan = plan_prune(root, policy=chosen, now=now, scan=scanned)
    runs: list[RunRecord] = scanned["runs"]
    ordered = sorted(
        runs, key=lambda run: (run.sealed_epoch or 0.0, run.run_id)
    )
    oldest = ordered[0] if ordered else None
    newest = ordered[-1] if ordered else None
    return {
        **plan,
        "oldest": None if oldest is None else _anchor_view(oldest),
        "newest": None if newest is None else _anchor_view(newest),
        "unsealed_runs": sum(1 for run in runs if run.state == "unsealed"),
        "unsealed_nested": sum(run.nested_unsealed for run in runs),
        "prune_log": read_prune_log(Path(root).expanduser()),
        "growth": growth_report(
            run_count=len(runs), total_bytes=sum(run.bytes for run in runs)
        ),
    }


__all__ = [
    "DEFAULT_KEEP_LAST",
    "DEFAULT_WARN_BYTES",
    "DEFAULT_WARN_RUNS",
    "DELETING_MARKER",
    "KEEP_LAST_ENV",
    "PRUNE_LOG_FILENAME",
    "RETENTION_DAYS_ENV",
    "RESULTS_LOCK_FILENAME",
    "ResultsLocked",
    "RetentionError",
    "WARN_BYTES_ENV",
    "WARN_RUNS_ENV",
    "append_prune_log",
    "growth_report",
    "parse_duration",
    "plan_prune",
    "prune_runs",
    "read_prune_log",
    "read_run",
    "resolve_policy",
    "results_lock",
    "scan_root",
    "status_report",
]
