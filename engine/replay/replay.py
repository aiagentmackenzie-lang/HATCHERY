"""Orchestration for ``hatchery replay`` (D26).

The replay locates the original sample, re-runs the existing ``hatchery submit``
pipeline with the settings the original bundle recorded, then compares. It does
not re-implement any analysis (one producer per data path, D4) and it does not
mutate the original bundle: the replay section lives in the **new** bundle plus
``replay.json``.

Fail-closed at every step:

* the sample is gone or its bytes changed → INCONCLUSIVE, with the reason;
* submit produced no bundle → INCONCLUSIVE, with the submit exit code;
* a deterministic static signal changed → ``static-mismatch`` (non-zero exit);
* the settings were not reproduced (weaker tier, no detonation, no emulation)
  → INCONCLUSIVE, with the exact mismatch;
* only dynamic signals drifted → ``dynamic-drift`` (reported, exit 0), because
  a sandbox is not bit-for-bit reproducible and a tool that failed on that would
  be useless.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from engine.bundle import ANALYSIS_FILENAME, load_bundle
from engine.replay.compare import (
    Comparison,
    SettingsComparison,
    compare_settings,
    compare_signals,
    settings_from_bundle,
)
from engine.replay.signals import extract_signals
from engine.store import SampleStore, SampleStoreError
from engine.store.staging import StagedPlaintext
from engine.store.store import resolve_ttl

logger = logging.getLogger(__name__)

REPLAY_FILENAME = "replay.json"

# A replay is only meaningful if the comparison policy is stated up front.
POLICY_LIMITATION = (
    "Replay compares deterministic static facts with equality and dynamic "
    "observations as drift: a sandbox cannot guarantee bit-for-bit event counts, "
    "durations or collected-IOC order, and this tool does not pretend it can."
)

SubmitRunner = Callable[[list[str], float], "tuple[int, str, str]"]
"""A submit runner: ``(command, timeout) -> (returncode, stdout, stderr)``."""


class ReplayError(RuntimeError):
    """The replay could not even be attempted (bad path, malformed bundle)."""


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Locating the original run and its sample
# ---------------------------------------------------------------------------


def resolve_run_dir(path: Path) -> Path:
    """Find the directory holding ``analysis.json``.

    Accepts either the bundle directory (``results/<task>/bundle``) or the task
    directory that contains it (``results/<task>``), because both are natural
    things to type.
    """
    path = Path(path)
    if (path / ANALYSIS_FILENAME).is_file():
        return path
    nested = path / "bundle"
    if (nested / ANALYSIS_FILENAME).is_file():
        return nested
    raise ReplayError(
        f"no analysis.json under {path} (looked in {path} and {nested}). "
        "Point replay at a HATCHERY run directory or its bundle/ directory."
    )


def default_output_dir(run_dir: Path) -> Path:
    """A fresh sibling directory for the replayed run.

    A unique suffix is used on purpose: a replay must never overwrite the run it
    is trying to reproduce.
    """
    run_dir = Path(run_dir)
    suffix = uuid.uuid4().hex[:8]
    if run_dir.name == "bundle":
        return run_dir.parent / f"replay-{suffix}"
    return run_dir / f"replay-{suffix}"


@dataclass(frozen=True)
class SampleResolution:
    """Where the sample came from, and whether its bytes were verified.

    ``plaintext`` is the decrypted sample for a store-backed resolution. It is
    deliberately excluded from :meth:`to_dict`: the replay section is written to
    disk and printed, and sample bytes must never be either.
    """

    requested_sha256: str
    sha256: str
    path: str
    resolution: str
    hash_verified: bool
    problem: str = ""
    reason: str = ""
    encryption: str = ""
    store_reference: str = ""
    plaintext: Optional[bytes] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_sha256": self.requested_sha256,
            "sha256": self.sha256,
            "path": self.path,
            "resolution": self.resolution,
            "hash_verified": self.hash_verified,
            "problem": self.problem,
            "reason": self.reason,
            "encryption": self.encryption,
            "store_reference": self.store_reference,
        }

    def limitations(self) -> list[str]:
        """What this resolution means for the strength of the replay."""
        lines: list[str] = []
        if self.encryption:
            lines.append(
                f"The sample was read from the sample store ({self.encryption}) and "
                "decrypted in memory; its sha256 was verified against the bundle "
                "before re-analysis."
            )
            if self.encryption == "plaintext-legacy":
                lines.append(
                    "The stored sample is still legacy plaintext on disk; run "
                    "`hatchery store migrate` to encrypt the store."
                )
            if self.plaintext is not None:
                lines.append(
                    "The path-based analysis pipeline was handed a single-use "
                    "staging file (0600, 0700 directory) containing the decrypted "
                    "sample for the duration of the submit subprocess; it is removed "
                    "when the replay ends. No plaintext is written to the store, the "
                    "index or the results tree."
                )
        if self.reason == "expired":
            lines.append(
                "The sample is past the configured retention TTL. A replay cannot "
                "be defended on an expired sample, so this replay is INCONCLUSIVE "
                "rather than a pass."
            )
        return lines


def _store_resolution(
    store: Any,
    expected: str,
    *,
    ttl: Optional[float],
    now: Optional[float],
) -> Optional[SampleResolution]:
    """Resolve a sample through the store, or ``None`` if it does not hold it.

    Once the store claims an address — a blob exists or the index has a row —
    the store is authoritative. A wrong key, a tampered envelope or an expired
    entry is then an INCONCLUSIVE replay with that precise reason; silently
    falling back to some other copy would hide exactly the integrity event a
    replay exists to surface.
    """
    if not expected or store is None:
        return None
    try:
        record = store.record(expected)
        present = record is not None or store.has(expected)
    except Exception as exc:  # a broken index must not look like a missing sample
        return SampleResolution(
            expected, "", "", "sample store", False,
            f"the sample store could not be queried: {exc}", reason="index-error",
        )
    if not present:
        return None

    try:
        ttl_seconds = resolve_ttl(ttl)
    except SampleStoreError as exc:
        return SampleResolution(
            expected, "", "", "sample store", False,
            f"the retention configuration is invalid: {exc.message}", reason=exc.reason,
        )
    moment = time.time() if now is None else float(now)
    if ttl_seconds > 0:
        anchor = record.anchor_epoch() if record is not None else 0.0
        if anchor and moment - anchor > ttl_seconds:
            return SampleResolution(
                expected, "", "", "sample store", False,
                f"the sample is {moment - anchor:.0f}s old, past the configured "
                f"retention TTL of {ttl_seconds:.0f}s; it is expired and a replay "
                "cannot rely on it",
                reason="expired",
                store_reference=expected,
            )
    try:
        stored = store.read(expected)
    except SampleStoreError as exc:
        return SampleResolution(
            expected, "", "", "sample store", False,
            f"the stored sample {expected} is unusable: {exc.reason}: {exc.message}",
            reason=exc.reason,
            store_reference=expected,
        )
    label = "sample store" if stored.encryption == "aes-256-gcm/v1" else "sample store (legacy plaintext)"
    return SampleResolution(
        expected,
        stored.sha256,
        str(store.blob_path(stored.sha256)),
        label,
        True,
        encryption=stored.encryption,
        store_reference=stored.sha256,
        plaintext=stored.data,
    )


def locate_sample(
    bundle: dict[str, Any],
    run_dir: Path,
    override: Optional[Path] = None,
    *,
    store: Any = None,
    ttl: Optional[float] = None,
    now: Optional[float] = None,
) -> SampleResolution:
    """Locate the original sample and verify it against the recorded hash.

    Order (D28): the **sample store** is authoritative when it holds the content
    address, then the recorded path, then a legacy ``samples/<sha256>.sample``
    directory. The store is checked first because it is the copy retention
    policy actually protects; the older locations remain for runs recorded before
    the store existed. A candidate whose bytes do not match the bundle is refused
    rather than replayed — comparing a different file would manufacture a false
    ``static-mismatch``.

    A store-backed resolution carries the decrypted bytes in memory; the caller
    stages them for the submit subprocess and never writes them into the store or
    the results tree.
    """
    sample = bundle.get("sample")
    sample = sample if isinstance(sample, dict) else {}
    expected = _text(sample.get("sha256")).lower()
    recorded = _text(sample.get("file_path"))

    if override is not None:
        candidate = Path(override)
        if not candidate.is_file():
            return SampleResolution(
                expected, "", str(candidate), "--sample override", False,
                f"--sample {candidate} does not exist", reason="not-found",
            )
        actual = _sha256(candidate)
        if expected and actual != expected:
            return SampleResolution(
                expected, actual, str(candidate.resolve()), "--sample override", False,
                f"--sample {candidate} has sha256 {actual}, but the bundle records "
                f"{expected}; refusing to replay different bytes",
                reason="hash-mismatch",
            )
        return SampleResolution(
            expected or actual, actual, str(candidate.resolve()), "--sample override", True,
        )

    resolved_store = _store_resolution(store, expected, ttl=ttl, now=now)
    if resolved_store is not None:
        return resolved_store

    # The store above is authoritative. The only other place a pre-D28 run may
    # legitimately point at is the path it recorded; ad-hoc ``samples/``
    # guessing is deliberately gone, because it could pick up an encrypted blob
    # from an unrelated directory and call it corrupt plaintext.
    last_problem = ""
    last_reason = ""
    if recorded and not recorded.startswith("store:"):
        candidate = Path(recorded)
        if candidate.is_file():
            actual = _sha256(candidate)
            if not expected or actual == expected:
                return SampleResolution(
                    expected or actual, actual, str(candidate.resolve()),
                    "recorded sample path", True,
                )
            last_problem = (
                f"the recorded sample path {candidate} has sha256 {actual}, but the "
                f"bundle records {expected}; refusing to replay different bytes"
            )
            last_reason = "hash-mismatch"

    problem = last_problem or (
        "the sample could not be located: the recorded path "
        f"{recorded or '(none)'} does not exist and no copy with sha256 "
        f"{expected or '(unknown)'} was found in the sample store. A replay is "
        "INCONCLUSIVE, not a pass."
    )
    return SampleResolution(
        expected, "", "", "not found", False, problem,
        reason=last_reason or "not-found",
    )


# ---------------------------------------------------------------------------
# Running submit
# ---------------------------------------------------------------------------


def build_submit_command(
    sample: Path,
    output_dir: Path,
    *,
    dynamic: bool,
    emulation: bool,
    allow_host_emulation: bool = False,
) -> list[str]:
    """Build the ``hatchery submit`` command that reproduces the original run.

    The existing pipeline is shelled out to, exactly as the MCP server does, so
    there is still one producer of analysis data (D4).
    """
    command = [
        sys.executable, "-m", "engine.cli", "submit", str(sample), "-o", str(output_dir),
    ]
    if not dynamic:
        command.append("--no-sandbox")
    if emulation:
        command.append("--emulate")
        if allow_host_emulation:
            command.append("--allow-host-emulation")
    return command


def _default_submit_runner(command: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"submit timed out after {timeout:.0f}s"
    except OSError as exc:  # the interpreter could not start
        return 127, "", f"could not start submit: {exc}"
    return completed.returncode, completed.stdout or "", completed.stderr or ""


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


def decide_verdict(
    comparison: Comparison,
    settings: SettingsComparison,
    unknown: tuple[str, ...],
) -> str:
    """The verdict precedence, in one place.

    A changed static fact is the loudest failure and wins. Otherwise a setting
    that could not be reproduced, or a deterministic signal that could not be
    re-established, is INCONCLUSIVE. Only then is dynamic drift considered.
    """
    if comparison.deterministic_mismatches:
        return "static-mismatch"
    if unknown or not settings.reproduced:
        return "inconclusive"
    if comparison.dynamic_drift:
        return "dynamic-drift"
    return "reproducible"


def _not_replayed(bundle: dict[str, Any]) -> list[str]:
    """Stages deliberately not reproduced.

    AI triage is model-generated and non-deterministic, so it is not a replay
    signal. It is recorded as not replayed rather than silently dropped.
    """
    items: list[str] = []
    if isinstance(bundle.get("triage"), dict):
        items.append("triage")
    return items


def _verdict_limitations(
    verdict: str,
    comparison: Comparison,
    settings: SettingsComparison,
    unknown: tuple[str, ...],
    not_replayed: list[str],
    resolution: SampleResolution,
) -> list[str]:
    lines: list[str] = []
    lines.append(
        f"Sample resolved via {resolution.resolution} ({resolution.path}); its "
        "sha256 was verified against the bundle before re-analysis."
    )
    if comparison.deterministic_mismatches:
        lines.append(
            "Deterministic signal(s) differ: "
            + ", ".join(comparison.deterministic_mismatches)
            + ". This replay does NOT reproduce the original static findings."
        )
    for mismatch in settings.mismatches:
        lines.append(
            "Settings not reproduced: " + mismatch + ". The replay is not "
            "equivalent to the original."
        )
    if unknown:
        lines.append(
            "Deterministic signal(s) could not be re-established from the bundle: "
            + ", ".join(unknown)
            + ". The bundle predates the stage that produces them, so the replay "
            "is INCONCLUSIVE rather than a silent pass."
        )
    if comparison.dynamic_drift:
        lines.append(
            "Dynamic drift (reported, not failed): "
            + ", ".join(comparison.dynamic_drift)
            + ". Sandboxes are not deterministic; this is expected."
        )
    if not_replayed:
        lines.append(
            "Not replayed: " + ", ".join(not_replayed)
            + ". Triage is model-generated and not deterministic; it is not a "
            "replay signal."
        )
    if verdict == "reproducible":
        lines.append(
            "Every deterministic static signal is identical and the run's "
            "settings were reproduced."
        )
    return lines


# ---------------------------------------------------------------------------
# Section assembly and persistence
# ---------------------------------------------------------------------------


def _base_section(
    original: dict[str, Any],
    original_run_dir: Path,
    replay_bundle_dir: Path,
    resolution: SampleResolution,
) -> dict[str, Any]:
    return {
        "original_task_id": _text(original.get("task_id")),
        "generated_at": _now(),
        "original_run_dir": str(original_run_dir),
        "replay_run_dir": str(replay_bundle_dir),
        "sample": resolution.to_dict(),
    }


def write_replay(directory: Path, section: dict[str, Any]) -> Path:
    """Write ``replay.json`` into ``directory``. Returns the path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / REPLAY_FILENAME
    path.write_text(json.dumps(section, indent=2, default=str), encoding="utf-8")
    return path


def attach_replay(run_dir: Path, section: dict[str, Any]) -> Path:
    """Attach the replay section to the replayed bundle, in place.

    The bundle is the single source of truth, so the replay patch lands in
    ``analysis.json`` (and its summary counters) as well as ``replay.json``,
    following the same pattern as triage (D22). The original bundle is never
    touched.
    """
    path = run_dir / ANALYSIS_FILENAME
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        data["replay"] = section
        summary = data.get("summary")
        if isinstance(summary, dict):
            summary.update(
                {
                    "replay_verdict": section.get("verdict"),
                    "replay_original_task_id": section.get("original_task_id"),
                    "replay_static_identical": not section.get("deterministic_mismatches"),
                    "replay_dynamic_drift": len(section.get("dynamic_drift") or []),
                }
            )
        limits = data.get("limitations")
        if isinstance(limits, list):
            for line in section.get("limitations") or []:
                if line not in limits:
                    limits.append(line)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return write_replay(run_dir, section)


# ---------------------------------------------------------------------------
# The replay itself
# ---------------------------------------------------------------------------


@dataclass
class ReplayResult:
    """A completed replay attempt (successful or inconclusive)."""

    section: dict[str, Any]
    output_dir: Path

    @property
    def verdict(self) -> str:
        return str(self.section.get("verdict") or "inconclusive")

    @property
    def exit_code(self) -> int:
        """0 for reproducible/dynamic-drift; 2 for static-mismatch; 1 otherwise."""
        return {"reproducible": 0, "dynamic-drift": 0, "static-mismatch": 2}.get(
            self.verdict, 1
        )


def _execute_replay(
    *,
    original: dict[str, Any],
    resolved: Path,
    out: Path,
    replay_bundle_dir: Path,
    original_settings: Any,
    original_signals: Any,
    resolution: SampleResolution,
    limitations: list[str],
    sample_path: Optional[Path],
    force_no_sandbox: bool,
    allow_host_emulation: bool,
    submit_runner: Optional[SubmitRunner],
    submit_timeout: float,
) -> ReplayResult:
    """Submit, compare and persist once the sample has been resolved.

    Split out so :func:`run_replay` can own the staging file's lifetime in a
    single ``try/finally``.
    """
    if sample_path is None:
        limitations.append(resolution.problem)
        section = _base_section(original, resolved, replay_bundle_dir, resolution)
        section.update(
            {
                "replay_task_id": None,
                "verdict": "inconclusive",
                "settings": {
                    "original": original_settings.to_dict(),
                    "replay": None,
                    "match": {},
                    "reproduced": False,
                    "mismatches": ["the sample was not available"],
                },
                "identical": {},
                "diff": {},
                "deterministic_mismatches": [],
                "dynamic_drift": [],
                "unknown": list(original_signals.unknown),
                "not_replayed": _not_replayed(original),
                "limitations": limitations,
            }
        )
        write_replay(out, section)
        logger.warning("Replay inconclusive for %s: %s", resolved, resolution.problem)
        return ReplayResult(section=section, output_dir=out)

    dynamic = original_settings.dynamic and not force_no_sandbox
    command = build_submit_command(
        sample_path,
        out,
        dynamic=dynamic,
        emulation=original_settings.emulation,
        allow_host_emulation=allow_host_emulation,
    )
    runner = submit_runner or _default_submit_runner
    returncode, stdout, stderr = runner(command, submit_timeout)

    if not (replay_bundle_dir / ANALYSIS_FILENAME).is_file():
        tail = [line for line in (stderr or stdout or "").strip().splitlines() if line.strip()]
        tail_text = " | ".join(tail[-3:]) if tail else "no output"
        limitations.append(
            f"the replay did not produce a bundle (submit exit {returncode}): {tail_text}"
        )
        section = _base_section(original, resolved, replay_bundle_dir, resolution)
        section.update(
            {
                "replay_task_id": None,
                "verdict": "inconclusive",
                "settings": {
                    "original": original_settings.to_dict(),
                    "replay": None,
                    "match": {},
                    "reproduced": False,
                    "mismatches": ["the replay analysis did not complete"],
                },
                "identical": {},
                "diff": {},
                "deterministic_mismatches": [],
                "dynamic_drift": [],
                "unknown": list(original_signals.unknown),
                "not_replayed": _not_replayed(original),
                "limitations": limitations,
            }
        )
        write_replay(out, section)
        logger.warning("Replay inconclusive for %s: submit exit %s", resolved, returncode)
        return ReplayResult(section=section, output_dir=out)

    try:
        replayed = load_bundle(replay_bundle_dir)
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        raise ReplayError(
            f"replayed bundle at {replay_bundle_dir / ANALYSIS_FILENAME} is unreadable: {exc}"
        ) from exc

    replay_settings = settings_from_bundle(replayed)
    replay_signals = extract_signals(replayed)
    comparison = compare_signals(original_signals, replay_signals)
    settings_comparison = compare_settings(
        original_settings,
        replay_settings,
        sample_verified=resolution.hash_verified,
        force_no_sandbox=force_no_sandbox,
    )
    unknown = tuple(sorted(set(original_signals.unknown) | set(replay_signals.unknown)))
    not_replayed = _not_replayed(original)
    verdict = decide_verdict(comparison, settings_comparison, unknown)
    limitations.extend(
        _verdict_limitations(
            verdict, comparison, settings_comparison, unknown, not_replayed, resolution
        )
    )

    section = _base_section(original, resolved, replay_bundle_dir, resolution)
    section.update(
        {
            "replay_task_id": _text(replayed.get("task_id")),
            "verdict": verdict,
            "settings": settings_comparison.to_dict(),
            "identical": comparison.identical,
            "diff": comparison.diff,
            "deterministic_mismatches": comparison.deterministic_mismatches,
            "dynamic_drift": comparison.dynamic_drift,
            "unknown": list(unknown),
            "not_replayed": not_replayed,
            "limitations": limitations,
        }
    )
    attach_replay(replay_bundle_dir, section)
    logger.info(
        "Replay %s for %s (static mismatches=%d, dynamic drift=%d)",
        verdict, resolved, len(comparison.deterministic_mismatches),
        len(comparison.dynamic_drift),
    )
    return ReplayResult(section=section, output_dir=out)


def run_replay(
    run_dir: Path,
    *,
    output_dir: Optional[Path] = None,
    force_no_sandbox: bool = False,
    allow_host_emulation: bool = False,
    sample_override: Optional[Path] = None,
    submit_runner: Optional[SubmitRunner] = None,
    submit_timeout: float = 1800.0,
    store: Any = None,
    ttl: Optional[float] = None,
    now: Optional[float] = None,
) -> ReplayResult:
    """Re-analyse a run and return the reproducibility verdict.

    Never raises for a failed *analysis* — a failure is an INCONCLUSIVE verdict
    with a reason. Raises :class:`ReplayError` only when the replay could not be
    attempted at all (bad path, malformed bundle).
    """
    resolved = resolve_run_dir(Path(run_dir))
    try:
        original = load_bundle(resolved)
    except json.JSONDecodeError as exc:
        raise ReplayError(
            f"malformed bundle at {resolved / ANALYSIS_FILENAME}: {exc}"
        ) from exc
    except FileNotFoundError as exc:
        raise ReplayError(str(exc)) from exc
    if not isinstance(original, dict):
        raise ReplayError(f"bundle at {resolved / ANALYSIS_FILENAME} is not a JSON object")

    original_settings = settings_from_bundle(original)
    original_signals = extract_signals(original)

    out = Path(output_dir) if output_dir else default_output_dir(resolved)
    out.mkdir(parents=True, exist_ok=True)
    replay_bundle_dir = out / "bundle"

    owned_store = store is None
    sample_store = store if store is not None else SampleStore(create=False)
    staged: Optional[StagedPlaintext] = None
    try:
        resolution = locate_sample(
            original, resolved, sample_override, store=sample_store, ttl=ttl, now=now
        )
        limitations = [POLICY_LIMITATION]
        limitations.extend(resolution.limitations())
        sample_path: Optional[Path] = None
        if resolution.hash_verified:
            if resolution.plaintext is not None:
                filename = Path(resolution.path).name or "sample"
                staged = StagedPlaintext(resolution.plaintext, filename)
                sample_path = staged.path
            else:
                sample_path = Path(resolution.path)
        return _execute_replay(
            original=original,
            resolved=resolved,
            out=out,
            replay_bundle_dir=replay_bundle_dir,
            original_settings=original_settings,
            original_signals=original_signals,
            resolution=resolution,
            limitations=limitations,
            sample_path=sample_path,
            force_no_sandbox=force_no_sandbox,
            allow_host_emulation=allow_host_emulation,
            submit_runner=submit_runner,
            submit_timeout=submit_timeout,
        )
    finally:
        if staged is not None:
            staged.close()
        if owned_store:
            sample_store.close()


__all__ = [
    "POLICY_LIMITATION",
    "REPLAY_FILENAME",
    "ReplayError",
    "ReplayResult",
    "SampleResolution",
    "SubmitRunner",
    "attach_replay",
    "build_submit_command",
    "decide_verdict",
    "default_output_dir",
    "locate_sample",
    "resolve_run_dir",
    "run_replay",
    "settings_from_bundle",
    "write_replay",
]
