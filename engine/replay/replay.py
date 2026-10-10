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
    """Where the sample came from, and whether its bytes were verified."""

    requested_sha256: str
    sha256: str
    path: str
    resolution: str
    hash_verified: bool
    problem: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_sha256": self.requested_sha256,
            "sha256": self.sha256,
            "path": self.path,
            "resolution": self.resolution,
            "hash_verified": self.hash_verified,
            "problem": self.problem,
        }


def locate_sample(
    bundle: dict[str, Any],
    run_dir: Path,
    override: Optional[Path] = None,
) -> SampleResolution:
    """Locate the original sample and verify it against the recorded hash.

    The recorded path is tried first, then the content-addressed sample store the
    uploader writes (``samples/<sha256>.sample``). A candidate whose bytes do not
    match the bundle is refused rather than replayed — comparing a different file
    would produce a false ``static-mismatch``.
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
                f"--sample {candidate} does not exist",
            )
        actual = _sha256(candidate)
        if expected and actual != expected:
            return SampleResolution(
                expected, actual, str(candidate.resolve()), "--sample override", False,
                f"--sample {candidate} has sha256 {actual}, but the bundle records "
                f"{expected}; refusing to replay different bytes",
            )
        return SampleResolution(
            expected or actual, actual, str(candidate.resolve()), "--sample override", True,
        )

    candidates: list[tuple[Path, str]] = []
    if recorded:
        candidates.append((Path(recorded), "recorded sample path"))
    if expected:
        store_name = f"{expected}.sample"
        seen_dirs: set[str] = set()
        for base in (Path("samples"), run_dir.parent / "samples", run_dir.parent.parent / "samples"):
            key = str(base.resolve()) if base.exists() else str(base)
            if key in seen_dirs:
                continue
            seen_dirs.add(key)
            candidates.append((base / store_name, "stored sample store"))

    last_problem = ""
    seen_paths: set[str] = set()
    for candidate, source in candidates:
        key = str(candidate)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        if not candidate.is_file():
            continue
        actual = _sha256(candidate)
        if expected and actual != expected:
            last_problem = (
                f"a candidate sample at {candidate} has sha256 {actual}, but the "
                f"bundle records {expected}; refusing to replay different bytes"
            )
            continue
        return SampleResolution(
            expected, actual, str(candidate.resolve()), source, True,
        )

    problem = last_problem or (
        "the sample could not be located: the recorded path "
        f"{recorded or '(none)'} does not exist and no copy with sha256 "
        f"{expected or '(unknown)'} was found in the sample store. A replay is "
        "INCONCLUSIVE, not a pass."
    )
    return SampleResolution(expected, "", "", "not found", False, problem)


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


def run_replay(
    run_dir: Path,
    *,
    output_dir: Optional[Path] = None,
    force_no_sandbox: bool = False,
    allow_host_emulation: bool = False,
    sample_override: Optional[Path] = None,
    submit_runner: Optional[SubmitRunner] = None,
    submit_timeout: float = 1800.0,
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

    resolution = locate_sample(original, resolved, sample_override)
    limitations = [POLICY_LIMITATION]

    if not resolution.hash_verified:
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
        Path(resolution.path),
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
