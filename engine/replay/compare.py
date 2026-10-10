"""Compare two runs, and compare the settings they were produced under (D26).

The comparison is deliberately split in two:

* :func:`compare_signals` diffs the deterministic and volatile signal sets. Its
  result decides the verdict.
* :func:`compare_settings` checks that the replay actually reproduced the
  original's environment (same isolation tier, same collector, detonation run or
  not, emulation run or not). A replay that silently ran weaker than the
  original is not a replay, and it says so.

Nothing here reads or writes files; both functions are pure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engine.replay.signals import DETERMINISTIC_KINDS, VOLATILE_KINDS
from engine.sandbox.isolation import TIER_PROFILES, IsolationTier


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _jsonable(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        return {str(key): value[key] for key in sorted(value)}
    return value


@dataclass(frozen=True)
class Comparison:
    """The result of diffing two bundles' signals."""

    identical: dict[str, bool]
    diff: dict[str, dict[str, Any]]
    deterministic_mismatches: list[str]
    dynamic_drift: list[str]

    @property
    def static_identical(self) -> bool:
        return not self.deterministic_mismatches

    def to_dict(self) -> dict[str, Any]:
        return {
            "identical": self.identical,
            "diff": self.diff,
            "deterministic_mismatches": self.deterministic_mismatches,
            "dynamic_drift": self.dynamic_drift,
        }


def _diff_value(kind: str, original: Any, replay: Any) -> dict[str, Any]:
    if kind == "set":
        only_original = sorted(set(original or set()) - set(replay or set()))
        only_replay = sorted(set(replay or set()) - set(original or set()))
        return {"only_original": only_original, "only_replay": only_replay}
    return {"original": _jsonable(original), "replay": _jsonable(replay)}


def compare_signals(original: Any, replay: Any) -> Comparison:
    """Diff a deterministic and volatile signal pair.

    ``original`` and ``replay`` are :class:`engine.replay.signals.Signals`
    instances. Set signals report what was added and what was lost.
    """
    identical: dict[str, bool] = {}
    diff: dict[str, dict[str, Any]] = {}
    deterministic_mismatches: list[str] = []
    dynamic_drift: list[str] = []

    for name, kind in DETERMINISTIC_KINDS.items():
        before = original.deterministic.get(name)
        after = replay.deterministic.get(name)
        same = before == after
        identical[name] = same
        if not same:
            deterministic_mismatches.append(name)
            diff[name] = _diff_value(kind, before, after)

    for name, kind in VOLATILE_KINDS.items():
        before = original.volatile.get(name)
        after = replay.volatile.get(name)
        same = before == after
        identical[name] = same
        if not same:
            dynamic_drift.append(name)
            diff[name] = _diff_value(kind, before, after)

    return Comparison(
        identical=identical,
        diff=diff,
        deterministic_mismatches=deterministic_mismatches,
        dynamic_drift=dynamic_drift,
    )


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReplaySettings:
    """The reproduction-relevant settings an original run recorded."""

    dynamic: bool
    emulation: bool
    isolation_tier: int
    collector: str
    sample_file_name: str = ""
    sample_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dynamic": self.dynamic,
            "emulation": self.emulation,
            "isolation_tier": self.isolation_tier,
            "isolation_tier_name": _tier_name(self.isolation_tier),
            "collector": self.collector,
            "sample_file_name": self.sample_file_name,
            "sample_sha256": self.sample_sha256,
        }


def _tier_name(tier: int) -> str:
    try:
        return TIER_PROFILES[IsolationTier(int(tier))].name
    except (ValueError, KeyError):
        return "unknown"


def settings_from_bundle(bundle: dict[str, Any]) -> ReplaySettings:
    """Read the settings the bundle recorded. Nothing here is guessed.

    ``sandbox`` being present means the original detonated. The tier is the one
    the original run actually had in force, not the one we wish it had.
    """
    bundle = bundle if isinstance(bundle, dict) else {}
    sample = bundle.get("sample")
    sample = sample if isinstance(sample, dict) else {}
    isolation = bundle.get("isolation")
    isolation = isolation if isinstance(isolation, dict) else {}
    sandbox = bundle.get("sandbox")
    sandbox = sandbox if isinstance(sandbox, dict) else None
    dynamic = sandbox is not None
    collector = ""
    if sandbox is not None:
        monitoring = sandbox.get("monitoring")
        if isinstance(monitoring, dict):
            collector = _text(monitoring.get("collector"))
    emulation = bundle.get("emulation")
    emulation = emulation if isinstance(emulation, dict) else {}
    try:
        tier = int(isolation.get("tier") or 0)
    except (TypeError, ValueError):
        tier = 0
    return ReplaySettings(
        dynamic=dynamic,
        emulation=bool(emulation.get("available")),
        isolation_tier=tier,
        collector=collector,
        sample_file_name=_text(sample.get("file_name")),
        sample_sha256=_text(sample.get("sha256")).lower(),
    )


@dataclass(frozen=True)
class SettingsComparison:
    """Whether the replay reproduced the original's environment."""

    original: ReplaySettings
    replay: ReplaySettings
    match: dict[str, bool]
    reproduced: bool
    mismatches: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original.to_dict(),
            "replay": self.replay.to_dict(),
            "match": self.match,
            "reproduced": self.reproduced,
            "mismatches": self.mismatches,
        }


def compare_settings(
    original: ReplaySettings,
    replay: ReplaySettings,
    *,
    sample_verified: bool,
    force_no_sandbox: bool = False,
) -> SettingsComparison:
    """Check that the replay reproduced the original's environment.

    A mismatch is a reason the replay is weaker than the original; it is never a
    silent pass. The verdict logic turns a mismatch into INCONCLUSIVE (unless a
    deterministic signal already failed much more loudly).
    """
    match: dict[str, bool] = {}
    mismatches: list[str] = []

    match["sample"] = sample_verified
    if not sample_verified:
        mismatches.append("the replayed sample's bytes were not verified against the bundle")

    match["isolation_tier"] = original.isolation_tier == replay.isolation_tier
    if not match["isolation_tier"]:
        mismatches.append(
            f"isolation tier differs: original tier {original.isolation_tier} "
            f"({_tier_name(original.isolation_tier)}) vs replay tier "
            f"{replay.isolation_tier} ({_tier_name(replay.isolation_tier)})"
        )

    # "dynamic" is a mismatch when the original detonated and the replay did
    # not. `replay.dynamic` already reflects what actually ran, so --no-sandbox
    # is caught here; force_no_sandbox only chooses which reason to report.
    match["dynamic"] = (not original.dynamic) or replay.dynamic
    if not match["dynamic"]:
        if force_no_sandbox:
            mismatches.append(
                "replay skipped detonation (--no-sandbox) but the original detonated; "
                "the dynamic behaviour was not reproduced"
            )
        else:
            mismatches.append(
                "the original detonated but the replay did not (no usable container runtime)"
            )

    match["emulation"] = (not original.emulation) or replay.emulation
    if not match["emulation"]:
        mismatches.append(
            "the original ran Windows PE emulation but the replay did not "
            "(the emulation image or runtime was unavailable)"
        )

    # The collector is only comparable when both runs observed behaviour.
    collector_expected = original.dynamic and replay.dynamic
    match["collector"] = (not collector_expected) or (original.collector == replay.collector)
    if not match["collector"]:
        mismatches.append(
            f"collector differs: original {original.collector or 'unknown'} vs "
            f"replay {replay.collector or 'unknown'}"
        )

    return SettingsComparison(
        original=original,
        replay=replay,
        match=match,
        reproduced=all(match.values()),
        mismatches=mismatches,
    )


__all__ = [
    "Comparison",
    "ReplaySettings",
    "SettingsComparison",
    "compare_settings",
    "compare_signals",
    "settings_from_bundle",
]
