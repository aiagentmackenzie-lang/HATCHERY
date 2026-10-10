"""The comparison and the verdict precedence."""

from __future__ import annotations

from _replay_builder import bundle_with, dynamic_bundle_with

from engine.replay.compare import compare_settings, compare_signals, settings_from_bundle
from engine.replay.replay import decide_verdict
from engine.replay.signals import extract_signals


def _compare(original: dict, replay: dict):
    return compare_signals(extract_signals(original), extract_signals(replay))


def test_identical_bundles_have_no_mismatch_and_no_drift() -> None:
    comparison = _compare(bundle_with(), bundle_with())
    assert comparison.deterministic_mismatches == []
    assert comparison.dynamic_drift == []
    assert all(comparison.identical.values())


def test_static_mismatch_reports_what_was_added_and_lost() -> None:
    original = bundle_with()
    replayed = bundle_with(
        static={
            "yara": {"matches": [{"rule": "HATCHERY_EICAR_TestFile"}, {"rule": "packed_upx"}]}
        }
    )
    comparison = _compare(original, replayed)
    assert comparison.deterministic_mismatches == ["yara_rules"]
    detail = comparison.diff["yara_rules"]
    assert detail["only_original"] == ["suspicious_base64"]
    assert detail["only_replay"] == ["packed_upx"]


def test_capa_capability_change_is_a_static_mismatch() -> None:
    original = bundle_with()
    replayed = bundle_with(
        static={"capa": {"capabilities": [{"name": "create process"}]}}
    )
    comparison = _compare(original, replayed)
    assert "capa_capabilities" in comparison.deterministic_mismatches


def test_technique_and_ioc_changes_are_static_mismatches() -> None:
    original = bundle_with()
    replayed = bundle_with(
        mitre={"techniques": [{"technique_id": "T1059.001"}, {"technique_id": "T1105"}]}
    )
    comparison = _compare(original, replayed)
    assert "attack_techniques" in comparison.deterministic_mismatches


def test_dynamic_only_drift_does_not_touch_deterministic_signals() -> None:
    original = dynamic_bundle_with()
    replayed = dynamic_bundle_with(
        sandbox={"status": "completed", "duration_seconds": 30.0,
                 "monitoring": {"collector": "strace-ptrace"}},
        summary={
            "events_total": 140,
            "events_by_category": {"process": 12, "file": 70, "network": 58},
            "events_by_severity": {"info": 100, "high": 40},
        },
    )
    comparison = _compare(original, replayed)
    assert comparison.deterministic_mismatches == []
    assert "events_total" in comparison.dynamic_drift
    assert "events_by_category" in comparison.dynamic_drift
    assert "sandbox_duration_seconds" in comparison.dynamic_drift


def test_verdict_precedence_static_mismatch_beats_unknown_and_settings() -> None:
    original = dynamic_bundle_with()
    replayed = dynamic_bundle_with(
        static={"capa": {"capabilities": []}},
        isolation={"tier": 0},
        sandbox=None,
    )
    comparison = compare_signals(extract_signals(original), extract_signals(replayed))
    settings = compare_settings(
        settings_from_bundle(original),
        settings_from_bundle(replayed),
        sample_verified=True,
        force_no_sandbox=True,
    )
    assert decide_verdict(comparison, settings, ()) == "static-mismatch"


def test_verdict_is_inconclusive_when_a_setting_was_not_reproduced() -> None:
    original = dynamic_bundle_with()
    replayed = dynamic_bundle_with(sandbox=None, isolation={"tier": 0})
    comparison = compare_signals(extract_signals(original), extract_signals(replayed))
    settings = compare_settings(
        settings_from_bundle(original),
        settings_from_bundle(replayed),
        sample_verified=True,
        force_no_sandbox=True,
    )
    assert not settings.reproduced
    assert any("skipped detonation" in reason for reason in settings.mismatches)
    assert decide_verdict(comparison, settings, ()) == "inconclusive"


def test_verdict_is_inconclusive_for_unknown_signals() -> None:
    original = bundle_with()
    replayed = bundle_with()
    comparison = compare_signals(extract_signals(original), extract_signals(replayed))
    settings = compare_settings(
        settings_from_bundle(original),
        settings_from_bundle(replayed),
        sample_verified=True,
    )
    assert decide_verdict(comparison, settings, ("delivery_format",)) == "inconclusive"


def test_verdict_is_dynamic_drift_when_only_volatile_signals_change() -> None:
    original = dynamic_bundle_with()
    replayed = dynamic_bundle_with(
        summary={"events_total": 200},
    )
    comparison = compare_signals(extract_signals(original), extract_signals(replayed))
    settings = compare_settings(
        settings_from_bundle(original),
        settings_from_bundle(replayed),
        sample_verified=True,
    )
    assert settings.reproduced
    assert decide_verdict(comparison, settings, ()) == "dynamic-drift"


def test_verdict_is_reproducible_when_everything_matches() -> None:
    original = dynamic_bundle_with()
    replayed = dynamic_bundle_with()
    comparison = compare_signals(extract_signals(original), extract_signals(replayed))
    settings = compare_settings(
        settings_from_bundle(original),
        settings_from_bundle(replayed),
        sample_verified=True,
    )
    assert decide_verdict(comparison, settings, ()) == "reproducible"


def test_tier_mismatch_is_reported() -> None:
    original = dynamic_bundle_with(isolation={"tier": 2},
                                   sandbox={"status": "completed",
                                            "monitoring": {"collector": "gvisor-sentry-strace"}})
    replayed = dynamic_bundle_with(isolation={"tier": 1},
                                   sandbox={"status": "completed",
                                            "monitoring": {"collector": "strace-ptrace"}})
    settings = compare_settings(
        settings_from_bundle(original),
        settings_from_bundle(replayed),
        sample_verified=True,
    )
    assert not settings.match["isolation_tier"]
    assert not settings.match["collector"]
    assert any("isolation tier differs" in reason for reason in settings.mismatches)


def test_emulation_not_reproduced_is_reported() -> None:
    original = bundle_with(emulation={"available": True, "status": "completed"})
    replayed = bundle_with(emulation={"available": False, "status": "unavailable"})
    settings = compare_settings(
        settings_from_bundle(original),
        settings_from_bundle(replayed),
        sample_verified=True,
    )
    assert not settings.match["emulation"]
    assert any("emulation" in reason for reason in settings.mismatches)
