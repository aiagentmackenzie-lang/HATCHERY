"""Bundle integration: triage reaches the summary, limitations and the API file."""

from __future__ import annotations

import json
from pathlib import Path

from engine.bundle import (
    AnalysisBundle,
    ANALYSIS_FILENAME,
    TRIAGE_FILENAME,
    attach_triage,
    compute_limitations,
    load_bundle,
    write_bundle,
)


def _triage(**overrides: object) -> dict:
    section = {
        "available": True,
        "status": "completed",
        "verdict": "suspicious",
        "confidence": 55,
        "summary": "Cron persistence.",
        "findings": [{"claim": "persistence", "grounding": ["event:1"]}],
        "findings_dropped": 0,
        "techniques": ["T1053.003"],
        "model": "mistral:7b",
        "prompt_version": "1.0",
        "contract_hash": "d" * 64,
        "evidence_ids": 12,
        "evidence_truncated": False,
        "inconclusive": False,
        "allowed_remote": False,
        "allowed_cloud_model": False,
        "limitations": [],
    }
    section.update(overrides)
    return section


def test_limitations_state_that_triage_is_advisory() -> None:
    limits = compute_limitations(None, None, None, [], triage=_triage())
    joined = " ".join(limits)
    assert "advisory" in joined
    assert "mistral:7b" in joined
    assert "not ground truth" in joined


def test_limitations_record_a_remote_triage_loudly() -> None:
    limits = compute_limitations(
        None, None, None, [], triage=_triage(allowed_cloud_model=True)
    )
    assert any("left this machine" in item for item in limits)


def test_limitations_report_dropped_findings_and_unvalidated_techniques() -> None:
    limits = compute_limitations(
        None, None, None, [], triage=_triage(findings_dropped=3, techniques=["T1053.003"])
    )
    joined = " ".join(limits)
    assert "dropped 3 finding(s)" in joined
    assert "unvalidated" in joined


def test_limitations_report_a_failed_triage_as_a_failure() -> None:
    limits = compute_limitations(
        None, None, None, [], triage={"available": False, "status": "timeout",
                                      "reason": "the model timed out"}
    )
    assert any("did not produce a verdict" in item for item in limits)


def test_summary_carries_the_triage_counters() -> None:
    bundle = AnalysisBundle(task_id="t", triage=_triage(), events=[{"category": "file", "severity": "high"}])
    summary = bundle.summary()
    assert summary["triage_available"] is True
    assert summary["triage_verdict"] == "suspicious"
    assert summary["triage_model"] == "mistral:7b"
    assert summary["triage_findings"] == 1
    assert summary["triage_inconclusive"] is False


def test_bundle_round_trips_the_triage_section(tmp_path: Path) -> None:
    bundle = AnalysisBundle(task_id="t", triage=_triage())
    analysis_path, _ = write_bundle(tmp_path, bundle)
    data = json.loads(analysis_path.read_text())
    assert data["triage"]["verdict"] == "suspicious"
    assert data["summary"]["triage_techniques"] == 1


def test_attach_triage_patches_the_bundle_and_writes_the_side_file(tmp_path: Path) -> None:
    write_bundle(tmp_path, AnalysisBundle(task_id="t", limitations=["base limit"]))
    attach_triage(tmp_path, _triage())
    data = json.loads((tmp_path / ANALYSIS_FILENAME).read_text())
    assert data["triage"]["available"] is True
    assert data["summary"]["triage_verdict"] == "suspicious"
    assert (tmp_path / TRIAGE_FILENAME).exists()
    assert "base limit" in data["limitations"]


def test_attach_triage_fails_clearly_without_a_bundle(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        attach_triage(tmp_path, _triage())


def test_load_bundle_round_trips(tmp_path: Path) -> None:
    write_bundle(tmp_path, AnalysisBundle(task_id="abc"))
    assert load_bundle(tmp_path)["task_id"] == "abc"
