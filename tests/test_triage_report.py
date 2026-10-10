"""The report must carry the triage section, clearly labelled advisory."""

from __future__ import annotations

import json
from pathlib import Path

from engine.export.report import ReportGenerator


def _triage(**overrides: object) -> dict:
    section = {
        "available": True,
        "status": "completed",
        "verdict": "suspicious",
        "confidence": 55,
        "summary": "Cron persistence plus an outbound URL.",
        "findings": [
            {"claim": "cron persistence", "grounding": ["event:1"],
             "technique_ids": ["T1053.003"]},
            {"claim": "outbound URL", "grounding": ["ioc:http://1.2.3.4/gate"]},
        ],
        "findings_dropped": 2,
        "dropped": [{"claim": "invented", "reason": "no citation"}],
        "not_established": ["payload purpose"],
        "recommended_actions": ["block the URL"],
        "techniques": ["T1053.003"],
        "model": "mistral:7b",
        "prompt_version": "1.0",
        "contract_hash": "d" * 64,
        "evidence_ids": 12,
        "evidence_truncated": False,
        "inconclusive": False,
        "allowed_remote": False,
        "allowed_cloud_model": False,
    }
    section.update(overrides)
    return section


def test_markdown_render_includes_verdict_and_citations() -> None:
    md = ReportGenerator().generate_markdown(
        "sample.bin", {"sha256": "a" * 64}, triage=_triage()
    )
    assert "## AI Triage (advisory, local model)" in md
    assert "`suspicious`" in md
    assert "`event:1`" in md
    assert "outbound URL" in md
    assert "2 finding(s) were discarded" in md
    assert "payload purpose" in md
    assert "model-suggested" in md


def test_markdown_render_flags_a_remote_model() -> None:
    md = ReportGenerator().generate_markdown(
        "sample.bin", {}, triage=_triage(allowed_remote=True)
    )
    assert "Remote model permitted" in md


def test_markdown_render_states_a_failed_triage() -> None:
    md = ReportGenerator().generate_markdown(
        "sample.bin", {},
        triage={"available": False, "status": "timeout", "reason": "the model timed out"},
    )
    assert "not produced" in md
    assert "the model timed out" in md


def test_json_report_carries_the_triage_section() -> None:
    payload = json.loads(
        ReportGenerator().generate_json("sample.bin", {}, triage=_triage())
    )
    assert payload["triage"]["verdict"] == "suspicious"


def test_write_report_persists_triage(tmp_path: Path) -> None:
    ReportGenerator().write_report(tmp_path, "sample.bin", {}, triage=_triage())
    assert "AI Triage" in (tmp_path / "report.md").read_text()
    assert json.loads((tmp_path / "report.json").read_text())["triage"]["model"] == "mistral:7b"
