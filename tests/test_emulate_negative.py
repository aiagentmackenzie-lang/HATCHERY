"""The negative test that is really negative (D3 rule for the emulation stage).

A sample that reaches an API the emulator does not implement must produce an
INCONCLUSIVE limitation, never a clean verdict. The fixture is a real Speakeasy
report captured from a hand-built PE whose only import is an unimplemented API.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.bundle import AnalysisBundle, compute_limitations, write_bundle
from engine.emulate import runner
from engine.emulate.report import parse_report

FIXTURE = Path(__file__).parent / "fixtures" / "speakeasy-report-unsupported-api.json"


def _negative_section() -> tuple[dict, list[dict]]:
    raw = json.loads(FIXTURE.read_text())
    return runner.analyze(raw, run_capa=False)


def test_real_capture_reports_unsupported_api() -> None:
    report = parse_report(json.loads(FIXTURE.read_text()))
    assert report.unsupported_apis == ["kernel32.ThisApiDoesNotExistBySpeakeasy"]
    assert not report.is_conclusive


def test_limitations_are_inconclusive_not_clean() -> None:
    section, events = _negative_section()
    assert section["unsupported_apis"]
    assert "emulation-api-missing" in section["flags"]
    limits = compute_limitations(
        isolation=None, sandbox=None, artifacts=None, events=events, emulation=section
    )
    joined = "\n".join(limits)
    assert "INCONCLUSIVE" in joined
    assert "ThisApiDoesNotExistBySpeakeasy" in joined


def test_unavailable_emulation_is_declared() -> None:
    limits = compute_limitations(
        isolation=None, sandbox=None, artifacts=None, events=[{"category": "file"}],
        emulation=runner.unavailable_section("docker daemon unreachable"),
    )
    joined = "\n".join(limits)
    assert "Emulation was not run" in joined
    assert "docker daemon unreachable" in joined


def test_timeout_is_declared() -> None:
    section, events = _negative_section()
    section["status"] = "timeout"
    section.pop("unsupported_apis", None)
    limits = compute_limitations(
        isolation=None, sandbox=None, artifacts=None, events=events, emulation=section
    )
    assert any("wall-clock" in line for line in limits)


def test_empty_emulation_is_not_established() -> None:
    empty, events = runner.analyze(
        {"report_version": "4.0.0", "filetype": "exe", "entry_points": []}, run_capa=False
    )
    limits = compute_limitations(
        isolation=None, sandbox=None, artifacts=None, events=events, emulation=empty
    )
    assert any("NOT ESTABLISHED" in line for line in limits)


def test_bundle_summary_marks_emulation_inconclusive(tmp_path: Path) -> None:
    section, events = _negative_section()
    bundle = AnalysisBundle(
        task_id="deadbeef",
        emulation=section,
        emulation_events=events,
        events=events,
    )
    summary = bundle.summary()
    assert summary["emulation_available"] is True
    assert summary["emulation_inconclusive"] is True
    # The emulated events are a separate stream (D4).
    write_bundle(tmp_path / "bundle", bundle)
    assert (tmp_path / "bundle" / "emulation-events.jsonl").exists()
    assert (tmp_path / "bundle" / "events.jsonl").exists()
    data = json.loads((tmp_path / "bundle" / "analysis.json").read_text())
    assert data["emulation"]["unsupported_apis"]
