"""Grounding: fabricated or approximate citations must not survive."""

from __future__ import annotations

from engine.triage.grounding import (
    apply_grounding,
    ground_findings,
    normalize_citation,
    normalize_technique,
    validate_techniques,
)

IDS = {
    "event:1",
    "event:12",
    "rule:linux_persistence_cron",
    "capa:create process",
    "ioc:http://185.220.101.5/gate.php",
    "technique:T1059.004",
}


def test_exact_citation_resolves() -> None:
    assert normalize_citation("event:1", IDS) == "event:1"


def test_citation_with_an_appended_description_resolves() -> None:
    assert normalize_citation("event:12 [file/high] CREATE /etc/cron.d", IDS) == "event:12"
    assert (
        normalize_citation("rule:linux_persistence_cron matched", IDS)
        == "rule:linux_persistence_cron"
    )


def test_citation_wrapped_in_backticks_or_parens_resolves() -> None:
    assert normalize_citation("`event:1`", IDS) == "event:1"
    assert normalize_citation("(event:1)", IDS) == "event:1"


def test_event_1_must_not_match_event_12() -> None:
    # a citation of event:12 against a known set containing only event:1 is not
    # grounded, and vice versa
    assert normalize_citation("event:12", {"event:1"}) is None
    assert normalize_citation("event:1", {"event:12"}) is None


def test_unknown_citation_returns_none() -> None:
    assert normalize_citation("event:999", IDS) is None
    assert normalize_citation("rule:not_a_rule", IDS) is None
    assert normalize_citation("", IDS) is None
    assert normalize_citation(None, IDS) is None


def test_longest_match_wins() -> None:
    ids = {"event:1", "event:12"}
    assert normalize_citation("event:12 something", ids) == "event:12"


def test_finding_without_a_resolvable_citation_is_dropped() -> None:
    findings = [
        {"claim": "real", "grounding": ["event:1"]},
        {"claim": "fabricated", "grounding": ["event:999"]},
        {"claim": "also fabricated", "grounding": []},
    ]
    kept, dropped, stats = ground_findings(findings, IDS)
    assert [f["claim"] for f in kept] == ["real"]
    assert len(dropped) == 2
    assert stats.findings_dropped == 2
    assert stats.citations_invalid >= 1


def test_partial_grounding_keeps_the_valid_citation() -> None:
    findings = [{"claim": "mixed", "grounding": ["event:999", "event:1"]}]
    kept, dropped, _ = ground_findings(findings, IDS)
    assert kept[0]["grounding"] == ["event:1"]
    assert kept[0]["invalid_citations"] == ["event:999"]


def test_normalize_technique_extracts_an_id() -> None:
    assert normalize_technique("T1059.004") == "T1059.004"
    assert normalize_technique("`T1055`") == "T1055"
    assert normalize_technique("technique T1055 here") is None
    assert normalize_technique("not a technique") is None


def test_validate_techniques_accepts_known_and_rejects_unknown_and_revoked() -> None:
    # T1086 (PowerShell) was revoked in favour of T1059.001; the pinned dataset
    # must reject it, which is exactly the guess D15 forbids.
    accepted, rejected = validate_techniques(["T1059.001", "T1086", "T9999", "nonsense"])
    assert "T1059.001" in accepted
    assert any("T1086" in r for r in rejected)
    assert any("T9999" in r for r in rejected)


def test_apply_grounding_labels_accepted_techniques_as_model_suggested() -> None:
    clean = {
        "verdict": "malicious",
        "findings": [
            {"claim": "cron persistence", "grounding": ["event:1"],
             "technique_ids": ["T1053.003", "T9999"]},
        ],
        "not_established": [],
    }
    grounded, dropped, stats = apply_grounding(clean, IDS)
    finding = grounded["findings"][0]
    assert finding["technique_ids"] == ["T1053.003"]
    assert "model-suggested" in finding["technique_source"]
    assert stats.techniques_accepted == ["T1053.003"]
    assert any("T9999" in r for r in stats.techniques_rejected)
