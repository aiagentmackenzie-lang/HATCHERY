"""OCSF Detection Finding tests — D16.

The exporter pins OCSF 1.9.0 and validates every finding against that schema:
required fields, enum membership and the class/category relationship. A
malformed severity, class or category must fail.
"""

from __future__ import annotations

import json

from engine.export.ocsf_export import (
    DETECTION_FINDING_CLASS_UID,
    OCSF_SCHEMA_VERSION,
    build_ocsf_findings,
    load_schema,
    validate_all,
    validate_finding,
)


def sample_mitre() -> dict:
    return {
        "attack_version": "19.2",
        "technique_count": 2,
        "errors": [],
        "techniques": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "subtechnique_id": "T1059.004",
                "subtechnique_name": "Unix Shell",
                "tactic": "Execution",
                "tactic_id": "execution",
                "source": "strace",
                "confidence": "high",
                "detection_strategy_ids": ["DET0001"],
            },
            {
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "subtechnique_id": "T1071.004",
                "subtechnique_name": "DNS",
                "tactic": "Command and Control",
                "tactic_id": "command-and-control",
                "source": "strace",
                "confidence": "medium",
                "detection_strategy_ids": [],
            },
        ],
    }


def sample_events() -> list[dict]:
    return [
        {
            "timestamp": "15:00:00.000001",
            "pid": 43,
            "syscall_name": "connect",
            "category": "network",
            "severity": "medium",
            "source": "gvisor-sentry",
            "args": json.dumps({"dst_ip": "1.1.1.1", "dst_port": 53, "path": "/etc/hosts"}),
        },
        {
            "timestamp": "15:00:00.000002",
            "pid": 43,
            "syscall_name": "execve",
            "category": "process",
            "severity": "high",
            "source": "gvisor-sentry",
            "args": json.dumps({"raw": 'execve("/bin/sh")'}),
        },
    ]


def findings():
    return build_ocsf_findings(
        task_id="abc123",
        sample_name="evil.elf",
        mitre=sample_mitre(),
        evasion={
            "score": 100,
            "verdict": "evasive",
            "impact_score": 0,
            "recon_then_quiet": True,
            "inconclusive": True,
            "signals": ["vm-artifact-probe"],
        },
        events=sample_events(),
        summary={"events_total": 2},
        limitations=["Network egress was blocked."],
        generated_at_ms=1_700_000_000_000,
    )


def test_schema_is_pinned_and_cited():
    schema = load_schema()
    assert schema["meta"]["version"] == OCSF_SCHEMA_VERSION == "1.9.0"
    assert schema["classes"]["2004"]["name"] == "Detection Finding"
    assert schema["categories"]["2"] == "Findings"


def test_findings_are_valid_against_the_pinned_schema():
    assert validate_all(findings()) == []


def test_one_finding_per_technique_plus_evasion():
    result = findings()
    titles = [f["finding_info"]["title"] for f in result]
    assert any("T1059.004" in title for title in titles)
    assert any("T1071.004" in title for title in titles)
    assert any("Evasion" in title for title in titles)


def test_required_fields_are_populated():
    for finding in findings():
        assert finding["class_uid"] == DETECTION_FINDING_CLASS_UID
        assert finding["category_uid"] == 2
        assert finding["type_uid"] == 200401
        assert finding["metadata"]["version"] == OCSF_SCHEMA_VERSION
        assert finding["metadata"]["product"]["name"] == "HATCHERY"
        assert finding["finding_info"]["uid"]
        assert finding["severity_id"] in (0, 1, 2, 3, 4, 5, 6, 99)
        assert isinstance(finding["time"], int) and finding["time"] > 0
        assert finding["evidences"]


def test_malformed_severity_fails_validation():
    result = findings()
    result[0]["severity_id"] = 42
    problems = validate_finding(result[0])
    assert any("severity_id" in problem for problem in problems)


def test_malformed_class_fails_validation():
    result = findings()
    result[0]["class_uid"] = 9999
    problems = validate_finding(result[0])
    assert any("class_uid" in problem for problem in problems)


def test_class_category_mismatch_fails_validation():
    result = findings()
    result[0]["category_uid"] = 1
    problems = validate_finding(result[0])
    assert any("category" in problem for problem in problems)


def test_missing_required_field_fails_validation():
    result = findings()
    del result[0]["finding_info"]
    problems = validate_finding(result[0])
    assert any("finding_info" in problem for problem in problems)


def test_wrong_schema_version_citation_fails_validation():
    result = findings()
    result[0]["metadata"]["version"] = "1.0.0"
    problems = validate_finding(result[0])
    assert any("does not cite OCSF" in problem for problem in problems)


def test_empty_run_still_produces_a_finding():
    result = build_ocsf_findings(task_id="t", sample_name="empty.elf")
    assert len(result) == 1
    assert validate_all(result) == []
    assert result[0]["severity_id"] == 1  # Informational
