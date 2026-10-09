"""Candidate Sigma rule tests — D18.

The rules are *generated drafts*, never validated detections. These tests pin
the YAML shape, the required draft labelling and the ``x_hatchery`` provenance
block.
"""

from __future__ import annotations

import yaml

from engine.export.sigma_candidates import (
    build_sigma_candidates,
    render_sigma_yaml,
    validate_sigma_rule,
    write_sigma_candidates,
)


def mitre() -> dict:
    return {
        "attack_version": "19.2",
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


def events() -> list[dict]:
    return [
        {"category": "process", "syscall_name": "execve", "args": "{}"},
        {"category": "network", "syscall_name": "connect", "args": "{}"},
    ]


def candidates() -> list[dict]:
    return build_sigma_candidates(
        mitre=mitre(), events=events(), task_id="abc123", sample_name="evil.elf"
    )


def test_every_candidate_is_valid_and_well_labelled():
    rules = candidates()
    assert rules
    for rule in rules:
        assert validate_sigma_rule(rule) == []
        assert rule["status"] == "experimental"
        assert "GENERATED DRAFT" in rule["description"]
        assert rule["x_hatchery"]["generated"] is True
        assert rule["x_hatchery"]["reviewed"] is False


def test_candidates_are_rendered_as_valid_yaml_documents():
    rules = candidates()
    text = render_sigma_yaml(rules)
    parsed = list(yaml.safe_load_all(text))
    assert len(parsed) == len(rules)
    for rule in parsed:
        assert rule["detection"]["condition"] == "selection"
        assert rule["logsource"]
        assert any(tag.startswith("attack.") for tag in rule["tags"])


def test_rules_are_written_one_file_per_technique(tmp_path):
    out_dir = write_sigma_candidates(tmp_path, candidates())
    assert out_dir is not None
    files = sorted(p.name for p in out_dir.glob("*.yml"))
    assert files == ["T1059_004.yml", "T1071_004.yml"]
    loaded = yaml.safe_load((out_dir / "T1059_004.yml").read_text())
    assert loaded["x_hatchery"]["technique_id"] == "T1059.004"


def test_no_rule_is_emitted_for_a_technique_without_an_honest_selection():
    """A vague rule that fires on everything is worse than no rule."""
    result = build_sigma_candidates(
        mitre={"techniques": [{"technique_id": "T9999", "tactic_id": "stealth"}]},
        events=events(),
        task_id="t",
    )
    assert result == []


def test_validation_rejects_a_non_experimental_status():
    rule = candidates()[0]
    rule["status"] = "stable"
    assert any("experimental" in problem for problem in validate_sigma_rule(rule))


def test_validation_rejects_a_missing_generated_mark():
    rule = candidates()[0]
    rule["x_hatchery"]["generated"] = False
    assert any("generated" in problem for problem in validate_sigma_rule(rule))


def test_validation_rejects_a_rule_without_a_detection():
    rule = candidates()[0]
    rule["detection"] = {}
    assert any("detection" in problem for problem in validate_sigma_rule(rule))
