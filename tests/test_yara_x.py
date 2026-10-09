"""Tests for YARA-X scanning and the rule lint gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.static.yara_scanner import (
    ACCEPTED_WARNINGS,
    RULE_NAME_PATTERN,
    YARAScanner,
    lint_rules,
)

RULES_DIR = Path(__file__).resolve().parents[1] / "engine" / "static" / "rules"


class TestShippedRules:
    """The rule sets in this repository must pass their own gate."""

    def test_shipped_rules_lint_with_no_errors(self):
        report = lint_rules(RULES_DIR)
        assert report.ok, report.errors
        assert report.files_checked >= 5

    def test_no_unaccepted_warnings_in_shipped_rules(self):
        report = lint_rules(RULES_DIR)
        assert report.warnings == []

    def test_every_non_test_rule_maps_to_attack(self):
        report = lint_rules(RULES_DIR)
        assert report.rules_without_attack_mapping == []

    def test_accepted_warnings_are_documented(self):
        for key, reason in ACCEPTED_WARNINGS.items():
            assert len(reason) > 20, f"{key} needs a real reason, not a placeholder"

    def test_scanner_loads_all_shipped_rules(self):
        scanner = YARAScanner(RULES_DIR)
        result = scanner.scan(Path(__file__).resolve().parents[1] / "samples" / "eicar.com")
        assert result.error is None
        assert result.rules_loaded >= 5
        assert result.backend == "yara-x"

    def test_eicar_rule_matches_the_eicar_sample(self):
        scanner = YARAScanner(RULES_DIR)
        result = scanner.scan(Path(__file__).resolve().parents[1] / "samples" / "eicar.com")
        assert any(m.rule == "HATCHERY_EICAR_TestFile" for m in result.matches)

    def test_matches_carry_severity_and_attack_from_metadata(self):
        scanner = YARAScanner(RULES_DIR)
        result = scanner.scan(Path(__file__).resolve().parents[1] / "samples" / "eicar.com")
        match = next(m for m in result.matches if m.rule == "HATCHERY_EICAR_TestFile")
        assert match.severity == "info"
        assert match.to_dict()["severity"] == "info"


class TestLintGateHasTeeth:
    """A gate that cannot fail is not a gate."""

    def test_rule_name_convention_is_enforced(self, tmp_path: Path):
        # Valid metadata, bad name: only the naming lint can fire, so this test
        # cannot pass by accident because of a different lint.
        (tmp_path / "bad.yar").write_text(
            'rule wrong_prefix { meta: description = "d" severity = "low" condition: true }'
        )
        report = lint_rules(tmp_path)
        assert not report.ok
        assert any("rule name does not match" in e for e in report.errors), report.errors

    def test_missing_required_metadata_is_an_error(self, tmp_path: Path):
        (tmp_path / "nometa.yar").write_text("rule HATCHERY_NoMeta { condition: true }")
        report = lint_rules(tmp_path)
        assert not report.ok
        assert any("severity" in e for e in report.errors)

    def test_syntax_errors_are_reported_not_swallowed(self, tmp_path: Path):
        (tmp_path / "broken.yar").write_text("rule HATCHERY_Broken { strings: $a = condition: $b }")
        report = lint_rules(tmp_path)
        assert not report.ok

    def test_missing_attack_mapping_is_reported_as_a_warning(self, tmp_path: Path):
        (tmp_path / "nomap.yar").write_text(
            'rule HATCHERY_NoMap { meta: description = "d" severity = "low" condition: true }'
        )
        report = lint_rules(tmp_path)
        assert report.ok
        assert any("HATCHERY_NoMap" in w for w in report.rules_without_attack_mapping)

    def test_test_rules_are_exempt_from_attack_mapping(self, tmp_path: Path):
        (tmp_path / "t.yar").write_text(
            'rule HATCHERY_TestThing { meta: description = "d" severity = "low" condition: true }'
        )
        report = lint_rules(tmp_path)
        assert report.rules_without_attack_mapping == []

    def test_empty_rules_dir_is_an_error(self, tmp_path: Path):
        report = lint_rules(tmp_path / "does-not-exist")
        assert not report.ok

    def test_report_is_json_serializable(self):
        report = lint_rules(RULES_DIR)
        import json

        json.dumps(report.to_dict())


def test_rule_name_pattern_matches_the_convention():
    import re

    assert re.match(RULE_NAME_PATTERN, "HATCHERY_Packing_UPX")
    assert not re.match(RULE_NAME_PATTERN, "Suspicious_Thing")


@pytest.mark.parametrize(
    "data,expected_rule",
    [
        (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "HATCHERY_EICAR_TestFile"),
    ],
)
def test_scan_bytes_matches(data: bytes, expected_rule: str):
    scanner = YARAScanner(RULES_DIR)
    result = scanner.scan_bytes(data)
    assert result.error is None
    assert any(m.rule == expected_rule for m in result.matches)


def test_scan_missing_file_returns_an_error_not_a_clean_result():
    scanner = YARAScanner(RULES_DIR)
    result = scanner.scan(Path("/nonexistent/sample.bin"))
    assert result.error is not None
    assert not result.has_matches
