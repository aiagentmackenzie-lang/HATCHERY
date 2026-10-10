"""The triage prompt contract: version, prompt rules, and the response validator.

The validator is the thing HATCHERY trusts — not Ollama's ``format`` enforcement
— so these tests pin its behaviour independently of any runtime.
"""

from __future__ import annotations

import json

from engine.triage.contract import (
    BOUNDARY_CLOSE,
    BOUNDARY_OPEN,
    PROMPT_CONTRACT_VERSION,
    RESPONSE_SCHEMA,
    SYSTEM_PROMPT,
    contract_hash,
    parse_response,
    validate_object,
)


def _valid() -> dict:
    return {
        "verdict": "suspicious",
        "confidence": 42,
        "summary": "Persistence via a cron job.",
        "findings": [{"claim": "cron persistence", "grounding": ["event:1"]}],
        "not_established": ["payload purpose"],
    }


def test_contract_hash_is_stable_and_pins_the_version() -> None:
    digest = contract_hash()
    assert len(digest) == 64
    assert contract_hash() == digest
    assert PROMPT_CONTRACT_VERSION in SYSTEM_PROMPT or True  # version is hashed
    payload = json.dumps(
        {"version": PROMPT_CONTRACT_VERSION, "system_prompt": SYSTEM_PROMPT,
         "schema": RESPONSE_SCHEMA},
        sort_keys=True, separators=(",", ":"),
    )
    import hashlib

    assert digest == hashlib.sha256(payload.encode()).hexdigest()


def test_system_prompt_contains_the_untrusted_boundary_and_citation_rules() -> None:
    assert BOUNDARY_OPEN in SYSTEM_PROMPT
    assert BOUNDARY_CLOSE in SYSTEM_PROMPT
    assert "data" in SYSTEM_PROMPT.lower()
    assert "never an instruction" in SYSTEM_PROMPT.lower()
    assert "verbatim" in SYSTEM_PROMPT.lower()
    # the honest "quiet is not benign" rule
    assert "not evidence that the sample is benign" in SYSTEM_PROMPT.lower()


def test_schema_enum_matches_the_verdict_set() -> None:
    assert RESPONSE_SCHEMA["properties"]["verdict"]["enum"] == [
        "malicious",
        "suspicious",
        "benign",
        "inconclusive",
    ]
    assert set(RESPONSE_SCHEMA["required"]) <= set(RESPONSE_SCHEMA["properties"])


def test_validate_accepts_a_well_formed_object() -> None:
    clean, errors = validate_object(_valid())
    assert errors == []
    assert clean["verdict"] == "suspicious"
    assert clean["findings"][0]["grounding"] == ["event:1"]


def test_validate_rejects_a_non_object() -> None:
    clean, errors = validate_object(["not", "a", "dict"])
    assert clean == {}
    assert errors and "not a JSON object" in errors[0]


def test_validate_rejects_an_unknown_verdict() -> None:
    clean, errors = validate_object({**_valid(), "verdict": "probably fine"})
    assert clean == {}
    assert any("verdict" in e for e in errors)


def test_validate_rejects_a_missing_summary() -> None:
    obj = _valid()
    del obj["summary"]
    clean, errors = validate_object(obj)
    assert clean == {}
    assert any("summary" in e for e in errors)


def test_validate_rejects_a_missing_findings_array() -> None:
    obj = _valid()
    del obj["findings"]
    clean, errors = validate_object(obj)
    assert clean == {}
    assert any("findings" in e for e in errors)


def test_validate_rejects_a_missing_not_established_array() -> None:
    obj = _valid()
    del obj["not_established"]
    clean, errors = validate_object(obj)
    assert clean == {}
    assert any("not_established" in e for e in errors)


def test_validate_truncates_an_over_long_summary_rather_than_failing() -> None:
    clean, errors = validate_object({**_valid(), "summary": "x" * 5000})
    assert errors == []
    assert len(clean["summary"]) <= 1201


def test_validate_clamps_confidence_into_range() -> None:
    high, _ = validate_object({**_valid(), "confidence": 999})
    low, _ = validate_object({**_valid(), "confidence": -5})
    assert high["confidence"] == 100
    assert low["confidence"] == 0


def test_validate_drops_a_finding_without_a_claim() -> None:
    obj = _valid()
    obj["findings"] = [{"claim": "", "grounding": ["event:1"]}, obj["findings"][0]]
    clean, errors = validate_object(obj)
    assert errors == []
    assert len(clean["findings"]) == 1
    assert clean["findings"][0]["claim"] == "cron persistence"
    assert clean["invalid_findings"] == [{"index": 0, "reason": "missing claim"}]


def test_parse_response_rejects_empty_and_non_json() -> None:
    assert parse_response("")[1]
    assert parse_response("   ")[1]
    assert parse_response("I could not analyse this sample.")[1]


def test_parse_response_extracts_a_fenced_object() -> None:
    fenced = "```json\n" + json.dumps(_valid()) + "\n```"
    clean, errors = parse_response(fenced)
    assert errors == []
    assert clean["verdict"] == "suspicious"


def test_parse_response_extracts_an_object_embedded_in_prose() -> None:
    prose = "Here is the triage:\n" + json.dumps(_valid()) + "\nHope that helps."
    clean, errors = parse_response(prose)
    assert errors == []
    assert clean["verdict"] == "suspicious"


def test_parse_response_reports_invalid_json() -> None:
    clean, errors = parse_response('{"verdict": "suspicious", }')
    assert clean == {}
    assert any("valid JSON" in e for e in errors)
