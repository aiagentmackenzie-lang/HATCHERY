"""Parse a real Speakeasy report (D6: assert against a real capture).

The fixture ``tests/fixtures/speakeasy-report-real.json`` is a genuine Speakeasy
2.0.0b6 report captured from the hand-built benign PE (tests/_pe_builder.py) run
under the emulation container. The ``data`` store is trimmed to the small
snapshots so the fixture stays reviewable; the parser's missing-reference path is
therefore exercised with real dangling refs.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from engine.emulate import report as report_mod
from engine.emulate.report import (
    EMULATOR_VERSION,
    decode_data_ref,
    parse_report,
    report_schema_hash,
)

FIXTURE = Path(__file__).parent / "fixtures" / "speakeasy-report-real.json"


@pytest.fixture(scope="module")
def raw() -> dict:
    return json.loads(FIXTURE.read_text())


def test_fixture_is_a_real_report(raw: dict) -> None:
    assert raw["report_version"] == "4.0.0"
    assert raw["arch"] == "x86"
    assert raw["filetype"] == "exe"
    assert raw["entry_points"]


def test_parser_extracts_structure(raw: dict) -> None:
    report = parse_report(raw)
    assert report.report_version == "4.0.0"
    assert report.entry_point_count == 1
    assert report.api_names == [
        "kernel32.GetTickCount",
        "kernel32.CreateMutexA",
        "wininet.InternetOpenA",
        "wininet.InternetOpenUrlA",
    ]
    assert report.api_call_count == 4
    assert report.memory_regions, "a run-end memory layout should be captured"
    assert all(region.address >= 0 and region.size >= 0 for region in report.memory_regions)


def test_schema_hash_is_stable_and_recorded(raw: dict) -> None:
    first = report_schema_hash(raw)
    second = report_schema_hash(json.loads(json.dumps(raw)))
    assert first == second
    assert parse_report(raw).schema_hash == first
    assert len(first) == 64


def test_schema_hash_changes_when_shape_changes(raw: dict) -> None:
    mutated = json.loads(json.dumps(raw))
    mutated["entry_points"][0]["events"].append({"event": "reg_write_value", "path": "HKCU\\X"})
    assert report_schema_hash(mutated) != report_schema_hash(raw)

    renamed = json.loads(json.dumps(raw))
    renamed["entry_points"][0]["events"][0]["event"] = "some_new_event"
    assert report_schema_hash(renamed) != report_schema_hash(raw)


def test_data_ref_roundtrip(raw: dict) -> None:
    report = parse_report(raw)
    decoded = 0
    for region in report.memory_regions:
        payload = decode_data_ref(report.data_store, region.data_ref)
        if payload is not None:
            decoded += 1
    assert decoded > 0, "at least one real snapshot should decode"


def test_data_ref_missing_and_corrupt_are_none(raw: dict) -> None:
    assert decode_data_ref(raw["data"], "deadbeef") is None
    corrupt = {"abc": {"compression": "zlib", "encoding": "base64", "size": 1, "data": "!!!notbase64!!!"}}
    assert decode_data_ref(corrupt, "abc") is None
    unknown = {"abc": {"compression": "lzo", "encoding": "base64", "size": 1, "data": "eA=="}}
    assert decode_data_ref(unknown, "abc") is None


def test_non_object_report_raises() -> None:
    with pytest.raises(ValueError):
        parse_report("[1, 2, 3]")
    with pytest.raises(ValueError):
        parse_report("not json at all")


def test_empty_report_is_not_conclusive_but_parses() -> None:
    report = parse_report({"report_version": "4.0.0", "entry_points": []})
    assert not report.has_events
    assert report.is_conclusive  # no unsupported API — simply empty
    assert report.api_call_count == 0


def test_emulator_pin_matches_pyproject() -> None:
    """The recorded emulator version must match the optional-extra pin."""
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    extras = data["project"]["optional-dependencies"]
    assert "emulation" in extras, "the emulation extra must exist"
    pins = [item for item in extras["emulation"] if item.startswith("speakeasy-emulator")]
    assert pins == [f"speakeasy-emulator=={EMULATOR_VERSION}"]


def test_emulation_is_not_a_runtime_dependency() -> None:
    """The pinned python-gate matrix must never install the beta emulator."""
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    declared = " ".join(data["project"]["dependencies"])
    assert "speakeasy" not in declared
    dev = " ".join(data["project"]["optional-dependencies"].get("dev", []))
    assert "speakeasy" not in dev


def test_report_module_does_not_import_speakeasy() -> None:
    source = (Path(report_mod.__file__)).read_text()
    assert "import speakeasy" not in source
