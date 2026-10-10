"""Fingerprint extraction: every token comes from something the engine recorded."""

from __future__ import annotations

import json
from pathlib import Path

from _cluster_builder import bundle_with

from engine.cluster.fingerprint import (
    features_from_bundle,
    find_run_dirs,
    fingerprint_from_bundle,
    fingerprint_from_run,
    load_fingerprints,
)


def test_features_cover_every_category() -> None:
    features = features_from_bundle(bundle_with())
    assert "create process" in features["capa"]
    assert "suspicious_powershell" in features["rule"]
    assert "T1059.001" in features["technique"]
    assert "evil.example" in features["ioc"]
    assert "kernel32.dll!createprocessa" in features["import"]
    assert "dllregisterserver" in features["export"]
    assert ".text" in features["section"]
    assert "high entropy section" in features["suspicious"]
    assert features["imphash"]
    assert "createfilew" in features["emulation_api"]
    assert any(token.startswith("urls:") for token in features["string"])


def test_import_hash_is_stable_and_dll_extension_is_stripped() -> None:
    features = features_from_bundle(bundle_with())
    other = bundle_with()
    other["static"]["pe"]["imports"] = [
        {"dll": "KERNEL32", "function": "CreateProcessA"},
        {"dll": "WS2_32.DLL", "function": "connect"},
    ]
    assert features["imphash"] == features_from_bundle(other)["imphash"]


def test_import_hash_differs_for_different_imports() -> None:
    left = features_from_bundle(bundle_with())["imphash"]
    other = bundle_with()
    other["static"]["pe"]["imports"] = [{"dll": "USER32.dll", "function": "MessageBoxA"}]
    assert left != features_from_bundle(other)["imphash"]


def test_zeroed_compile_timestamp_is_not_a_feature() -> None:
    other = bundle_with()
    other["static"]["pe"]["compile_timestamp"] = "1970-01-01 00:00:00"
    assert "compile_time" not in features_from_bundle(other)


def test_absent_categories_are_omitted_not_empty() -> None:
    features = features_from_bundle({"task_id": "t", "sample": {}, "static": {}})
    assert features == {}


def test_fingerprint_id_is_content_addressed_and_key_is_the_run() -> None:
    first = fingerprint_from_bundle(bundle_with(task_id="run-a"))
    second = fingerprint_from_bundle(bundle_with(task_id="run-b"))
    assert first.id == second.id  # identical content, identical address
    assert first.key == "run-a"
    assert second.key == "run-b"


def test_fingerprint_id_changes_when_content_changes() -> None:
    base = fingerprint_from_bundle(bundle_with())
    other = bundle_with()
    other["static"]["capa"]["capabilities"] = [{"name": "delete file"}]
    assert base.id != fingerprint_from_bundle(other).id


def test_to_dict_round_trips() -> None:
    payload = fingerprint_from_bundle(bundle_with()).to_dict()
    assert payload["id"]
    assert payload["task_id"] == "t1"
    assert "create process" in payload["features"]["capa"]


def test_find_run_dirs_accepts_nested_and_bare_layouts(tmp_path: Path) -> None:
    nested = tmp_path / "run1" / "bundle"
    nested.mkdir(parents=True)
    (nested / "analysis.json").write_text(json.dumps(bundle_with(task_id="run1")))
    bare = tmp_path / "run2"
    bare.mkdir()
    (bare / "analysis.json").write_text(json.dumps(bundle_with(task_id="run2")))

    found = {path.name for path in find_run_dirs(tmp_path)}
    assert found == {"bundle", "run2"}


def test_load_fingerprints_skips_a_broken_bundle(tmp_path: Path) -> None:
    good = tmp_path / "good"
    good.mkdir()
    (good / "analysis.json").write_text(json.dumps(bundle_with(task_id="good")))
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "analysis.json").write_text("{not json")

    fingerprints = load_fingerprints(tmp_path)
    assert [fp.task_id for fp in fingerprints] == ["good"]


def test_fingerprint_from_run_reads_the_bundle(tmp_path: Path) -> None:
    (tmp_path / "analysis.json").write_text(json.dumps(bundle_with(task_id="solo")))
    assert fingerprint_from_run(tmp_path).task_id == "solo"
