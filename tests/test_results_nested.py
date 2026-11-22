"""A run directory's claim includes its nested units (D34).

D33 made ``manifest.json`` the claim that a run directory is intact, but the
parent's conclusion ignored a nested replay that could not be verified at all:
``verify_run`` returned ``ok: True`` with ``nested_runs: [("replay-…",
"unsealed")]``, and retention read only the parent's state, so a prune deleted
the nested evidence with it. These tests pin the corrected conclusion and the
retention refusal, using real run directories and the real CLI.
"""

from __future__ import annotations

import json
from pathlib import Path

from _results_builder import cli_json, make_run, manifest_hash, run_cli
from engine.results import verify_run


def _parent_with_legacy_replay(results: Path) -> tuple[Path, Path]:
    parent = make_run(results, "run-with-legacy-replay", days_ago=30)
    nested = make_run(parent, "replay-deadbeef", days_ago=30, sealed=False)
    (nested / "replay.json").write_text(
        json.dumps({"replay_id": "deadbeef", "verdict": "inconclusive"}),
        encoding="utf-8",
    )
    return parent, nested


def _corpus(tmp_path: Path) -> tuple[Path, Path, Path]:
    results = tmp_path / "results"
    results.mkdir()
    parent, nested = _parent_with_legacy_replay(results)
    # The anchor: a newer run so the parent is the one a policy would delete.
    make_run(results, "run-newer", days_ago=1)
    return results, parent, nested


# ---------------------------------------------------------------------------
# 1. verify: a nested unsealed unit is part of the parent's conclusion
# ---------------------------------------------------------------------------


def test_a_nested_unsealed_replay_breaks_the_parents_claim(tmp_path: Path) -> None:
    results, parent, _nested = _corpus(tmp_path)

    code, report = cli_json(["results", "verify", str(parent), "--json"], tmp_path)
    assert code == 1, "an unverifiable nested unit must not report ok"
    assert report["ok"] is False
    assert report["state"] == "broken"
    assert report["classification"] == "nested-unsealed"
    assert report["path"] == "replay-deadbeef"

    # Every child is still listed with its own state, and the child carries the
    # same classification and its own path.
    assert [(item["run_id"], item["state"]) for item in report["nested_runs"]] == [
        ("replay-deadbeef", "unsealed")
    ]
    assert report["nested_runs"][0]["classification"] == "nested-unsealed"
    assert report["nested_runs"][0]["path"] == "replay-deadbeef"

    # The human output says it in a line nobody can miss.
    human = run_cli(["results", "verify", str(parent)], tmp_path)
    assert human.returncode == 1
    assert "nested replay replay-deadbeef: unsealed" in human.stdout


def test_the_anchor_can_match_while_the_directory_is_broken(tmp_path: Path) -> None:
    results, parent, _nested = _corpus(tmp_path)
    anchor = manifest_hash(parent)

    code, report = cli_json(
        [
            "results",
            "verify",
            str(parent),
            "--json",
            "--expect-manifest",
            anchor,
        ],
        tmp_path,
    )
    assert code == 1
    assert report["anchor"]["match"] is True
    assert report["ok"] is False
    assert report["classification"] == "nested-unsealed"

    human = run_cli(
        ["results", "verify", str(parent), "--expect-manifest", anchor], tmp_path
    )
    assert human.returncode == 1
    flattened = " ".join(human.stdout.split())
    assert "matches the anchor" in flattened
    assert "not that every nested unit" in flattened


def test_sealing_the_nested_unit_makes_the_directory_intact_anchor_safely(
    tmp_path: Path,
) -> None:
    results, parent, nested = _corpus(tmp_path)
    parent_before = manifest_hash(parent)
    assert verify_run(parent)["state"] == "broken"

    code, report = cli_json(
        ["results", "seal", str(results), "--all", "--json"], tmp_path, expect=0
    )
    assert [entry["run_id"] for entry in report["sealed"]] == [
        "replay-deadbeef"
    ]
    assert {entry["run_id"] for entry in report["already"]} == {
        "run-with-legacy-replay",
        "run-newer",
    }
    assert (nested / "manifest.json").is_file()

    # Sealing a nested unit never changes the parent's manifest bytes, so an
    # anchor recorded at delivery is still valid.
    assert manifest_hash(parent) == parent_before
    code, verified = cli_json(
        ["results", "verify", str(parent), "--json"], tmp_path, expect=0
    )
    assert verified["ok"] is True
    assert verified["state"] == "intact"
    assert verified["manifest_sha256"] == parent_before


def test_a_nested_broken_unit_keeps_its_own_classification_and_prefixed_path(
    tmp_path: Path,
) -> None:
    results, parent, nested = _corpus(tmp_path)
    assert cli_json(["results", "seal", str(results), "--all", "--json"], tmp_path,
                    expect=0)
    (nested / "bundle" / "events.jsonl").write_text('{"tampered":true}\n')

    code, report = cli_json(["results", "verify", str(parent), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "modified"
    assert report["path"] == "replay-deadbeef/bundle/events.jsonl"
    assert report["nested_runs"][0]["classification"] == "modified"


# ---------------------------------------------------------------------------
# 2. retention: the whole plan is refused and nothing is deleted
# ---------------------------------------------------------------------------


def test_prune_refuses_the_whole_plan_for_a_nested_unsealed_unit(
    tmp_path: Path,
) -> None:
    results, parent, nested = _corpus(tmp_path)

    code, dry = cli_json(
        [
            "results",
            "prune",
            "--older-than",
            "10d",
            "--keep-last",
            "1",
            "--json",
            "--results",
            str(results),
        ],
        tmp_path,
    )
    assert code == 2
    assert dry["blocked"] is True
    decision = next(item for item in dry["decisions"] if item["run_id"] == parent.name)
    assert decision["reason"] == "nested-unsealed"
    assert decision["decision"] == "keep"
    refusal = next(item for item in dry["refused"] if item["run_id"] == parent.name)
    assert refusal["reason"] == "nested-unsealed"
    assert refusal["classification"] == "nested-unsealed"
    assert refusal["path"] == "replay-deadbeef"

    code, applied = cli_json(
        [
            "results",
            "prune",
            "--older-than",
            "10d",
            "--keep-last",
            "1",
            "--apply",
            "--json",
            "--results",
            str(results),
        ],
        tmp_path,
    )
    assert code == 2
    assert applied["removed"] == []
    assert parent.is_dir(), "a run with unverifiable nested evidence is never deleted"
    assert nested.is_dir()
    log = json.loads((results / ".prune-log.jsonl").read_text().splitlines()[-1])
    assert log["refused"][0]["reason"] == "nested-unsealed"


def test_prune_removes_the_run_and_records_the_nested_count_after_sealing(
    tmp_path: Path,
) -> None:
    results, parent, nested = _corpus(tmp_path)
    cli_json(["results", "seal", str(results), "--all", "--json"], tmp_path, expect=0)

    code, applied = cli_json(
        [
            "results",
            "prune",
            "--older-than",
            "10d",
            "--keep-last",
            "1",
            "--apply",
            "--json",
            "--results",
            str(results),
        ],
        tmp_path,
        expect=0,
    )
    assert applied["applied"] is True
    assert [item["run_id"] for item in applied["removed"]] == [parent.name]
    assert applied["removed"][0]["nested_runs"] == 1
    assert not parent.exists() and not nested.exists()
    assert (results / "run-newer").is_dir()


# ---------------------------------------------------------------------------
# 3. status: counts, a named block, and no deletion
# ---------------------------------------------------------------------------


def test_status_reports_unsealed_runs_and_nested_units_without_deleting(
    tmp_path: Path,
) -> None:
    results, _parent, nested = _corpus(tmp_path)
    make_run(results, "legacy-run", days_ago=5, sealed=False)
    before = sorted(path.name for path in results.iterdir())

    code, report = cli_json(
        ["results", "status", "--json", "--results", str(results)],
        tmp_path,
        expect=0,
    )
    assert report["unsealed_runs"] == 1
    assert report["unsealed_nested"] == 1
    assert report["blocked"] is True
    assert sorted(path.name for path in results.iterdir()) == before, (
        "status must never delete anything"
    )

    human = run_cli(["results", "status", "--results", str(results)], tmp_path)
    assert human.returncode == 0
    assert "Unsealed:" in human.stdout
    assert "would be refused" in human.stdout
    assert nested.is_dir()
