"""The corpus seal and the verifier the recipient runs (D34).

``hatchery results seal --all`` exists because a control that is documented but
not operable at corpus scale is a control nobody uses: the operator's checkout
held 35 runs that all had to be sealed by hand. ``scripts/verify_manifest.py``
exists because an integrity claim is only worth what the recipient can check:
it is the same ``verify_run`` behind the standard library alone.
"""

from __future__ import annotations

from pathlib import Path

from _results_builder import cli_json, make_run, manifest_hash, run_cli
from engine.results import verify_run



# ---------------------------------------------------------------------------
# 1. seal --all over a corpus
# ---------------------------------------------------------------------------


def _corpus(tmp_path: Path) -> Path:
    results = tmp_path / "results"
    results.mkdir()

    # A parent and its legacy nested replay, both without a manifest.
    unsealed = make_run(results, "with-replay", days_ago=30, sealed=False)
    nested = make_run(unsealed, "replay-deadbeef", days_ago=30, sealed=False)
    (nested / "replay.json").write_text('{"replay_id":"deadbeef"}\n', encoding="utf-8")

    # An already-sealed, intact run: its manifest must not be rewritten.
    make_run(results, "already-sealed", days_ago=5)

    # A tampered run: refused, never blessed.
    tampered = make_run(results, "tampered", days_ago=4)
    (tampered / "bundle" / "events.jsonl").write_text('{"tampered":true}\n')

    # Entries that are not runs and must never be followed or sealed.
    (results / "notes").mkdir()
    (results / "notes" / "readme.txt").write_text("operator notes\n")
    (results / "run-dead.deleting-20260101T000000Z").mkdir()
    (results / ".hidden").mkdir()
    outside = tmp_path / "outside-run"
    outside.mkdir()
    (results / "linked-run").symlink_to(outside)
    return results


def test_seal_all_seals_a_corpus_depth_first_and_is_idempotent(tmp_path: Path) -> None:
    results = _corpus(tmp_path)
    sealed_hash = manifest_hash(results / "already-sealed")
    tampered_hash = manifest_hash(results / "tampered")

    code, report = cli_json(
        ["results", "seal", str(results), "--all", "--json"], tmp_path
    )
    assert code == 2, "a refused run is exit 2 even when the rest were sealed"
    assert report["counts"] == {
        "sealed": 2,
        "already": 1,
        "refused": 1,
        "ignored": 4,
    }
    sealed = [entry["run_id"] for entry in report["sealed"]]
    assert sealed.index("replay-deadbeef") < sealed.index("with-replay"), (
        "nested units are sealed before their parent"
    )
    assert [entry["run_id"] for entry in report["already"]] == ["already-sealed"]

    refusal = report["refused"][0]
    assert refusal["run_id"] == "tampered"
    assert refusal["reason"] == "manifest-mismatch"
    assert refusal["classification"] == "modified"
    assert refusal["break_path"] == "bundle/events.jsonl"

    ignored = {entry["name"]: entry["reason"] for entry in report["ignored"]}
    assert ignored == {
        ".hidden": "hidden",
        "linked-run": "symlink",
        "notes": "not-a-run",
        "run-dead.deleting-20260101T000000Z": "deleting-stray",
    }
    assert (results / "linked-run").is_symlink()
    assert not (tmp_path / "outside-run" / "manifest.json").exists(), (
        "a symlinked run directory is never followed"
    )
    assert (results / "notes" / "readme.txt").is_file()

    # Nothing was blessed: the tampered manifest is byte-identical.
    assert manifest_hash(results / "tampered") == tampered_hash
    assert verify_run(results / "tampered")["state"] == "broken"

    # The intact run was not rewritten, and sealing the corpus was anchor-safe.
    assert manifest_hash(results / "already-sealed") == sealed_hash
    assert (results / "with-replay" / "manifest.json").is_file()
    assert (results / "with-replay" / "replay-deadbeef" / "manifest.json").is_file()
    assert verify_run(results / "with-replay")["state"] == "intact"

    # A second invocation seals nothing and prints the same hashes.
    code, again = cli_json(
        ["results", "seal", str(results), "--all", "--json"], tmp_path
    )
    assert code == 2
    assert again["sealed"] == []
    assert [entry["run_id"] for entry in again["already"]] == [
        "already-sealed",
        "replay-deadbeef",
        "with-replay",
    ]
    assert {
        entry["run_id"]: entry["manifest_sha256"] for entry in again["already"]
    } == {
        entry["run_id"]: entry["manifest_sha256"]
        for entry in report["sealed"] + report["already"]
    }


def test_seal_all_refuses_replace_and_rewrites_nothing(tmp_path: Path) -> None:
    results = _corpus(tmp_path)
    before = {
        path.name: manifest_hash(path)
        for path in results.iterdir()
        if path.is_dir() and (path / "manifest.json").is_file()
    }
    result = run_cli(
        ["results", "seal", str(results), "--all", "--replace"], tmp_path
    )
    assert result.returncode == 2
    assert "replace-not-allowed" in (result.stdout + result.stderr)
    assert not (results / "with-replay" / "manifest.json").exists(), (
        "a refused batch must not seal anything"
    )
    assert {
        path.name: manifest_hash(path)
        for path in results.iterdir()
        if path.is_dir() and (path / "manifest.json").is_file()
    } == before


def test_seal_all_on_a_missing_root_is_an_operational_error(tmp_path: Path) -> None:
    result = run_cli(
        ["results", "seal", str(tmp_path / "nope"), "--all"], tmp_path
    )
    assert result.returncode == 1
    assert "not-found" in result.stderr
