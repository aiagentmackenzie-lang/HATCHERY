"""Replay and the bundle manifest (D5): fail closed on a mismatch, unchanged on
a legacy run, and an explicit ``--require-manifest`` for operators who seal
everything.

The verdict and the seal state are separate fields — the same "``ok`` is not the
whole answer" rule as D31's ``assurance`` — so a reproducible replay of an
unsealed run still says ``bundle_manifest: unsealed``.
"""

from __future__ import annotations

import json
from pathlib import Path

from _results_builder import base_env, cli_json, run_cli, submit
from engine.results import verify_run


def _replay(tmp_path: Path, run_dir: Path, *, extra: list[str] | None = None):
    env = base_env(tmp_path)
    args = [
        "replay",
        str(run_dir),
        "--no-sandbox",
        "--json",
        *(extra or []),
    ]
    return cli_json(args, tmp_path, env=env)


def test_a_sealed_run_replays_and_both_runs_verify(tmp_path: Path) -> None:
    run_dir = submit(tmp_path, "original")
    source_hash = verify_run(run_dir)["manifest_sha256"]

    code, section = _replay(tmp_path, run_dir)
    assert code == 0
    assert section["verdict"] == "reproducible"
    assert section["bundle_manifest"]["state"] == "verified"
    assert section["bundle_manifest"]["manifest_sha256"] == source_hash
    assert section["bundle_manifest"]["classification"] is None

    replay_dir = Path(section["replay_run_dir"]).parent
    replay_manifest = replay_dir / "manifest.json"
    assert replay_manifest.is_file(), "the replay run is re-sealed at stage replay"
    report = verify_run(replay_dir)
    assert report["state"] == "intact", report["error"]
    assert report["stage"] == "replay"

    # The parent is still intact: the nested replay is a separate unit and is
    # reported as such, never as an ``extra`` file in the run it came from.
    parent = verify_run(run_dir)
    assert parent["state"] == "intact", parent["error"]
    assert parent["manifest_sha256"] == source_hash
    assert [item["state"] for item in parent["nested_runs"]] == ["intact"]


def test_a_tampered_run_is_inconclusive_and_names_the_break(tmp_path: Path) -> None:
    run_dir = submit(tmp_path, "original")
    target = run_dir / "bundle" / "analysis.json"
    data = bytearray(target.read_bytes())
    data[20] ^= 0x01
    target.write_bytes(bytes(data))

    code, section = _replay(tmp_path, run_dir)
    assert code == 1
    assert section["verdict"] == "inconclusive"
    assert section["bundle_manifest"]["state"] == "broken"
    assert section["bundle_manifest"]["classification"] == "modified"
    assert section["bundle_manifest"]["path"] == "bundle/analysis.json"
    assert section["replay_task_id"] is None
    assert any("modified at bundle/analysis.json" in line for line in section["limitations"])
    # No replay analysis was run: a verdict about different bytes is fiction.
    assert not (Path(section["replay_run_dir"]) / "analysis.json").exists()

    # The failed replay still wrote a record, and the parent's own state is
    # reported honestly as the break it is.
    record = Path(section["replay_run_dir"]).parent / "replay.json"
    assert record.is_file()
    assert verify_run(run_dir)["classification"] == "modified"


def test_an_unsealed_legacy_run_replays_with_the_state_recorded(tmp_path: Path) -> None:
    run_dir = submit(tmp_path, "original")
    (run_dir / "manifest.json").unlink()

    code, section = _replay(tmp_path, run_dir)
    assert code == 0, "legacy compatibility must not be broken by a new field"
    assert section["verdict"] == "reproducible"
    assert section["bundle_manifest"]["state"] == "unsealed"
    assert section["bundle_manifest"]["manifest_sha256"] is None
    assert any("bundle_manifest: unsealed" in line for line in section["limitations"])

    replay_dir = Path(section["replay_run_dir"]).parent
    assert verify_run(replay_dir)["stage"] == "replay"


def test_require_manifest_turns_an_unsealed_source_into_inconclusive(tmp_path: Path) -> None:
    run_dir = submit(tmp_path, "original")
    (run_dir / "manifest.json").unlink()

    code, section = _replay(tmp_path, run_dir, extra=["--require-manifest"])
    assert code == 1
    assert section["verdict"] == "inconclusive"
    assert section["bundle_manifest"]["state"] == "unsealed"
    assert section["require_manifest"] is True
    assert section["replay_task_id"] is None
    assert any("--require-manifest" in line for line in section["limitations"])


def test_a_deleted_manifest_after_delivery_is_caught_by_the_anchor(tmp_path: Path) -> None:
    """The anchor survives the manifest: deleting it is unambiguous (D2)."""
    run_dir = submit(tmp_path, "delivered")
    anchored = verify_run(run_dir)["manifest_sha256"]
    (run_dir / "manifest.json").unlink()

    code, report = cli_json(
        [
            "results",
            "verify",
            str(run_dir),
            "--json",
            "--expect-manifest",
            anchored,
        ],
        tmp_path,
    )
    assert code == 1
    assert report["classification"] == "manifest-missing"

    # An unanchored verify reports the same state but does not fail a corpus.
    code, plain = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert plain["state"] == "unsealed"
    assert plain["ok"] is False


def test_replay_json_is_pure_json_on_stdout(tmp_path: Path) -> None:
    run_dir = submit(tmp_path, "original")
    env = base_env(tmp_path)
    result = run_cli(["replay", str(run_dir), "--no-sandbox", "--json"], tmp_path, env=env)
    assert result.returncode == 0
    section = json.loads(result.stdout)  # a log line on stdout would break this
    assert section["verdict"] == "reproducible"
    assert "Sealed" not in result.stdout
