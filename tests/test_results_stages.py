"""Every stage that mutates a run re-seals it (D4/D33).

The constraint that matters: a manifest written only at submit time would report
``modified`` after a legitimate ``triage`` or ``push``, and a false break would
make the whole feature untrustworthy. These are real CLI processes against real
runs — triage against an unreachable local model (the unavailable path still
patches the bundle), and push against a closed port (a failed push still writes
its result file).
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from _results_builder import base_env, cli_json, manifest_hash, run_cli, submit


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _unavailable_triage_env(tmp_path: Path) -> dict[str, str]:
    env = base_env(tmp_path)
    env["HATCHERY_OLLAMA_URL"] = f"http://127.0.0.1:{_closed_port()}"
    env["HATCHERY_TRIAGE_TIMEOUT"] = "1"
    env["HATCHERY_TRIAGE_ATTEMPTS"] = "1"
    env["HATCHERY_TRIAGE_MODEL"] = "test-model"
    return env


def test_triage_mutates_the_bundle_and_reseals_at_stage_triage(tmp_path: Path) -> None:
    env = _unavailable_triage_env(tmp_path)
    run_dir = submit(tmp_path, env=env)
    before = manifest_hash(run_dir)

    result = run_cli(["triage", str(run_dir / "bundle")], tmp_path, env=env)
    # No model is reachable, so triage is unavailable — and the CLI says so with
    # a non-zero exit. It still patched the bundle, which is exactly the case
    # that must be re-sealed rather than reported as tamper.
    assert result.returncode == 1, result.stdout[-2000:] + result.stderr[-1000:]
    assert "Manifest re-sealed at stage triage" in result.stdout

    analysis = json.loads((run_dir / "bundle" / "analysis.json").read_text())
    assert analysis["triage"]["status"] == "unavailable"

    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert report["state"] == "intact", report["error"]
    assert report["stage"] == "triage"
    assert report["manifest_sha256"] != before

    # An out-of-band edit after the re-seal is a break — D4's constraint, pinned.
    target = run_dir / "bundle" / "analysis.json"
    target.write_text(target.read_text().replace('"evasion": null', '"evasion": null '))
    code, broken = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert broken["classification"] == "modified"
    assert broken["path"] == "bundle/analysis.json"


@pytest.mark.parametrize("form", ["run", "bundle"])
def test_triage_accepts_a_run_directory_or_its_bundle(
    tmp_path: Path, form: str
) -> None:
    """Both paths an operator naturally types must patch and re-seal (D34)."""
    env = _unavailable_triage_env(tmp_path)
    run_dir = submit(tmp_path, env=env)
    target = run_dir if form == "run" else run_dir / "bundle"

    result = run_cli(["triage", str(target)], tmp_path, env=env)
    assert result.returncode == 1, result.stdout[-2000:] + result.stderr[-1000:]
    assert "Manifest re-sealed at stage triage" in result.stdout
    assert "No analysis bundle at" not in result.stdout

    analysis = json.loads((run_dir / "bundle" / "analysis.json").read_text())
    assert analysis["triage"]["status"] == "unavailable"
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert report["state"] == "intact"
    assert report["stage"] == "triage"

    # An out-of-band edit after the re-seal is still a break.
    target_file = run_dir / "bundle" / "events.jsonl"
    target_file.write_text('{"out":"of-band"}\n')
    code, broken = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert broken["classification"] == "modified"


def test_a_stage_refuses_to_launder_a_modified_run(tmp_path: Path) -> None:
    env = _unavailable_triage_env(tmp_path)
    run_dir = submit(tmp_path, env=env)
    (run_dir / "bundle" / "events.jsonl").write_text('{"out":"of-band"}\n')

    result = run_cli(["triage", str(run_dir / "bundle")], tmp_path, env=env)
    assert result.returncode == 1
    assert "Refusing to modify" in result.stdout
    # The console wraps long paths, so check the classification and path.
    assert "modified at" in result.stdout
    assert "bundle/events.jsonl" in result.stdout
    # The refusal must not have blessed the change.
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "modified"


def test_push_reseals_at_stage_push_even_when_the_push_fails(tmp_path: Path) -> None:
    run_dir = submit(tmp_path)
    before = manifest_hash(run_dir)

    result = run_cli(
        [
            "push",
            str(run_dir),
            "--target",
            "misp",
            "--url",
            f"http://127.0.0.1:{_closed_port()}",
            "--token",
            "not-a-real-token",
        ],
        tmp_path,
    )
    assert result.returncode == 1, result.stdout[-2000:]
    assert "Manifest re-sealed at stage push" in result.stdout

    assert (run_dir / "push-misp.json").is_file()
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert report["state"] == "intact"
    assert report["stage"] == "push"
    assert report["manifest_sha256"] != before
    pushed = json.loads((run_dir / "push-misp.json").read_text())
    assert "not-a-real-token" not in json.dumps(pushed)
