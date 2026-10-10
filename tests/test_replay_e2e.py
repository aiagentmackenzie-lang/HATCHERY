"""Replay a *real* static run end to end (no Docker).

Runs the real ``hatchery submit --no-sandbox`` on the EICAR fixture, then the
real ``hatchery replay`` and asserts the replayed bundle reproduces the static
findings. This is the honest version of the feature: the exact pipeline the
operator runs, not a mock.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = (REPO_ROOT / "tests" / "fixtures" / "eicar.com").resolve()


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )


def test_replay_of_a_real_static_run_is_reproducible(tmp_path: Path) -> None:
    original = tmp_path / "orig"
    submitted = _run_cli(
        ["submit", str(SAMPLE), "--no-sandbox", "-o", str(original)], tmp_path
    )
    assert submitted.returncode == 0, submitted.stderr[-2000:]
    assert (original / "bundle" / "analysis.json").exists()

    replay_out = tmp_path / "replayed"
    replayed = _run_cli(
        ["replay", str(original / "bundle"), "--no-sandbox", "-o", str(replay_out)],
        tmp_path,
    )
    assert replayed.returncode == 0, replayed.stdout[-3000:] + replayed.stderr[-2000:]

    section = json.loads((replay_out / "bundle" / "replay.json").read_text())
    assert section["verdict"] == "reproducible"
    assert section["deterministic_mismatches"] == []
    assert section["settings"]["reproduced"] is True
    assert section["sample"]["hash_verified"] is True

    # the replayed bundle carries the section, and the original was not touched
    replayed_bundle = json.loads((replay_out / "bundle" / "analysis.json").read_text())
    assert replayed_bundle["replay"]["verdict"] == "reproducible"
    assert replayed_bundle["summary"]["replay_verdict"] == "reproducible"
    original_bundle = json.loads((original / "bundle" / "analysis.json").read_text())
    assert "replay" not in original_bundle

    # a deterministic signal really was compared, not skipped
    assert "yara_rules" in section["identical"]
    assert section["identical"]["yara_rules"] is True
