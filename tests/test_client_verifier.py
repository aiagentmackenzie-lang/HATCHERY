"""The verifier the recipient runs (D34).

An integrity claim is only worth what the recipient can check. This script is
the same ``verify_run`` behind the standard library alone, so its answer cannot
drift from ``hatchery results verify`` — and these tests prove that on real runs,
including one copied outside the checkout with the analysis toolchain blocked.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from _results_builder import cli_json, make_run, manifest_hash, submit

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "scripts" / "verify_manifest.py"

BLOCKED_MODULES = ("click", "rich", "yara_x", "capa", "docker")


def _client(
    args: list[str], cwd: Path, *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=env,
    )


# ---------------------------------------------------------------------------
# 2. scripts/verify_manifest.py agrees with `results verify`
# ---------------------------------------------------------------------------


def _client(
    args: list[str], cwd: Path, *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=env,
    )


def test_the_client_verifier_agrees_with_results_verify(tmp_path: Path) -> None:
    intact = submit(tmp_path, "intact")
    modified = submit(tmp_path, "modified")
    (modified / "bundle" / "events.jsonl").write_text("changed\n", encoding="utf-8")
    missing = submit(tmp_path, "missing")
    (missing / "ocsf.json").unlink()
    unsealed = make_run(tmp_path / "results", "unsealed", sealed=False)
    anchored = submit(tmp_path, "anchored")
    anchored_hash = manifest_hash(anchored)
    replaced = submit(tmp_path, "replaced")

    cases: list[tuple[str, Path, list[str], int]] = [
        ("intact", intact, [], 0),
        ("modified", modified, [], 1),
        ("missing", missing, [], 1),
        ("unsealed", unsealed, [], 0),
        ("anchored", anchored, ["--expect-manifest", anchored_hash], 0),
        ("replaced", replaced, ["--expect-manifest", "0" * 64], 1),
    ]
    for name, run, extra, expected in cases:
        cli_code, cli_report = cli_json(
            ["results", "verify", str(run), "--json", *extra], tmp_path
        )
        client = _client([str(run), "--json", *extra], tmp_path)
        assert client.returncode == expected, name
        assert client.returncode == cli_code, name
        client_report = json.loads(client.stdout)

        assert set(client_report) == set(cli_report), (
            f"{name}: the recipient's tool must emit the same keys as `results verify`"
        )
        for key in ("ok", "state", "classification", "path", "manifest_sha256", "anchor"):
            assert client_report[key] == cli_report[key], f"{name}: {key}"


def test_the_client_verifier_runs_with_the_toolchain_blocked(tmp_path: Path) -> None:
    run = submit(tmp_path, "delivered")
    copied = tmp_path / "delivery" / "renamed-run"
    copied.parent.mkdir()
    shutil.copytree(run, copied)

    wrapper = r"""
import runpy, sys
blocked = set(sys.argv[1].split(","))
script, run = sys.argv[2], sys.argv[3]
class Blocker:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in blocked:
            raise ImportError("blocked for this test: " + name)
        return None
sys.meta_path.insert(0, Blocker())
try:
    import click
except ImportError:
    pass
else:  # the blocker itself must be proven, not assumed
    raise SystemExit("the import blocker is not in force")
sys.argv = ["verify_manifest.py", run, "--json"]
runpy.run_path(script, run_name="__main__")
"""
    env = dict(os.environ)
    env.pop("HATCHERY_SAMPLE_STORE", None)
    env.pop("HATCHERY_RESULTS_ROOT", None)
    env["HATCHERY_SAMPLE_STORE"] = str(tmp_path / "no-store-here")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            wrapper,
            ",".join(BLOCKED_MODULES),
            str(VERIFIER),
            str(copied),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=env,
    )
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    report = json.loads(result.stdout)
    assert report["state"] == "intact"
    assert report["run_dir"] == str(tmp_path / "delivery" / "renamed-run")


def test_the_client_verifier_is_a_usage_error_for_a_missing_path(
    tmp_path: Path,
) -> None:
    result = _client([str(tmp_path / "nope")], tmp_path)
    assert result.returncode == 2
    assert "not-found" in result.stderr
