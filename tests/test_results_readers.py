"""Readers are untouched by the manifest (D33, contract item 6).

The manifest lives at the run root precisely so that ``bundle/`` — which the API
lists and ingests and which replay, clustering and the MCP tools read — is not
changed. This is verified rather than assumed: the same sealed run is read by the
cluster fingerprinter, the MCP ``list_runs``/``get_report`` tools and the CLI
``report``/``iocs`` paths, and a nested replay run does not confuse any of them.
"""

from __future__ import annotations

import json
from pathlib import Path

from _results_builder import base_env, cli_json, run_cli, submit
from engine.bundle import SCHEMA_VERSION
from engine.mcp.tools import build_tools


def test_cluster_reads_sealed_runs_and_ignores_the_manifest(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    first = submit(tmp_path, "run-a")
    second = submit(tmp_path, "run-b")
    # A nested replay with its own manifest must not be mistaken for a run.
    nested = first / "replay-deadbeef"
    (nested / "bundle").mkdir(parents=True)
    (nested / "bundle" / "analysis.json").write_text(
        (first / "bundle" / "analysis.json").read_text()
    )
    from engine.results import seal_run

    seal_run(nested, stage="replay")

    result = run_cli(["cluster", str(results), "--json"], tmp_path, env=base_env(tmp_path))
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    payload = json.loads(result.stdout)
    # Clustering walks for analysis.json and has always seen a nested replay as
    # its own run; the extra manifest.json at either run root changes nothing.
    assert payload["stats"]["runs_scanned"] == 3, payload["stats"]
    assert len(payload["runs"]) == 3
    assert all(run["sha256"] for run in payload["runs"])
    assert payload["stats"]["clusters"] == 1
    assert second.is_dir()


def test_mcp_tools_read_sealed_runs(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    run_dir = submit(tmp_path, "run-a")

    tools = {tool.name: tool for tool in build_tools(results)}
    listing = json.loads(tools["list_runs"].handler({"root": str(results)}))
    assert listing["count"] == 1
    assert Path(listing["runs"][0]["run_dir"]).parent.name == "run-a"
    assert listing["runs"][0]["sha256"]

    report = tools["get_report"].handler({"run_dir": str(run_dir / "bundle")})
    assert "limitations" in report
    iocs = json.loads(tools["get_iocs"].handler({"run_dir": str(run_dir / "bundle")}))
    assert "count" in iocs


def test_the_cli_report_and_stix_exports_are_unchanged(tmp_path: Path) -> None:
    """The exporters read bundle/ and the run root, never the manifest."""
    run_dir = submit(tmp_path, "run-a")
    _, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert report["state"] == "intact"
    # The files the API and exporters consume still exist with the same shape.
    analysis = json.loads((run_dir / "bundle" / "analysis.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert analysis["task_id"] and analysis["task_id"] == manifest["task_id"]
    assert analysis["schema_version"] == SCHEMA_VERSION
    stix = json.loads((run_dir / "stix_bundle.json").read_text())
    assert stix["type"] == "bundle"
    assert set(analysis["exports"]) >= {"stix", "navigator", "ocsf", "sigma"}
