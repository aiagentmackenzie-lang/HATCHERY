"""Tools HATCHERY exposes over MCP (D24).

Each tool is a thin wrapper over work the engine already does; no tool
re-implements analysis. The MCP server runs **locally over stdio**, so it
inherits the operator's privileges — it is not a remote service and must never be
exposed on a socket. Paths are validated to exist and reads are limited to a run
directory's own files, so a tool call cannot be turned into an arbitrary file
read.

``submit_sample`` shells out to the existing CLI rather than duplicating the
pipeline, keeping one producer of analysis data (D4).
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from engine.bundle import ANALYSIS_FILENAME, attach_triage, load_bundle

DEFAULT_RESULTS_ROOT = Path("results")


class ToolError(RuntimeError):
    """A tool could not complete. Reported to the client as an MCP tool error."""


def _resolve_run_dir(raw: Any) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ToolError("run_dir is required and must be a path to an analysed run")
    path = Path(raw.strip()).expanduser()
    if not path.exists():
        raise ToolError(f"run directory does not exist: {path}")
    if not (path / ANALYSIS_FILENAME).exists():
        raise ToolError(f"no analysis.json in {path} — is this a HATCHERY run directory?")
    return path


def _resolve_roots(raw: Any, default: Path) -> Path:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return default
    if not isinstance(raw, str):
        raise ToolError("root must be a path string")
    path = Path(raw.strip()).expanduser()
    if not path.exists():
        raise ToolError(f"results root does not exist: {path}")
    return path


def _json_text(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str)


@dataclass
class Tool:
    """One MCP tool: a descriptor plus the callable behind it."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], str]

    def descriptor(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


def build_tools(results_root: Path = DEFAULT_RESULTS_ROOT) -> list[Tool]:
    """The tool registry. ``results_root`` is the default corpus for read tools."""

    def list_runs(arguments: dict[str, Any]) -> str:
        from engine.cluster.fingerprint import find_run_dirs

        root = _resolve_roots(arguments.get("root"), results_root)
        runs: list[dict[str, Any]] = []
        for run_dir in find_run_dirs(root):
            try:
                bundle = load_bundle(run_dir)
            except (OSError, ValueError):
                continue
            sample = bundle.get("sample") or {}
            summary = bundle.get("summary") or {}
            runs.append(
                {
                    "run_dir": str(run_dir),
                    "task_id": bundle.get("task_id"),
                    "file_name": sample.get("file_name"),
                    "sha256": sample.get("sha256"),
                    "events_total": summary.get("events_total"),
                    "triage_verdict": (bundle.get("triage") or {}).get("verdict"),
                    "triage_available": bool((bundle.get("triage") or {}).get("available")),
                }
            )
        return _json_text({"root": str(root), "count": len(runs), "runs": runs})

    def get_report(arguments: dict[str, Any]) -> str:
        run_dir = _resolve_run_dir(arguments.get("run_dir"))
        fmt = str(arguments.get("format") or "json").lower()
        if fmt == "json":
            return _json_text(load_bundle(run_dir))
        if fmt == "triage":
            bundle = load_bundle(run_dir)
            triage = bundle.get("triage")
            if not triage:
                raise ToolError("this run has no triage section; call triage_run first")
            return _json_text(triage)
        if fmt == "stix":
            path = run_dir / "stix_bundle.json"
            if not path.exists():
                raise ToolError("this run has no stix_bundle.json")
            return path.read_text(encoding="utf-8")
        if fmt in ("markdown", "md"):
            path = run_dir / "report.md"
            if not path.exists():
                raise ToolError("this run has no report.md")
            return path.read_text(encoding="utf-8")
        raise ToolError(f"unknown format {fmt!r}; use json, markdown, triage or stix")

    def get_iocs(arguments: dict[str, Any]) -> str:
        run_dir = _resolve_run_dir(arguments.get("run_dir"))
        bundle = load_bundle(run_dir)
        iocs = bundle.get("iocs") or []
        counts: dict[str, int] = {}
        for ioc in iocs:
            if isinstance(ioc, dict):
                counts[str(ioc.get("type") or "unknown")] = (
                    counts.get(str(ioc.get("type") or "unknown"), 0) + 1
                )
        return _json_text({"count": len(iocs), "by_type": counts, "iocs": iocs})

    def triage_run(arguments: dict[str, Any]) -> str:
        from engine.triage.triage import TriageConfig, run_triage

        run_dir = _resolve_run_dir(arguments.get("run_dir"))
        bundle = load_bundle(run_dir)
        events = _load_events(run_dir)
        config = TriageConfig.from_env()
        model = arguments.get("model")
        if isinstance(model, str) and model.strip():
            config.model = model.strip()
        # The MCP tool never opts into a remote model: that stays an explicit
        # operator decision at the CLI, never something an agent can turn on.
        section = run_triage(bundle, events, config=config)
        attach_triage(run_dir, section)
        return _json_text(section)

    def cluster_runs(arguments: dict[str, Any]) -> str:
        from engine.cluster.cluster import build_clusters

        root = _resolve_roots(arguments.get("root"), results_root)
        threshold = arguments.get("threshold", 0.5)
        min_size = arguments.get("min_size", 2)
        try:
            threshold_value = float(threshold)
            min_size_value = int(min_size)
        except (TypeError, ValueError) as exc:
            raise ToolError(f"threshold must be a number and min_size an integer: {exc}") from exc
        clusters, fingerprints, stats = build_clusters(
            root, threshold=threshold_value, min_size=min_size_value
        )
        return _json_text(
            {
                "root": str(root),
                "stats": stats,
                "clusters": [cluster.to_dict() for cluster in clusters],
                "runs": [fingerprint.to_dict() for fingerprint in fingerprints],
            }
        )

    def submit_sample(arguments: dict[str, Any]) -> str:
        raw = arguments.get("path")
        if not isinstance(raw, str) or not raw.strip():
            raise ToolError("path is required")
        sample = Path(raw.strip()).expanduser()
        if not sample.exists() or not sample.is_file():
            raise ToolError(f"sample does not exist: {sample}")

        out_dir = results_root / f"mcp-{uuid.uuid4().hex[:12]}"
        command = [sys.executable, "-m", "engine.cli", "submit", str(sample), "-o", str(out_dir)]
        # Static by default: an MCP client must not silently trigger a detonation.
        if arguments.get("no_sandbox", True):
            command.append("--no-sandbox")
        if arguments.get("triage"):
            command.append("--triage")
        timeout = arguments.get("timeout", 600)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=float(timeout),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"analysis did not finish within {timeout}s") from exc

        bundle_dir = out_dir / "bundle"
        if not (bundle_dir / ANALYSIS_FILENAME).exists():
            tail = (completed.stderr or completed.stdout or "")[-600:]
            raise ToolError(f"analysis produced no bundle (exit {completed.returncode}): {tail}")
        bundle = load_bundle(bundle_dir)
        return _json_text(
            {
                "run_dir": str(bundle_dir),
                "task_id": bundle.get("task_id"),
                "summary": bundle.get("summary"),
                "limitations": bundle.get("limitations"),
            }
        )

    return [
        Tool(
            name="list_runs",
            description=(
                "List analysed runs under a results root, with each run's file name, "
                "hash, event count and triage verdict."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "root": {"type": "string", "description": "Results root (default: results/)"}
                },
            },
            handler=list_runs,
        ),
        Tool(
            name="get_report",
            description=(
                "Return one run's report: the full analysis bundle (json), the "
                "Markdown report, the advisory triage section, or the STIX bundle."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "run_dir": {"type": "string", "description": "Path to a run directory"},
                    "format": {
                        "type": "string",
                        "enum": ["json", "markdown", "triage", "stix"],
                        "description": "Which report to return (default: json)",
                    },
                },
                "required": ["run_dir"],
            },
            handler=get_report,
        ),
        Tool(
            name="get_iocs",
            description="Return a run's indicators of compromise, grouped by type.",
            input_schema={
                "type": "object",
                "properties": {
                    "run_dir": {"type": "string", "description": "Path to a run directory"}
                },
                "required": ["run_dir"],
            },
            handler=get_iocs,
        ),
        Tool(
            name="triage_run",
            description=(
                "Run local LLM triage over an existing run and return the advisory, "
                "grounded verdict. Uses a local model only."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "run_dir": {"type": "string", "description": "Path to a run directory"},
                    "model": {"type": "string", "description": "Ollama model (optional)"},
                },
                "required": ["run_dir"],
            },
            handler=triage_run,
        ),
        Tool(
            name="cluster_runs",
            description=(
                "Group analysed runs that look like the same campaign and return the "
                "clusters, their shared features and the fingerprints."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "root": {"type": "string", "description": "Results root (default: results/)"},
                    "threshold": {"type": "number", "description": "Similarity threshold (0-1)"},
                    "min_size": {"type": "integer", "description": "Smallest cluster to report"},
                },
            },
            handler=cluster_runs,
        ),
        Tool(
            name="submit_sample",
            description=(
                "Analyse a local sample file. Static-only by default; set "
                "no_sandbox=false to detonate (needs Docker) and triage=true to add "
                "local LLM triage."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the sample file"},
                    "no_sandbox": {"type": "boolean", "description": "Static only (default true)"},
                    "triage": {"type": "boolean", "description": "Also run local LLM triage"},
                    "timeout": {"type": "integer", "description": "Seconds before giving up"},
                },
                "required": ["path"],
            },
            handler=submit_sample,
        ),
    ]


def _load_events(run_dir: Path) -> list[dict[str, Any]]:
    from engine.bundle import load_events

    return load_events(run_dir)


__all__ = ["DEFAULT_RESULTS_ROOT", "Tool", "ToolError", "build_tools"]
