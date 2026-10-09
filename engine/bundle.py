"""Canonical analysis bundle — the single source of truth for a run.

One run of HATCHERY produces exactly two machine-readable files:

  ``analysis.json``  the whole analysis document (metadata, static, sandbox,
                     IOCs, ATT&CK, summary, limitations)
  ``events.jsonl``   one normalized behavioral event per line

Everything downstream reads these. The CLI prints them, the API ingests them,
the dashboard renders them, and a future MISP/OCSF exporter maps them. There is
deliberately no second path that writes the same data somewhere else: the
previous revision had the Python engine writing files while the TypeScript
server read SQLite tables that nothing ever populated, so the dashboard showed
an empty interface over a working analysis.

The bundle also carries a ``limitations`` list. Every run states, in plain
language, what it did *not* establish: which isolation tier was in force, that
egress was blocked so C2 behavior cannot appear, that a missing syscall log
makes the run inconclusive. A sandbox that returns a verdict without its own
caveats is the thing this project exists to not be.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from engine.sandbox.isolation import IsolationTier, TIER_PROFILES

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"
ANALYSIS_FILENAME = "analysis.json"
EVENTS_FILENAME = "events.jsonl"


# ---------------------------------------------------------------------------
# Event normalisation
# ---------------------------------------------------------------------------


def events_from_strace(parse_result: Any) -> list[dict]:
    """Convert a :class:`StraceParseResult` into normalized event rows.

    Output shape matches the API's ``behavioral_events`` table so the ingest
    step is a straight copy.
    """
    rows: list[dict] = []
    for event in getattr(parse_result, "events", []) or []:
        rows.append(
            {
                "timestamp": event.timestamp,
                "pid": event.pid,
                "syscall_name": event.syscall,
                "category": event.category.value
                if hasattr(event.category, "value")
                else str(event.category),
                "severity": event.severity.value
                if hasattr(event.severity, "value")
                else str(event.severity),
                "args": json.dumps({"raw": event.args}),
                "return_value": event.return_value,
                "raw_line": f"{event.syscall}({event.args}) = {event.return_value}",
                "source": "strace",
                "indicators": list(getattr(event, "indicators", []) or []),
            }
        )
    return rows


def events_from_inotify(log_path: Optional[Path]) -> list[dict]:
    """Convert an inotifywait log into normalized file events.

    Expected line format: ``YYYY-MM-DDTHH:MM:SS /path/to/file EVENT[,EVENT]``
    """
    rows: list[dict] = []
    if not log_path or not log_path.exists():
        return rows

    severity_map = {
        "CREATE": "low",
        "MODIFY": "info",
        "DELETE": "medium",
        "MOVE": "low",
        "ATTRIB": "medium",
    }
    suspicious = ("/tmp/", "/dev/shm/", "/var/tmp/", ".bashrc", ".ssh", "/etc/cron")

    for line in log_path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 2)
        if len(parts) < 3:
            continue
        timestamp, path, kinds = parts[0], parts[1], parts[2]
        kind = kinds.split(",")[0] if kinds else "MODIFY"
        severity = severity_map.get(kind, "info")
        if any(marker in path for marker in suspicious):
            severity = "high"
        rows.append(
            {
                "timestamp": timestamp,
                "pid": 0,
                "syscall_name": kind,
                "category": "file",
                "severity": severity,
                "args": json.dumps({"path": path, "events": kinds}),
                "return_value": "",
                "raw_line": line,
                "source": "inotify",
                "indicators": [kinds] if severity == "high" else [],
            }
        )
    return rows


def events_from_network(net_result: Any) -> list[dict]:
    """Convert a :class:`NetworkCaptureResult` into normalized network events."""
    rows: list[dict] = []
    if net_result is None:
        return rows

    for conn in getattr(net_result, "connections", []) or []:
        dst_ip = getattr(conn, "dst_ip", "")
        dst_port = getattr(conn, "dst_port", 0)
        rows.append(
            {
                "timestamp": getattr(conn, "first_seen", "") or "",
                "pid": 0,
                "syscall_name": "connect",
                "category": "network",
                "severity": "medium",
                "args": json.dumps(
                    {
                        "src_ip": getattr(conn, "src_ip", ""),
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": getattr(conn, "protocol", "TCP"),
                    }
                ),
                "return_value": "",
                "raw_line": f"connect {dst_ip}:{dst_port}",
                "source": "pcap",
                "indicators": [f"{dst_ip}:{dst_port}"],
            }
        )

    for c2 in getattr(net_result, "c2_detections", []) or []:
        rows.append(
            {
                "timestamp": "",
                "pid": 0,
                "syscall_name": "c2_beacon",
                "category": "network",
                "severity": "critical",
                "args": json.dumps(
                    {
                        "dst_ip": getattr(c2, "dst_ip", ""),
                        "dst_port": getattr(c2, "dst_port", 0),
                        "score": getattr(c2, "score", None),
                    }
                ),
                "return_value": "",
                "raw_line": f"C2 beacon to {getattr(c2, 'dst_ip', '')}",
                "source": "pcap",
                "indicators": list(getattr(c2, "reasons", []) or []),
            }
        )
    return rows


def normalize_events(
    strace_result: Any = None,
    inotify_log: Optional[Path] = None,
    net_result: Any = None,
) -> list[dict]:
    """Merge every behavioral source into one chronological event list."""
    rows = (
        events_from_strace(strace_result)
        + events_from_inotify(inotify_log)
        + events_from_network(net_result)
    )
    rows.sort(key=lambda r: (r.get("timestamp") or "", r.get("source") or ""))
    return rows


# ---------------------------------------------------------------------------
# Limitations — the honesty engine
# ---------------------------------------------------------------------------


def compute_limitations(
    isolation: Optional[dict],
    sandbox: Optional[dict],
    artifacts: Optional[dict],
    events: list[dict],
    egress_blocked: bool = True,
) -> list[str]:
    """State plainly what this run does not establish.

    These strings are shown to the operator and stored in the bundle. They are
    the difference between "no malicious behavior observed" and a verdict.
    """
    limits: list[str] = []

    tier = IsolationTier(int((isolation or {}).get("tier", 0)))
    profile = TIER_PROFILES[tier]
    limits.append(f"Isolation tier {int(tier)} ({profile.name}): {profile.boundary}")
    if not profile.is_security_boundary:
        limits.append(
            f"No hardware boundary was in force. An attacker would need to defeat "
            f"only: {profile.escape_barrier}."
        )

    if egress_blocked:
        limits.append(
            "Network egress was blocked. Command-and-control contact, payload "
            "downloads and exfiltration cannot appear in this run by construction."
        )

    artifacts = artifacts or {}
    found = artifacts.get("found") or {}
    for key, consequence in (
        ("strace_log", "syscall-level behavior is unknown"),
        ("inotify_log", "filesystem changes are unknown"),
        ("pcap", "network behavior is unknown"),
    ):
        if key not in found:
            limits.append(f"No {key.replace('_', ' ')} was recovered — {consequence}.")

    if not events:
        limits.append(
            "This run produced no behavioral events at all. Treat it as "
            "INCONCLUSIVE, not as evidence of benign behavior."
        )

    if sandbox:
        if sandbox.get("status") == "timeout":
            limits.append(
                "The sample was still running when the timeout expired. Anything it "
                "did after that point was not observed."
            )
        if sandbox.get("error"):
            limits.append(f"Sandbox reported an error: {sandbox['error']}")

    limits.append(
        "A Linux guest cannot hide the host from the sample: kernel version, CPU "
        "count, RAM and uptime are readable via /proc at any isolation tier."
    )
    limits.append(
        "Dynamic analysis covers Linux ELF behavior only. Windows, macOS, document "
        "and script samples are analysed statically; see the static section."
    )
    return limits


# ---------------------------------------------------------------------------
# Bundle assembly
# ---------------------------------------------------------------------------


@dataclass
class AnalysisBundle:
    """Everything one analysis produced."""

    task_id: str
    sample: dict = field(default_factory=dict)
    isolation: Optional[dict] = None
    static: dict = field(default_factory=dict)
    sandbox: Optional[dict] = None
    iocs: list[dict] = field(default_factory=list)
    mitre: dict = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    generated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "generated_at": self.generated_at
            or datetime.now(timezone.utc).isoformat(),
            "sample": self.sample,
            "isolation": self.isolation,
            "static": self.static,
            "sandbox": self.sandbox,
            "iocs": self.iocs,
            "mitre": self.mitre,
            "limitations": self.limitations,
            "errors": self.errors,
            "summary": self.summary(),
        }

    def summary(self) -> dict:
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for row in self.events:
            by_category[row.get("category", "unknown")] = (
                by_category.get(row.get("category", "unknown"), 0) + 1
            )
            by_severity[row.get("severity", "info")] = (
                by_severity.get(row.get("severity", "info"), 0) + 1
            )

        yara_count = len((self.static.get("yara") or {}).get("matches") or [])
        capa_count = len((self.static.get("capa") or {}).get("capabilities") or [])
        high_iocs = [
            i for i in self.iocs if i.get("severity") in ("high", "critical")
        ]

        return {
            "events_total": len(self.events),
            "events_by_category": by_category,
            "events_by_severity": by_severity,
            "yara_matches": yara_count,
            "capa_capabilities": capa_count,
            "iocs_total": len(self.iocs),
            "iocs_high_or_critical": len(high_iocs),
            "techniques": (self.mitre or {}).get("technique_count", 0),
            "dynamic_analysis_performed": bool(self.sandbox),
            "inconclusive": not self.events,
        }


def write_bundle(run_dir: Path, bundle: AnalysisBundle) -> tuple[Path, Path]:
    """Write ``analysis.json`` and ``events.jsonl`` into ``run_dir``.

    Returns:
        ``(analysis_path, events_path)``
    """
    run_dir.mkdir(parents=True, exist_ok=True)

    analysis_path = run_dir / ANALYSIS_FILENAME
    analysis_path.write_text(
        json.dumps(bundle.to_dict(), indent=2, default=str), encoding="utf-8"
    )

    events_path = run_dir / EVENTS_FILENAME
    with events_path.open("w", encoding="utf-8") as handle:
        for row in bundle.events:
            handle.write(json.dumps(row, default=str) + "\n")

    logger.info(
        "Wrote bundle for task %s: %d events, %d IOCs",
        bundle.task_id, len(bundle.events), len(bundle.iocs),
    )
    return analysis_path, events_path


def load_bundle(run_dir: Path) -> dict:
    """Read ``analysis.json`` back, raising a clear error when absent."""
    path = run_dir / ANALYSIS_FILENAME
    if not path.exists():
        raise FileNotFoundError(f"No analysis bundle at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_events(run_dir: Path) -> list[dict]:
    """Read ``events.jsonl``, tolerating a trailing partial line."""
    path = run_dir / EVENTS_FILENAME
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning("Skipping malformed event line in %s", path)
    return rows


def render_limitations(limitations: list[str]) -> str:
    """Format the limitations block for terminal output."""
    if not limitations:
        return ""
    lines = ["", "What this run does NOT establish:"]
    lines.extend(f"  - {item}" for item in limitations)
    return "\n".join(lines)
