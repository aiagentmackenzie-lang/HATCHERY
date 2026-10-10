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

from engine.sandbox.isolation import IsolationTier, TIER_GUEST_TELLS, TIER_PROFILES

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"
ANALYSIS_FILENAME = "analysis.json"
EVENTS_FILENAME = "events.jsonl"
# Emulated events are a separate stream: a run of an emulator is not a run of
# the sample, and mixing them into events.jsonl would imply the sample did it
# natively (D4).
EMULATION_EVENTS_FILENAME = "emulation-events.jsonl"
# The advisory LLM triage section, kept beside the bundle so it is never confused
# with the engine's own findings (D22).
TRIAGE_FILENAME = "triage.json"
# Interoperable exports written alongside the bundle, by the same engine run.
EXPORT_FILENAMES: dict[str, str] = {
    "stix": "stix_bundle.json",
    "navigator": "attack-navigator.json",
    "ocsf": "ocsf.json",
    "sigma": "sigma-candidates",
}


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


def events_from_gvisor(parse_result: Any) -> list[dict]:
    """Convert a :class:`GvisorParseResult` into normalized event rows.

    Same row shape as every other source; only ``source`` differs
    (``gvisor-sentry``), so downstream consumers need no second code path.
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
                "args": json.dumps(
                    {
                        "raw": event.args,
                        "paths": list(getattr(event, "paths", []) or []),
                    }
                ),
                "return_value": event.return_value,
                "raw_line": f"{event.syscall}({event.args}) = {event.return_value}",
                "source": "gvisor-sentry",
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
    evasion_events: Optional[list[dict]] = None,
    gvisor_result: Any = None,
) -> list[dict]:
    """Merge every behavioral source into one chronological event list.

    ``evasion_events`` come from :func:`engine.monitor.evasion.analyze_evasion`
    and carry ``category="evasion"``. ``gvisor_result`` comes from
    :class:`engine.monitor.gvisor_strace.GvisorStraceParser` and carries
    ``source="gvisor-sentry"``. They are normalised rows like every other
    source, so the API and dashboard consume them without a second path.
    """
    rows = (
        events_from_strace(strace_result)
        + events_from_gvisor(gvisor_result)
        + events_from_inotify(inotify_log)
        + events_from_network(net_result)
        + list(evasion_events or [])
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
    evasion: Optional[dict] = None,
    delivery: Optional[dict] = None,
    emulation: Optional[dict] = None,
    triage: Optional[dict] = None,
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
    has_gvisor_trace = bool((sandbox or {}).get("gvisor_trace_log"))
    for key, consequence in (
        ("strace_log", "syscall-level behavior is unknown"),
        ("inotify_log", "filesystem changes are unknown"),
        ("pcap", "network behavior is unknown"),
    ):
        if key in found:
            continue
        if key == "strace_log" and has_gvisor_trace:
            limits.append(
                "The in-guest strace log was not recovered through the tier-2 output "
                "volume. Syscall behaviour comes from the gVisor Sentry trace instead."
            )
            continue
        limits.append(f"No {key.replace('_', ' ')} was recovered — {consequence}.")

    for problem in artifacts.get("errors") or []:
        limits.append(f"Artifact recovery problem: {problem}")

    if not events:
        limits.append(
            "This run produced no native behavioral events. Treat it as "
            "INCONCLUSIVE, not as evidence of benign behavior."
        )

    # Delivery-format intake. A container that was detected but not unpacked is
    # a finding, not a clean run: the silent "no findings" this project exists
    # to eliminate (D19). Extracted children are analysed statically and are
    # not detonated, and the run says so.
    if delivery and delivery.get("format") not in (None, "unknown", "macho"):
        fmt = delivery.get("format")
        children = delivery.get("children") or []
        unsupported = delivery.get("unsupported") or []
        if children:
            if sandbox:
                limits.append(
                    f"Delivery container ({fmt}) was unpacked: {len(children)} "
                    "file(s) extracted and analysed statically. Only the top-level "
                    "sample was detonated; extracted children were not executed."
                )
            else:
                limits.append(
                    f"Delivery container ({fmt}) was unpacked: {len(children)} "
                    "file(s) extracted and analysed statically. Nothing was "
                    "executed."
                )
        elif unsupported:
            limits.append(
                f"Delivery container ({fmt}) was detected but not unpacked. Its "
                "contents were not inspected beyond a raw byte/string scan."
            )
        for item in unsupported:
            limits.append(
                f"Delivery format {item.get('format')} at {item.get('path')} "
                f"was not extracted: {item.get('reason')}"
            )
        if delivery.get("truncated"):
            limits.append(
                "Delivery extraction stopped at a configured limit; the "
                "extracted file list is incomplete."
            )
        for problem in delivery.get("errors") or []:
            limits.append(f"Delivery intake problem: {problem}")

    # Evasion is a finding in its own right, and an evasive run that produced
    # no impact is inconclusive rather than clean. This is the difference the
    # project exists to make.
    if evasion:
        verdict = str(evasion.get("verdict", "none"))
        score = int(evasion.get("score", 0))
        signals = evasion.get("signals") or []
        if evasion.get("inconclusive"):
            limits.append(
                f"Evasion score {score}/100 ({verdict}); signals: "
                f"{', '.join(signals) or 'none'}. The sample reconnoitered and "
                "then exited without observable impact. Treat this run as "
                "INCONCLUSIVE (evasive), not clean."
            )
        elif verdict in ("evasive", "suspicious"):
            limits.append(
                f"Evasion score {score}/100 ({verdict}); signals: "
                f"{', '.join(signals) or 'none'}. Environment reconnaissance was "
                "observed; the sample may be adapting to the analysis environment."
            )
        limits.append(
            "RDTSC/CPUID and vDSO clock reads are CPU/userspace operations and "
            "are not visible to ptrace-based syscall tracing at this tier."
        )

    if sandbox:
        monitoring = sandbox.get("monitoring") or {}
        if monitoring:
            blind = monitoring.get("blind_spots") or []
            limits.append(
                f"Behaviour was observed with {monitoring.get('collector', 'unknown')} "
                f"({monitoring.get('location', 'unknown')}). It cannot see: "
                + "; ".join(blind)
            )
            if monitoring.get("downgrade_reason"):
                limits.append(str(monitoring["downgrade_reason"]))
            attribution = monitoring.get("trace_attribution") or {}
            if attribution:
                if attribution.get("attributed"):
                    limits.append(
                        "Behaviour was attributed to the sample's process subtree "
                        f"(root PID {attribution.get('sample_root_pid')}): "
                        f"{attribution.get('included')} events kept, "
                        f"{attribution.get('excluded')} entrypoint/monitor events "
                        "excluded before scoring."
                    )
                else:
                    limits.append(
                        "Sample-subtree attribution failed, so this trace is "
                        "container-wide: " + str(attribution.get("reason", ""))
                    )
        if sandbox.get("status") == "timeout":
            limits.append(
                "The sample was still running when the timeout expired. Anything it "
                "did after that point was not observed."
            )
        if sandbox.get("error"):
            limits.append(f"Sandbox reported an error: {sandbox['error']}")

    limits.append(f"Guest-profile tells at tier {int(tier)}: {TIER_GUEST_TELLS[tier]}")
    if emulation and emulation.get("available"):
        limits.append(
            "Dynamic analysis covers Linux ELF behavior natively. Windows PE samples "
            "are analysed statically and, when emulation is enabled, inside an "
            "emulator (their instructions are interpreted, not executed)."
        )
    else:
        limits.append(
            "Dynamic analysis covers Linux ELF behavior only. Windows, macOS, document "
            "and script samples are analysed statically; see the static section."
        )

    _emulation_limitations(emulation, limits)
    _triage_limitations(triage, limits)
    return limits


def _emulation_limitations(emulation: Optional[dict], limits: list[str]) -> None:
    """State what an emulation stage did and did not establish (D21).

    An empty emulation report on a Windows PE is *not established*, never
    benign. A crash, a wall-clock timeout, or an unimplemented API handler is
    INCONCLUSIVE — the D3 rule applied to the emulation collector.
    """
    if not emulation:
        return

    if not emulation.get("available"):
        reason = emulation.get("reason") or "not run"
        limits.append(f"Emulation was not run: {reason}")
        return

    version = emulation.get("emulator_version") or "unknown"
    schema = str(emulation.get("schema_hash") or "")[:12]
    limits.append(
        f"Windows PE emulation used {emulation.get('emulator', 'speakeasy')} "
        f"{version} (report schema {schema or 'unknown'}). Its instructions were "
        "interpreted by a software CPU and its Windows APIs emulated in Python; "
        "the sample did not execute natively. Emulation is not an isolation "
        "boundary and its results are not ground truth."
    )
    limits.append(
        "Emulation blind spots: APIs the emulator does not implement, emulator "
        "detection by the sample, and the emulated network (attempts are recorded; "
        "no real connection is made)."
    )

    status = str(emulation.get("status") or "")
    unsupported = emulation.get("unsupported_apis") or []
    if unsupported:
        limits.append(
            "Emulation was INCONCLUSIVE: the sample reached API(s) the emulator does "
            f"not implement ({', '.join(map(str, unsupported))}) and emulation stopped "
            "there. Behaviour after that point is unknown."
        )
    if status == "timeout":
        limits.append(
            "Emulation was stopped at the wall-clock/time cap. Anything the sample "
            "would have done after that point was not observed."
        )
    if status in ("error", "unavailable") and emulation.get("error"):
        limits.append(f"Emulation reported a problem: {emulation['error']}")

    if status == "completed" and not unsupported:
        events_written = int(emulation.get("events_written") or 0)
        api_calls = int(emulation.get("api_calls") or 0)
        if api_calls == 0:
            limits.append(
                "The emulator produced no API calls for this sample. Treat the "
                "emulation result as NOT ESTABLISHED, never as evidence of benign "
                "behaviour."
            )
        config = emulation.get("config") or {}
        endpoints = config.get("network_endpoints") or []
        persistence = config.get("registry_persistence") or []
        limits.append(
            f"Emulation observed {api_calls} API call(s) and wrote {events_written} "
            f"event(s); extracted {len(endpoints)} network endpoint(s), "
            f"{len(persistence)} persistence key(s)."
        )
    snapshots = emulation.get("snapshots") or {}
    if snapshots:
        available = int(
            snapshots.get("regions_available") or snapshots.get("regions_selected") or 0
        )
        limits.append(
            "capa_dynamic is static capa run over the emulator's captured memory "
            f"snapshots ({int(snapshots.get('regions_decoded') or 0)} decoded of "
            f"{available} candidate region(s); capa ran on "
            f"{int(snapshots.get('capa_regions') or 0)}) — "
            "not a Speakeasy-to-CAPE conversion, which is deliberately not done."
        )
        if snapshots.get("truncated"):
            limits.append(
                "Memory-snapshot analysis stopped at a configured bound; only part "
                "of the captured memory was scanned."
            )
        for problem in (snapshots.get("errors") or [])[:3]:
            limits.append(f"Memory-snapshot problem: {problem}")


def _triage_limitations(triage: Optional[dict], limits: list[str]) -> None:
    """State what the LLM triage layer did and did not establish (D22).

    Triage is advisory and model-generated. It must never read as a verdict the
    engine reached, and a triage that failed is stated as a failure rather than
    as an absence of findings.
    """
    if not triage:
        return

    if not triage.get("available"):
        status = str(triage.get("status") or "unavailable")
        reason = str(triage.get("reason") or "not run")
        if status == "unavailable":
            limits.append(f"AI triage was not run: {reason}")
        else:
            limits.append(f"AI triage did not produce a verdict ({status}): {reason}")
        return

    model = triage.get("model") or "unknown"
    version = triage.get("prompt_version") or "?"
    digest = str(triage.get("contract_hash") or "")[:12]
    limits.append(
        f"AI triage is advisory and model-generated (local model {model}, prompt "
        f"contract {version}/{digest}). It summarises the evidence below; it is not "
        "ground truth and it does not replace the engine's findings."
    )
    if triage.get("allowed_remote") or triage.get("allowed_cloud_model"):
        limits.append(
            "AI triage was permitted to use a remote endpoint or a `:cloud` model: "
            "sample-derived text left this machine. This is not the default and is "
            "flagged here on purpose."
        )
    limits.append(
        f"Triage verdict: {triage.get('verdict')} (model confidence "
        f"{int(triage.get('confidence') or 0)}/100), grounded in "
        f"{len(triage.get('findings') or [])} finding(s) over "
        f"{int(triage.get('evidence_ids') or 0)} citable evidence item(s)."
    )
    dropped = int(triage.get("findings_dropped") or 0)
    if dropped:
        limits.append(
            f"AI triage dropped {dropped} finding(s) that cited evidence not present "
            "in this run; the verdict reflects only what could be grounded."
        )
    techniques = triage.get("techniques") or []
    if techniques:
        limits.append(
            "AI triage proposed ATT&CK technique(s) "
            f"({', '.join(map(str, techniques))}) that exist in the pinned dataset, "
            "but the observation-to-technique association is model-suggested and "
            "unvalidated — validating an id is not proving the association."
        )
    if triage.get("evidence_truncated"):
        limits.append(
            "The triage evidence set was truncated to fit the model context; the "
            "model did not see every event."
        )


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
    evasion: Optional[dict] = None
    emulation: Optional[dict] = None
    triage: Optional[dict] = None
    events: list[dict] = field(default_factory=list)
    emulation_events: list[dict] = field(default_factory=list)
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
            "evasion": self.evasion,
            "emulation": self.emulation,
            "triage": self.triage,
            "limitations": self.limitations,
            "errors": self.errors,
            "exports": dict(EXPORT_FILENAMES),
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
        delivery = self.static.get("delivery") or {}
        emulation = self.emulation or {}
        emulation_config = emulation.get("config") or {}
        emulation_snapshots = emulation.get("snapshots") or {}
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
            "delivery_format": delivery.get("format"),
            "delivery_children": len(delivery.get("children") or []),
            "delivery_unsupported": len(delivery.get("unsupported") or []),
            "inconclusive": not self.events,
            "evasion_score": int((self.evasion or {}).get("score", 0)),
            "evasion_verdict": (self.evasion or {}).get("verdict", "none"),
            "evasion_signals": (self.evasion or {}).get("signals", []),
            "evasive": (self.evasion or {}).get("verdict") in ("evasive", "suspicious"),
            "evasion_inconclusive": bool((self.evasion or {}).get("inconclusive", False)),
            "emulation_available": bool(emulation.get("available", False)),
            "emulation_status": emulation.get("status"),
            "emulation_events": len(self.emulation_events),
            "emulation_api_calls": int(emulation.get("api_calls") or 0),
            "emulation_endpoints": len(emulation_config.get("network_endpoints") or []),
            "emulation_persistence": len(emulation_config.get("registry_persistence") or []),
            "emulation_regions": int(emulation_snapshots.get("regions_decoded") or 0),
            "capa_dynamic_capabilities": len(
                (emulation.get("capa_dynamic") or {}).get("capabilities") or []
            ),
            "emulation_inconclusive": bool(emulation.get("available"))
            and (
                emulation.get("status") != "completed"
                or bool(emulation.get("unsupported_apis"))
                or int(emulation.get("api_calls") or 0) == 0
            ),
            "triage_available": bool((self.triage or {}).get("available", False)),
            "triage_status": (self.triage or {}).get("status"),
            "triage_model": (self.triage or {}).get("model"),
            "triage_verdict": (self.triage or {}).get("verdict"),
            "triage_confidence": int((self.triage or {}).get("confidence") or 0),
            "triage_findings": len((self.triage or {}).get("findings") or []),
            "triage_findings_dropped": int((self.triage or {}).get("findings_dropped") or 0),
            "triage_techniques": len((self.triage or {}).get("techniques") or []),
            "triage_inconclusive": bool((self.triage or {}).get("inconclusive", True)),
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

    # Emulated events are a separate stream (D4). The file always exists when
    # emulation produced anything, so its absence is meaningful too.
    emulation_events_path = run_dir / EMULATION_EVENTS_FILENAME
    with emulation_events_path.open("w", encoding="utf-8") as handle:
        for row in bundle.emulation_events:
            handle.write(json.dumps(row, default=str) + "\n")

    logger.info(
        "Wrote bundle for task %s: %d events, %d emulated events, %d IOCs",
        bundle.task_id, len(bundle.events), len(bundle.emulation_events), len(bundle.iocs),
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


def write_triage(run_dir: Path, section: dict) -> Path:
    """Write ``triage.json`` next to the bundle. Returns the path."""
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / TRIAGE_FILENAME
    path.write_text(json.dumps(section, indent=2, default=str), encoding="utf-8")
    return path


def attach_triage(run_dir: Path, section: dict) -> Path:
    """Attach a triage section to an existing bundle in place.

    Used by the standalone ``hatchery triage`` command: the bundle is the single
    source of truth, so triage patches ``analysis.json`` (and its ``summary``
    counters) rather than living only in a side file the API never reads. The
    ``triage.json`` side file is written too, for convenience.
    """
    path = run_dir / ANALYSIS_FILENAME
    if not path.exists():
        raise FileNotFoundError(f"No analysis bundle at {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["triage"] = section
    summary = data.get("summary")
    if isinstance(summary, dict):
        summary.update(
            {
                "triage_available": bool(section.get("available", False)),
                "triage_status": section.get("status"),
                "triage_model": section.get("model"),
                "triage_verdict": section.get("verdict"),
                "triage_confidence": int(section.get("confidence") or 0),
                "triage_findings": len(section.get("findings") or []),
                "triage_findings_dropped": int(section.get("findings_dropped") or 0),
                "triage_techniques": len(section.get("techniques") or []),
                "triage_inconclusive": bool(section.get("inconclusive", True)),
            }
        )
    limits = data.get("limitations")
    if isinstance(limits, list):
        for line in section.get("limitations") or []:
            if line not in limits:
                limits.append(line)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    write_triage(run_dir, section)
    return path
