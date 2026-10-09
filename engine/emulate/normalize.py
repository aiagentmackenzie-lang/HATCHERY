"""Normalise emulated API/behaviour events into HATCHERY's event row shape.

Emulated events are a **separate stream** from native sandbox events: they are
written to ``emulation-events.jsonl``, never mixed into ``events.jsonl`` (one
producer per data path, D4). A row carries ``source="emulation"`` so a consumer
can always tell that it came from an emulator, not from a real detonation.

The row shape matches every other source in ``engine.bundle`` so the API and
dashboard can consume it without a second code path.
"""

from __future__ import annotations

import json
import logging

from engine.emulate.report import (
    FILE_EVENTS,
    MEMORY_EVENTS,
    PROCESS_EVENTS,
    REGISTRY_EVENTS,
    EmulationReport,
)

logger = logging.getLogger(__name__)

CATEGORY_BY_EVENT: dict[str, str] = {
    "api": "api",
    "net_dns": "network",
    "net_http": "network",
    "net_traffic": "network",
}
for _event in REGISTRY_EVENTS:
    CATEGORY_BY_EVENT[_event] = "registry"
for _event in FILE_EVENTS:
    CATEGORY_BY_EVENT[_event] = "file"
for _event in PROCESS_EVENTS:
    CATEGORY_BY_EVENT[_event] = "process"
for _event in MEMORY_EVENTS:
    CATEGORY_BY_EVENT[_event] = "memory"

SEVERITY_BY_EVENT: dict[str, str] = {
    "net_http": "high",
    "net_traffic": "high",
    "net_dns": "medium",
    "reg_write_value": "high",
    "reg_create_key": "medium",
    "file_write": "medium",
    "file_create": "low",
    "process_create": "high",
    "thread_inject": "high",
}


def _summarise(kind: str, event: dict) -> str:
    if kind == "api":
        args = ", ".join(str(a) for a in (event.get("args") or []))
        return f"{event.get('api_name', '')}({args})"
    for field in ("path", "query", "server", "name"):
        if event.get(field):
            return f"{kind} {event[field]}"
    return kind


def normalize_emulation_events(report: EmulationReport) -> list[dict]:
    """Convert a parsed report's events into normalised event rows."""
    rows: list[dict] = []
    for event in report.events:
        kind = str(event.get("event") or "unknown")
        pos = event.get("pos") or {}
        pid = pos.get("pid") if isinstance(pos, dict) else None
        tid = pos.get("tid") if isinstance(pos, dict) else None

        category = CATEGORY_BY_EVENT.get(kind, "system")
        if kind == "file_write":
            severity = "high" if str(event.get("path", "")).lower().startswith(("c:\\windows", "c:\\programdata")) else "medium"
        else:
            severity = SEVERITY_BY_EVENT.get(kind, "info")

        args = {k: v for k, v in event.items() if k not in ("pos", "event")}
        indicators: list[str] = []
        if kind in ("net_http", "net_traffic") and event.get("server"):
            indicators.append(f"{event.get('server')}:{event.get('port', 0)}")
        elif kind == "net_dns" and event.get("query"):
            indicators.append(str(event["query"]))
        elif kind in ("reg_write_value", "reg_create_key") and event.get("path"):
            indicators.append(str(event["path"]))

        rows.append(
            {
                "timestamp": "",
                "pid": pid,
                "tid": tid,
                "syscall_name": str(event.get("api_name") or kind),
                "category": category,
                "severity": severity,
                "args": json.dumps(args, default=str),
                "return_value": str(event.get("ret_val") or ""),
                "raw_line": _summarise(kind, event),
                "source": "emulation",
                "indicators": indicators,
                "event_type": kind,
            }
        )
    return rows
