"""Extract configuration and indicators from an emulated Speakeasy run.

This is the deliverable analysts actually want from Windows emulation: the
configuration a packed sample only produces at runtime — C2 endpoints, user
agents, mutexes, registry persistence and dropped files — plus the API surface
the emulator observed.

Input is the *report*, not the sample. The report already resolves API string
arguments (Speakeasy dereferences pointers into the emulated address space), so
``CreateMutexA(..., "HatcheryMutex")`` arrives as a readable argument rather
than an opaque hex pointer. What is extracted is what the emulator observed; if
the emulator never reached a decryption routine, nothing here invents it.

Nothing here executes anything and nothing imports ``speakeasy``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import Counter
from typing import Any

from engine.emulate.report import EmulationReport

logger = logging.getLogger(__name__)

URL_RE = re.compile(r"https?://[^\s\"'<>\]\)]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)

# Registry paths that mean "this runs again after a reboot / at logon".
PERSISTENCE_MARKERS = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\currentversion\\runservices",
    "\\winlogon",
    "\\services\\",
    "\\startup",
    "\\schedule\\taskcache",
)

MUTEX_API_SUFFIXES = ("createmutexa", "createmutexw", "openmutexa", "openmutexw")
USER_AGENT_API_SUFFIXES = ("internetopena", "internetopenw")


def _api_suffix(api_name: str) -> str:
    return api_name.rsplit(".", 1)[-1].lower()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _endpoint_is_routable(server: str) -> bool:
    """False for loopback/empty so we do not report the emulator's own host."""
    if not server:
        return False
    if _is_ip(server):
        try:
            return not ipaddress.ip_address(server).is_loopback
        except ValueError:
            return True
    return True


def _add_dedup(target: list[dict], item: dict, key: str) -> None:
    if item.get(key) and not any(existing.get(key) == item.get(key) for existing in target):
        target.append(item)


def _add_dedup_str(target: list[str], value: str) -> None:
    if value and value not in target:
        target.append(value)


def extract_config(report: EmulationReport) -> dict:
    """Pull C2 endpoints, mutexes, persistence and dropped files from a report."""
    endpoints: list[dict] = []
    dns_queries: list[dict] = []
    http_events: list[dict] = []
    user_agents: list[str] = []
    mutexes: list[str] = []
    registry: list[dict] = []
    dropped: list[dict] = []
    file_paths: list[str] = []
    processes: list[str] = []
    api_counts: Counter[str] = Counter()
    embedded_urls: list[str] = []
    notes: list[str] = []

    for event in report.events:
        kind = str(event.get("event") or "")
        if kind == "api":
            api_name = str(event.get("api_name") or "")
            if api_name:
                api_counts[api_name] += 1
            suffix = _api_suffix(api_name)
            args = [str(a) for a in (event.get("args") or [])]
            if suffix in MUTEX_API_SUFFIXES and args:
                _add_dedup_str(mutexes, args[-1])
            if suffix in USER_AGENT_API_SUFFIXES and args:
                _add_dedup_str(user_agents, args[0])
            for arg in args:
                for url in URL_RE.findall(arg):
                    if url not in embedded_urls:
                        embedded_urls.append(url)
            continue

        if kind in ("net_http", "net_traffic"):
            server = str(event.get("server") or "")
            if _endpoint_is_routable(server):
                endpoint = {
                    "server": server,
                    "port": int(event.get("port") or 0),
                    "protocol": str(event.get("proto") or ""),
                    "kind": kind,
                }
                _add_dedup(endpoints, endpoint, "server")
            if kind == "net_http":
                http_events.append(
                    {
                        "server": server,
                        "port": int(event.get("port") or 0),
                        "proto": str(event.get("proto") or ""),
                        "method": str(event.get("method") or ""),
                    }
                )
            continue

        if kind == "net_dns":
            query = str(event.get("query") or "")
            response = event.get("response")
            dns_queries.append({"query": query, "response": str(response) if response else ""})
            continue

        if kind.startswith("file_"):
            path = str(event.get("path") or "")
            if path:
                _add_dedup_str(file_paths, path)
            continue

        if kind.startswith("reg_"):
            path = str(event.get("path") or "")
            value_name = event.get("value_name")
            lowered = path.lower()
            record = {
                "path": path,
                "value_name": str(value_name) if value_name else "",
                "persistence": any(marker in lowered for marker in PERSISTENCE_MARKERS),
                "kind": kind,
            }
            _add_dedup(registry, record, "path")
            continue

        if kind == "process_create":
            name = str(event.get("path") or event.get("name") or "")
            if name:
                _add_dedup_str(processes, name)
            continue

    for item in report.dropped_files:
        path = str(item.get("path") or "")
        if path:
            _add_dedup(
                dropped,
                {"path": path, "sha256": str(item.get("sha256") or "")},
                "path",
            )

    # URLs captured from API arguments that did not surface as net_http events
    # (e.g. a URL passed to a function the emulator did not route through HTTP).
    for url in embedded_urls:
        match = re.match(r"https?://([^/:]+)(?::(\d+))?", url)
        if match and _endpoint_is_routable(match.group(1)):
            _add_dedup(
                endpoints,
                {
                    "server": match.group(1),
                    "port": int(match.group(2) or (443 if url.lower().startswith("https") else 80)),
                    "protocol": "https" if url.lower().startswith("https") else "http",
                    "kind": "api_arg",
                },
                "server",
            )

    if not report.has_events:
        notes.append(
            "The emulator produced no events; configuration could not be "
            "established from this run."
        )
    if report.unsupported_apis:
        notes.append(
            "The sample reached API(s) the emulator does not implement "
            f"({', '.join(report.unsupported_apis)}); emulation stopped there "
            "and any later configuration is unknown."
        )

    config: dict[str, Any] = {
        "network_endpoints": endpoints,
        "dns_queries": dns_queries,
        "http_events": http_events,
        "embedded_urls": embedded_urls,
        "user_agents": user_agents,
        "mutexes": mutexes,
        "registry": registry,
        "registry_persistence": [r for r in registry if r.get("persistence")],
        "dropped_files": dropped,
        "file_paths": file_paths,
        "processes": processes,
        "api_calls": dict(api_counts.most_common()),
        "notes": notes,
    }
    logger.info(
        "Emulation config: %d endpoint(s), %d mutex(es), %d registry key(s) "
        "(%d persistence), %d dropped file(s)",
        len(endpoints), len(mutexes), len(registry),
        len(config["registry_persistence"]), len(dropped),
    )
    return config


def extract_iocs(config: dict) -> list[dict]:
    """Turn extracted configuration into IOC rows for the main extractor.

    ``source="emulation"`` on every row, so an indicator that only existed in
    emulated memory is distinguishable from one found in the static bytes.
    """
    iocs: list[dict] = []

    def add(ioc_type: str, value: str, severity: str, context: str) -> None:
        if not value:
            return
        if any(i["type"] == ioc_type and i["value"] == value for i in iocs):
            return
        iocs.append(
            {
                "type": ioc_type,
                "value": value,
                "source": "emulation",
                "severity": severity,
                "context": context,
                "confidence": "medium",
            }
        )

    for endpoint in config.get("network_endpoints") or []:
        server = str(endpoint.get("server") or "")
        port = endpoint.get("port") or 0
        if _is_ip(server):
            add("ip", server, "high", f"Emulated {endpoint.get('kind', 'network')} to {server}:{port}")
        elif server:
            add("domain", server, "high", f"Emulated {endpoint.get('kind', 'network')} to {server}:{port}")
    for url in config.get("embedded_urls") or []:
        add("url", str(url), "high", "URL argument observed during emulation")
    for query in config.get("dns_queries") or []:
        add("domain", str(query.get("query") or ""), "medium", "DNS query during emulation")
    for mutex in config.get("mutexes") or []:
        add("mutex", str(mutex), "medium", "Mutex named during emulation")
    for agent in config.get("user_agents") or []:
        add("user_agent", str(agent), "low", "User agent set during emulation")
    for key in config.get("registry") or []:
        path = str(key.get("path") or "")
        severity = "high" if key.get("persistence") else "medium"
        context = "Registry persistence written during emulation" if key.get("persistence") else "Registry key touched during emulation"
        add("registry_key", path, severity, context)
    for dropped in config.get("dropped_files") or []:
        sha = str(dropped.get("sha256") or "")
        if sha:
            add("hash", sha, "high", f"Dropped by emulated code: {dropped.get('path', '')}")
    return iocs
