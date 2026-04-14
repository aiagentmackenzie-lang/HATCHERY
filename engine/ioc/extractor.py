"""IOC extractor — aggregate indicators of compromise from all analysis sources.

Collects IOCs from static analysis (strings, YARA, capa), behavioral
monitoring (strace, file watcher, network capture), and fake services
into a unified, deduplicated list.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """A single indicator of compromise."""
    type: str  # ip, domain, url, email, hash, file_path, registry_key, user_agent, mutex, c2_beacon
    value: str
    source: str  # static, strace, file_watch, network, fake_service, capa, yara
    severity: str = "medium"  # info, low, medium, high, critical
    context: str = ""
    confidence: str = "medium"  # low, medium, high

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "severity": self.severity,
            "context": self.context,
            "confidence": self.confidence,
        }


@dataclass
class IOCReport:
    """Complete IOC extraction report."""
    iocs: list[IOC] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "iocs": [i.to_dict() for i in self.iocs],
            "summary": self.summary,
        }

    @property
    def total_count(self) -> int:
        return len(self.iocs)

    def get_by_type(self, ioc_type: str) -> list[IOC]:
        return [i for i in self.iocs if i.type == ioc_type]

    def get_by_severity(self, severity: str) -> list[IOC]:
        return [i for i in self.iocs if i.severity == severity]


class IOCExtractor:
    """Extract and aggregate IOCs from all HATCHERY analysis sources.

    Takes results from static analysis, behavioral monitoring, and fake
    services, deduplicates, and produces a unified IOC report.
    """

    # Severity mapping by IOC type
    TYPE_SEVERITY: dict[str, str] = {
        "ip": "medium",
        "domain": "medium",
        "url": "high",
        "email": "medium",
        "hash": "low",
        "file_path": "low",
        "registry_key": "medium",
        "user_agent": "low",
        "mutex": "medium",
        "c2_beacon": "critical",
        "yara_match": "high",
        "capa_capability": "medium",
    }

    def extract(
        self,
        static_data: Optional[dict] = None,
        strace_data: Optional[dict] = None,
        file_watch_data: Optional[dict] = None,
        network_data: Optional[dict] = None,
        fake_service_data: Optional[dict] = None,
    ) -> IOCReport:
        """Extract IOCs from all available analysis data.

        Args:
            static_data: Results from static analysis (strings, YARA, capa, PE/ELF).
            strace_data: Results from strace parsing.
            file_watch_data: Results from file watcher.
            network_data: Results from network capture.
            fake_service_data: Results from fake services.

        Returns:
            IOCReport with deduplicated, categorized IOCs.
        """
        all_iocs: list[IOC] = []
        seen: set[str] = set()  # type:value for dedup

        if static_data:
            all_iocs.extend(self._extract_from_static(static_data, seen))
        if strace_data:
            all_iocs.extend(self._extract_from_strace(strace_data, seen))
        if file_watch_data:
            all_iocs.extend(self._extract_from_file_watch(file_watch_data, seen))
        if network_data:
            all_iocs.extend(self._extract_from_network(network_data, seen))
        if fake_service_data:
            all_iocs.extend(self._extract_from_fake_services(fake_service_data, seen))

        # Build summary
        summary: dict[str, int] = {}
        for ioc in all_iocs:
            summary[ioc.type] = summary.get(ioc.type, 0) + 1

        report = IOCReport(iocs=all_iocs, summary=summary)

        logger.info(
            "Extracted %d IOCs: %s",
            report.total_count, summary,
        )
        return report

    def _dedup_add(
        self,
        ioc: IOC,
        seen: set[str],
        results: list[IOC],
    ) -> None:
        """Add an IOC only if not already seen (by type:value).

        Args:
            ioc: The IOC to potentially add.
            seen: Set of already-seen type:value keys.
            results: List to append to.
        """
        key = f"{ioc.type}:{ioc.value}"
        if key not in seen:
            seen.add(key)
            results.append(ioc)

    def _extract_from_static(
        self, data: dict, seen: set[str]
    ) -> list[IOC]:
        """Extract IOCs from static analysis results."""
        results: list[IOC] = []

        # Strings extraction results
        strings = data.get("strings", {})
        for url in strings.get("urls", []):
            self._dedup_add(IOC(
                type="url", value=url, source="static",
                severity="high", context="Extracted from binary strings",
            ), seen, results)

        for ip in strings.get("ips", []):
            self._dedup_add(IOC(
                type="ip", value=ip, source="static",
                severity="medium", context="IP address in strings",
            ), seen, results)

        for domain in strings.get("domains", []):
            self._dedup_add(IOC(
                type="domain", value=domain, source="static",
                severity="medium", context="Domain in strings",
            ), seen, results)

        for email in strings.get("emails", []):
            self._dedup_add(IOC(
                type="email", value=email, source="static",
                severity="medium", context="Email in strings",
            ), seen, results)

        for reg_key in strings.get("registry_keys", []):
            self._dedup_add(IOC(
                type="registry_key", value=reg_key, source="static",
                severity="medium", context="Registry key in strings",
            ), seen, results)

        # YARA matches
        yara = data.get("yara", {})
        for match in yara.get("matches", []):
            self._dedup_add(IOC(
                type="yara_match", value=match.get("rule", "unknown"),
                source="yara", severity="high",
                context=f"YARA rule: {match.get('rule', '')} ({match.get('meta', {}).get('description', '')})",
            ), seen, results)

        # capa capabilities
        capa = data.get("capa", {})
        for cap in capa.get("capabilities", []):
            self._dedup_add(IOC(
                type="capa_capability", value=cap.get("name", "unknown"),
                source="capa", severity="medium",
                context=f"capa: {cap.get('name', '')} ({cap.get('namespace', '')})",
            ), seen, results)

        return results

    def _extract_from_strace(
        self, data: dict, seen: set[str]
    ) -> list[IOC]:
        """Extract IOCs from strace parsing results."""
        results: list[IOC] = []

        # Network connections
        for conn in data.get("network_connections", []):
            ip = conn.get("ip", "")
            if ip and ip not in ("127.0.0.1", "::1", "unix"):
                self._dedup_add(IOC(
                    type="ip", value=ip, source="strace",
                    severity="high",
                    context=f"connect() to {ip}:{conn.get('port', 0)}",
                ), seen, results)

        # Process executions
        for proc in data.get("process_operations", []):
            path = proc.get("path", "")
            if path:
                self._dedup_add(IOC(
                    type="file_path", value=path, source="strace",
                    severity="high",
                    context=f"execve() of {path}",
                ), seen, results)

        return results

    def _extract_from_file_watch(
        self, data: dict, seen: set[str]
    ) -> list[IOC]:
        """Extract IOCs from file watcher results."""
        results: list[IOC] = []

        # Dropped executables
        for dropped in data.get("dropped_executables", []):
            sha256 = dropped.get("sha256", "")
            if sha256:
                self._dedup_add(IOC(
                    type="hash", value=sha256, source="file_watch",
                    severity="high",
                    context=f"Dropped {dropped.get('type', 'file')}: {dropped.get('path', '')}",
                ), seen, results)

        # Persistence attempts
        for persistence in data.get("persistence_attempts", []):
            path = persistence.get("path", "")
            if path:
                self._dedup_add(IOC(
                    type="file_path", value=path, source="file_watch",
                    severity="critical",
                    context=f"Persistence: modification of {path}",
                ), seen, results)

        return results

    def _extract_from_network(
        self, data: dict, seen: set[str]
    ) -> list[IOC]:
        """Extract IOCs from network capture results."""
        results: list[IOC] = []

        for ioc in data.get("network_iocs", []):
            ioc_type = ioc.get("type", "unknown")
            value = ioc.get("value", "")
            if value:
                severity = "critical" if ioc_type == "c2_beacon" else self.TYPE_SEVERITY.get(ioc_type, "medium")
                self._dedup_add(IOC(
                    type=ioc_type, value=value, source="network",
                    severity=severity,
                    context=ioc.get("context", ""),
                ), seen, results)

        return results

    def _extract_from_fake_services(
        self, data: dict, seen: set[str]
    ) -> list[IOC]:
        """Extract IOCs from fake service logs."""
        results: list[IOC] = []

        for ioc in data.get("network_iocs", []):
            ioc_type = ioc.get("type", "unknown")
            value = ioc.get("value", "")
            if value:
                self._dedup_add(IOC(
                    type=ioc_type, value=value, source="fake_service",
                    severity=self.TYPE_SEVERITY.get(ioc_type, "medium"),
                    context=ioc.get("context", ""),
                ), seen, results)

        return results