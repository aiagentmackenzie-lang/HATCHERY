"""MITRE ATT&CK mapping — map capabilities to ATT&CK techniques.

Uses capa output and behavioral events to map observed behaviors
to MITRE ATT&CK tactics and techniques.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ATTCKTechnique:
    """A MITRE ATT&CK technique mapping."""
    tactic: str
    technique_id: str
    technique_name: str
    subtechnique_id: str = ""
    subtechnique_name: str = ""
    source: str = ""  # capa, yara, strace, file_watch
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "subtechnique_id": self.subtechnique_id,
            "subtechnique_name": self.subtechnique_name,
            "source": self.source,
            "confidence": self.confidence,
        }


# Behavioral indicators → ATT&CK technique mappings
BEHAVIOR_TECHNIQUE_MAP: dict[str, ATTCKTechnique] = {
    # Process operations
    "execve": ATTCKTechnique(
        tactic="Execution",
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        source="strace",
    ),
    "fork": ATTCKTechnique(
        tactic="Execution",
        technique_id="T1106",
        technique_name="Native API",
        source="strace",
    ),
    "clone": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1055",
        technique_name="Process Injection",
        source="strace",
    ),

    # Network operations
    "connect": ATTCKTechnique(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        source="strace",
    ),
    "socket": ATTCKTechnique(
        tactic="Command and Control",
        technique_id="T1571",
        technique_name="Non-Standard Port",
        source="strace",
    ),
    "bind": ATTCKTechnique(
        tactic="Command and Control",
        technique_id="T1570",
        technique_name="Non-Standard Port (Listen)",
        source="strace",
    ),

    # File operations
    "openat": ATTCKTechnique(
        tactic="Collection",
        technique_id="T1005",
        technique_name="Data from Local System",
        source="strace",
    ),
    "unlink": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1070.004",
        technique_name="File Deletion",
        source="strace",
    ),
    "chmod": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1222",
        technique_name="File Permissions Modification",
        source="strace",
    ),

    # Memory operations
    "mprotect": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1055",
        technique_name="Process Injection",
        source="strace",
    ),
    "mmap": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1055.012",
        technique_name="Process Hollowing",
        source="strace",
    ),
}

# Suspicious file patterns → ATT&CK techniques
FILE_PATTERN_MAP: dict[str, ATTCKTechnique] = {
    ".bashrc": ATTCKTechnique(
        tactic="Persistence",
        technique_id="T1546.004",
        technique_name="Unix Shell Configuration Modification",
        source="file_watch",
        confidence="high",
    ),
    ".ssh": ATTCKTechnique(
        tactic="Persistence",
        technique_id="T1098",
        technique_name="Account Manipulation",
        source="file_watch",
        confidence="high",
    ),
    "/etc/cron": ATTCKTechnique(
        tactic="Persistence",
        technique_id="T1053.003",
        technique_name="Scheduled Task/Job: Cron",
        source="file_watch",
        confidence="high",
    ),
    "/etc/init.d": ATTCKTechnique(
        tactic="Persistence",
        technique_id="T1037.004",
        technique_name="Boot or Logon Initialization Scripts: RC Scripts",
        source="file_watch",
        confidence="high",
    ),
    "/etc/hosts": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1112",
        technique_name="Modify Registry",
        source="file_watch",
        confidence="medium",
    ),
}

# YARA rule tag → ATT&CK technique mappings
YARA_TAG_MAP: dict[str, ATTCKTechnique] = {
    "anti_debug": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1622",
        technique_name="Debugger Evasion",
        source="yara",
        confidence="high",
    ),
    "sandbox_evasion": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1497",
        technique_name="Virtualization/Sandbox Evasion",
        source="yara",
        confidence="high",
    ),
    "packing": ATTCKTechnique(
        tactic="Defense Evasion",
        technique_id="T1027.002",
        technique_name="Software Packing",
        source="yara",
        confidence="high",
    ),
}


@dataclass
class MITREMappingResult:
    """Complete MITRE ATT&CK mapping result."""
    techniques: list[ATTCKTechnique] = field(default_factory=list)
    tactics_covered: list[str] = field(default_factory=list)
    technique_count: int = 0

    def to_dict(self) -> dict:
        return {
            "techniques": [t.to_dict() for t in self.techniques],
            "tactics_covered": sorted(set(self.tactics_covered)),
            "technique_count": self.technique_count,
        }


class MITREMapper:
    """Map HATCHERY observations to MITRE ATT&CK techniques.

    Uses capa output, strace events, file watcher results, and
    YARA matches to produce a comprehensive ATT&CK technique mapping.
    """

    def map_all(
        self,
        capa_data: Optional[dict] = None,
        strace_data: Optional[dict] = None,
        file_watch_data: Optional[dict] = None,
        yara_data: Optional[dict] = None,
    ) -> MITREMappingResult:
        """Map all analysis results to MITRE ATT&CK techniques.

        Args:
            capa_data: capa capability extraction results.
            strace_data: strace parsing results.
            file_watch_data: file watcher results.
            yara_data: YARA scan results.

        Returns:
            MITREMappingResult with all mapped techniques.
        """
        seen_techniques: set[str] = set()
        techniques: list[ATTCKTechnique] = []
        tactics: list[str] = []

        # From capa
        if capa_data:
            for tech in self._map_capa(capa_data):
                key = tech.technique_id
                if key not in seen_techniques:
                    seen_techniques.add(key)
                    techniques.append(tech)
                    tactics.append(tech.tactic)

        # From strace
        if strace_data:
            for tech in self._map_strace(strace_data):
                key = tech.technique_id
                if key not in seen_techniques:
                    seen_techniques.add(key)
                    techniques.append(tech)
                    tactics.append(tech.tactic)

        # From file watcher
        if file_watch_data:
            for tech in self._map_file_watch(file_watch_data):
                key = tech.technique_id
                if key not in seen_techniques:
                    seen_techniques.add(key)
                    techniques.append(tech)
                    tactics.append(tech.tactic)

        # From YARA
        if yara_data:
            for tech in self._map_yara(yara_data):
                key = tech.technique_id
                if key not in seen_techniques:
                    seen_techniques.add(key)
                    techniques.append(tech)
                    tactics.append(tech.tactic)

        result = MITREMappingResult(
            techniques=techniques,
            tactics_covered=tactics,
            technique_count=len(techniques),
        )

        logger.info(
            "MITRE ATT&CK mapping: %d techniques across %d tactics",
            result.technique_count,
            len(set(result.tactics_covered)),
        )
        return result

    def _map_capa(self, capa_data: dict) -> list[ATTCKTechnique]:
        """Map capa capabilities to ATT&CK techniques."""
        techniques: list[ATTCKTechnique] = []
        for attack in capa_data.get("attack_techniques", []):
            techniques.append(ATTCKTechnique(
                tactic=attack.get("tactic", ""),
                technique_id=attack.get("id", ""),
                technique_name=attack.get("technique", ""),
                subtechnique_id=attack.get("subtechnique", ""),
                source="capa",
                confidence="high",
            ))
        return techniques

    def _map_strace(self, strace_data: dict) -> list[ATTCKTechnique]:
        """Map strace events to ATT&CK techniques."""
        techniques: list[ATTCKTechnique] = []
        # Check events for known syscall patterns
        for event in strace_data.get("events", []):
            syscall = event.get("syscall", "")
            if syscall in BEHAVIOR_TECHNIQUE_MAP:
                tech = BEHAVIOR_TECHNIQUE_MAP[syscall]
                techniques.append(ATTCKTechnique(
                    tactic=tech.tactic,
                    technique_id=tech.technique_id,
                    technique_name=tech.technique_name,
                    subtechnique_id=tech.subtechnique_id,
                    subtechnique_name=tech.subtechnique_name,
                    source=tech.source,
                    confidence="medium",
                ))
        return techniques

    def _map_file_watch(self, file_watch_data: dict) -> list[ATTCKTechnique]:
        """Map file watcher events to ATT&CK techniques."""
        techniques: list[ATTCKTechnique] = []
        for event in file_watch_data.get("events", []):
            path = event.get("path", "")
            for pattern, tech in FILE_PATTERN_MAP.items():
                if pattern in path:
                    techniques.append(ATTCKTechnique(
                        tactic=tech.tactic,
                        technique_id=tech.technique_id,
                        technique_name=tech.technique_name,
                        source=tech.source,
                        confidence=tech.confidence,
                    ))
        return techniques

    def _map_yara(self, yara_data: dict) -> list[ATTCKTechnique]:
        """Map YARA matches to ATT&CK techniques."""
        techniques: list[ATTCKTechnique] = []
        for match in yara_data.get("matches", []):
            # Check rule tags
            tags = match.get("tags", [])
            for tag in tags:
                if tag in YARA_TAG_MAP:
                    tech = YARA_TAG_MAP[tag]
                    techniques.append(ATTCKTechnique(
                        tactic=tech.tactic,
                        technique_id=tech.technique_id,
                        technique_name=tech.technique_name,
                        source=tech.source,
                        confidence=tech.confidence,
                    ))

            # Check meta for MITRE ATT&CK reference
            meta = match.get("meta", {})
            if "mitre_attck" in meta:
                techniques.append(ATTCKTechnique(
                    tactic="Unknown",
                    technique_id=meta["mitre_attck"].split(":")[0] if ":" in meta["mitre_attck"] else "",
                    technique_name=meta.get("mitre_attck", ""),
                    source="yara",
                    confidence="high",
                ))

        return techniques