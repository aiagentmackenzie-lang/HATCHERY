"""capa capability extraction — identify malware behaviors from static analysis.

Uses Mandiant/FLARE capa to extract capabilities from PE and ELF binaries,
mapping them to MITRE ATT&CK techniques. Falls back gracefully if capa
is not installed.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Check if capa is available
def _check_capa_available() -> bool:
    """Check if flare-capa CLI is available on PATH."""
    try:
        result = subprocess.run(
            ["capa", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

HAS_CAPA = _check_capa_available()
if not HAS_CAPA:
    # Try Python import
    try:
        import capa
        HAS_CAPA_PYTHON = True
    except ImportError:
        HAS_CAPA_PYTHON = False
    logger.debug("capa CLI not found, Python import: %s", HAS_CAPA_PYTHON)
else:
    HAS_CAPA_PYTHON = False


@dataclass
class CapaCapability:
    """A single capability extracted by capa."""
    name: str
    namespace: str
    description: str = ""
    attack_techniques: list[dict[str, str]] = field(default_factory=list)
    mbc_behaviors: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "description": self.description,
            "attack_techniques": self.attack_techniques,
            "mbc_behaviors": self.mbc_behaviors,
        }


@dataclass
class CapaResult:
    """Complete capa analysis result."""
    is_available: bool = False
    capabilities: list[CapaCapability] = field(default_factory=list)
    attack_techniques: list[dict[str, str]] = field(default_factory=list)
    mbc_behaviors: list[dict[str, str]] = field(default_factory=list)
    analysis_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "is_available": self.is_available,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "attack_techniques": self.attack_techniques,
            "mbc_behaviors": self.mbc_behaviors,
            "analysis_time_ms": self.analysis_time_ms,
            "error": self.error,
        }

    @property
    def has_capabilities(self) -> bool:
        return len(self.capabilities) > 0


class CapaScanner:
    """Extract capabilities from binaries using FLARE capa.

    Runs capa as a subprocess (or Python import) and parses the JSON output
    into structured capability objects with MITRE ATT&CK mappings.
    """

    # Mapping of capability namespaces to categories
    NAMESPACE_CATEGORIES: dict[str, str] = {
        "communication": "C2 Communication",
        "data": "Data Manipulation",
        "defense-evasion": "Defense Evasion",
        "discovery": "Discovery",
        "execution": "Execution",
        "collection": "Collection",
        "credential-access": "Credential Access",
        "persistence": "Persistence",
        "privilege-escalation": "Privilege Escalation",
        "lateral-movement": "Lateral Movement",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
        "anti-analysis": "Anti-Analysis",
        "host-interaction": "Host Interaction",
        "lib": "Library Function",
        "malware": "Malware Family",
        "operating-system": "OS Interaction",
    }

    def scan(self, file_path: Path) -> CapaResult:
        """Run capa analysis on a file.

        Args:
            file_path: Path to the binary to analyze.

        Returns:
            CapaResult with extracted capabilities and ATT&CK mappings.
        """
        import time

        if not file_path.exists():
            return CapaResult(error=f"File not found: {file_path}")

        if not HAS_CAPA and not HAS_CAPA_PYTHON:
            return CapaResult(
                is_available=False,
                error="capa not available — install flare-capa",
            )

        result = CapaResult(is_available=True)
        start = time.monotonic()

        try:
            # Use CLI for reliability
            if HAS_CAPA:
                raw_output = self._run_capa_cli(file_path)
            else:
                raw_output = self._run_capa_python(file_path)

            if raw_output:
                result = self._parse_output(raw_output, is_available=True)

        except subprocess.TimeoutExpired:
            result.error = "capa analysis timed out (>120s)"
        except Exception as e:
            result.error = f"capa analysis failed: {e}"

        elapsed = time.monotonic() - start
        result.analysis_time_ms = elapsed * 1000
        result.is_available = True

        logger.info(
            "capa analysis of %s: %d capabilities in %.1fms",
            file_path.name, len(result.capabilities), result.analysis_time_ms,
        )
        return result

    def _run_capa_cli(self, file_path: Path) -> Optional[dict]:
        """Run capa CLI and return parsed JSON output.

        Args:
            file_path: Path to the binary.

        Returns:
            Parsed JSON dict or None on failure.
        """
        try:
            proc = subprocess.run(
                ["capa", "-j", str(file_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                logger.warning("capa returned non-zero: %s", proc.stderr[:500])
                return None

            return json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse capa JSON: %s", e)
            return None

    def _run_capa_python(self, file_path: Path) -> Optional[dict]:
        """Run capa via Python API (fallback).

        Args:
            file_path: Path to the binary.

        Returns:
            Parsed dict or None on failure.
        """
        try:
            import capa
            import capa.render.json as capa_json

            with open(file_path, "rb") as f:
                capabilities = capa.main.find_capabilities(f)

            # Convert to JSON-serializable dict
            output = capa_json.render_capabilities(capabilities)
            return json.loads(json.dumps(output))
        except Exception as e:
            logger.error("capa Python API failed: %s", e)
            return None

    def _parse_output(self, raw: dict, is_available: bool = True) -> CapaResult:
        """Parse capa JSON output into structured CapaResult.

        Args:
            raw: Parsed JSON from capa output.

        Returns:
            Structured CapaResult.
        """
        result = CapaResult(is_available=is_available)

        # capa v9+ JSON format
        rules = raw.get("rules", {})

        # Also handle the flat format from older capa
        if not rules and "meta" in raw:
            rules = {raw.get("meta", {}).get("name", "unknown"): raw}

        all_attack: list[dict[str, str]] = []
        all_mbc: list[dict[str, str]] = []

        for rule_name, rule_data in rules.items():
            if isinstance(rule_data, dict):
                meta = rule_data.get("meta", rule_data)
            else:
                continue

            name = meta.get("name", rule_name)
            namespace = meta.get("namespace", "")
            description = meta.get("description", "")

            # Extract ATT&CK technique references
            attack_refs: list[dict[str, str]] = []
            for attack in meta.get("attack", []):
                technique = {
                    "tactic": attack.get("tactic", ""),
                    "technique": attack.get("technique", ""),
                    "subtechnique": attack.get("subtechnique", ""),
                    "id": attack.get("id", ""),
                }
                attack_refs.append(technique)
                if technique not in all_attack:
                    all_attack.append(technique)

            # Extract MBC behavior references
            mbc_refs: list[dict[str, str]] = []
            for mbc in meta.get("mbc", []):
                behavior = {
                    "objective": mbc.get("objective", ""),
                    "behavior": mbc.get("behavior", ""),
                    "id": mbc.get("id", ""),
                }
                mbc_refs.append(behavior)
                if behavior not in all_mbc:
                    all_mbc.append(behavior)

            result.capabilities.append(CapaCapability(
                name=name,
                namespace=namespace,
                description=description,
                attack_techniques=attack_refs,
                mbc_behaviors=mbc_refs,
            ))

        result.attack_techniques = all_attack
        result.mbc_behaviors = all_mbc

        return result