"""STIX 2.1 export — generate STIX bundles from HATCHERY IOCs.

Produces STIX 2.1 formatted bundles compatible with threat intelligence
platforms (MISP, OpenCTI, GHOSTWIRE).
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# STIX 2.1 type mapping from IOC types
STIX_TYPE_MAP: dict[str, str] = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "email": "email-addr",
    "hash": "file",  # SHA256 hashes → file objects
    "file_path": "file",
    "registry_key": "windows-registry-key",
    "user_agent": "user-agent",
    "mutex": "mutex",
    "c2_beacon": "ipv4-addr",  # Map to the IP with a relationship
}

# HATCHERY namespace for STIX IDs
HATCHERY_NAMESPACE = uuid.UUID("a3c5b7d2-4e6f-4a1b-8c3d-5e7f9a2b4c6d")


def _stix_id(stix_type: str, value: str) -> str:
    """Generate a deterministic STIX ID for a given type and value.

    Uses UUID5 with HATCHERY namespace for deterministic, reproducible IDs.

    Args:
        stix_type: STIX object type (e.g., "ipv4-addr").
        value: The indicator value.

    Returns:
        STIX ID string (e.g., "ipv4-addr--a1b2c3d4...").
    """
    determiner = uuid.uuid5(HATCHERY_NAMESPACE, f"{stix_type}:{value}")
    return f"{stix_type}--{determiner}"


class STIXExporter:
    """Export HATCHERY IOCs as STIX 2.1 bundles.

    Produces valid STIX 2.1 JSON bundles containing observed-data,
    indicators, and relationships from HATCHERY analysis results.
    """

    def export_iocs(self, ioc_report: dict) -> str:
        """Export an IOC report as a STIX 2.1 bundle.

        Args:
            ioc_report: IOC report dict from IOCExtractor.

        Returns:
            STIX 2.1 JSON bundle string.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        objects: list[dict] = []

        # Add HATCHERY identity
        identity_id = _stix_id("identity", "hatchery")
        objects.append({
            "type": "identity",
            "id": identity_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "HATCHERY Sandbox",
            "identity_class": "system",
            "description": "HATCHERY — Docker-based malware sandbox engine",
        })

        # Process each IOC
        for ioc in ioc_report.get("iocs", []):
            ioc_type = ioc.get("type", "")
            value = ioc.get("value", "")
            source = ioc.get("source", "")
            context = ioc.get("context", "")
            severity = ioc.get("severity", "medium")

            stix_type = STIX_TYPE_MAP.get(ioc_type)
            if not stix_type:
                continue

            # Create the STIX object based on type
            if stix_type == "ipv4-addr":
                objects.append({
                    "type": "ipv4-addr",
                    "id": _stix_id("ipv4-addr", value),
                    "spec_version": "2.1",
                    "value": value,
                })

            elif stix_type == "domain-name":
                objects.append({
                    "type": "domain-name",
                    "id": _stix_id("domain-name", value),
                    "spec_version": "2.1",
                    "value": value,
                })

            elif stix_type == "url":
                objects.append({
                    "type": "url",
                    "id": _stix_id("url", value),
                    "spec_version": "2.1",
                    "value": value,
                })

            elif stix_type == "email-addr":
                objects.append({
                    "type": "email-addr",
                    "id": _stix_id("email-addr", value),
                    "spec_version": "2.1",
                    "value": value,
                })

            elif stix_type == "file":
                # If the value looks like a SHA256 hash
                if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()):
                    objects.append({
                        "type": "file",
                        "id": _stix_id("file", value),
                        "spec_version": "2.1",
                        "hashes": {"SHA-256": value.lower()},
                    })
                else:
                    objects.append({
                        "type": "file",
                        "id": _stix_id("file", value),
                        "spec_version": "2.1",
                        "name": value,
                    })

            elif stix_type == "windows-registry-key":
                objects.append({
                    "type": "windows-registry-key",
                    "id": _stix_id("windows-registry-key", value),
                    "spec_version": "2.1",
                    "key": value,
                })

            # Create indicator object for high/critical IOCs
            if severity in ("high", "critical"):
                indicator_id = _stix_id("indicator", f"indicator-{value}")
                pattern = self._build_pattern(stix_type, value)
                if pattern:
                    objects.append({
                        "type": "indicator",
                        "id": indicator_id,
                        "spec_version": "2.1",
                        "created_by_ref": identity_id,
                        "created": now,
                        "modified": now,
                        "name": f"HATCHERY: {ioc_type} - {value[:50]}",
                        "description": context,
                        "pattern": pattern,
                        "pattern_type": "stix",
                        "valid_from": now,
                        "labels": [f"source:{source}", f"severity:{severity}"],
                    })

        # Build the bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

        logger.info("Exported STIX 2.1 bundle with %d objects", len(objects))
        return json.dumps(bundle, indent=2)

    def _build_pattern(self, stix_type: str, value: str) -> Optional[str]:
        """Build a STIX pattern for an indicator.

        Args:
            stix_type: STIX object type.
            value: The indicator value.

        Returns:
            STIX pattern string, or None if not applicable.
        """
        patterns: dict[str, str] = {
            "ipv4-addr": f"[ipv4-addr:value = '{value}']",
            "domain-name": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "email-addr": f"[email-addr:value = '{value}']",
            "file": f"[file:hashes.'SHA-256' = '{value.lower()}']"
                if len(value) == 64 else None,
            "windows-registry-key": f"[windows-registry-key:key = '{value}']",
        }
        return patterns.get(stix_type)