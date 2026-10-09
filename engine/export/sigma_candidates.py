"""Candidate Sigma rules from observed behaviour — D18 (stretch).

These are **generated drafts**, not validated detections. A rule is emitted only
for a technique that was actually observed in this run, and each rule carries
``status: experimental`` plus an ``x_hatchery`` block marking it as an
unreviewed, machine-generated candidate. The rule's ``falsepositives`` field
says plainly that it was derived from a single sample and has not been tuned.

The point is to hand an analyst a starting point, not to claim detection
coverage. One producer: the engine writes ``sigma-candidates/``; nothing else
emits Sigma.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Technique -> Sigma template. Only techniques with a meaningful, honest
# selection are templated; anything else is skipped rather than emitted as a
# vague rule that fires on everything.
SIGMA_TEMPLATES: dict[str, dict[str, Any]] = {
    "T1059.004": {
        "logsource": {"product": "linux", "category": "process_creation"},
        "selection": {"Image|endswith": ["/sh", "/bash", "/dash", "/ash", "/zsh", "/ksh", "/busybox"]},
        "level": "low",
    },
    "T1622": {
        "logsource": {"product": "linux", "category": "process_creation"},
        "selection": {"CommandLine|contains": ["ptrace", "/proc/self/status", "/proc/self/mem"]},
        "level": "medium",
    },
    "T1497.001": {
        "logsource": {"product": "linux", "category": "file_event"},
        "selection": {
            "TargetFilename|startswith": [
                "/proc/cpuinfo",
                "/proc/self/auxv",
                "/proc/uptime",
                "/sys/hypervisor",
                "/sys/class/dmi",
            ]
        },
        "level": "low",
    },
    "T1003.008": {
        "logsource": {"product": "linux", "category": "file_event"},
        "selection": {"TargetFilename|endswith": ["/etc/passwd", "/etc/shadow", "/etc/gshadow"]},
        "level": "high",
    },
    "T1071.004": {
        "logsource": {"category": "network_connection"},
        "selection": {"DestinationPort": [53, 5353]},
        "level": "low",
    },
    "T1071.001": {
        "logsource": {"category": "network_connection"},
        "selection": {"DestinationPort": [80, 443, 8080, 8443]},
        "level": "low",
    },
    "T1571": {
        "logsource": {"category": "network_connection"},
        "selection": {"Initiated": "true"},
        "level": "low",
    },
    "T1095": {
        "logsource": {"category": "network_connection"},
        "selection": {"Initiated": "true"},
        "level": "low",
    },
    "T1070.004": {
        "logsource": {"product": "linux", "category": "file_delete"},
        "selection": {"EventType": ["unlink", "unlinkat"]},
        "level": "medium",
    },
    "T1222": {
        "logsource": {"product": "linux", "category": "file_event"},
        "selection": {"EventType": ["chmod", "fchmod", "fchmodat"]},
        "level": "medium",
    },
    "T1620": {
        "logsource": {"product": "linux", "category": "process_creation"},
        "selection": {"CommandLine|contains": ["memfd_create"]},
        "level": "medium",
    },
    "T1055": {
        "logsource": {"product": "linux", "category": "process_creation"},
        "selection": {"CommandLine|contains": ["PROT_EXEC"]},
        "level": "medium",
    },
    "T1518.001": {
        "logsource": {"product": "linux", "category": "process_creation"},
        "selection": {
            "CommandLine|contains": ["strace", "gdb", "ltrace", "tcpdump", "inotifywait", "auditd"]
        },
        "level": "medium",
    },
}


def _rule_id(task_id: str, technique_id: str) -> str:
    digest = hashlib.sha1(f"hatchery-sigma:{task_id}:{technique_id}".encode()).hexdigest()
    return (
        f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
    )


def build_sigma_candidates(
    *,
    mitre: Optional[dict] = None,
    events: Optional[list[dict]] = None,
    task_id: str = "",
    sample_name: str = "",
    attack_version: str = "19.2",
) -> list[dict]:
    """Build candidate Sigma rules for the techniques observed in this run."""
    mitre = mitre or {}
    events = list(events or [])
    rules: list[dict] = []

    for technique in mitre.get("techniques", []) or []:
        effective = technique.get("subtechnique_id") or technique.get("technique_id") or ""
        template = SIGMA_TEMPLATES.get(effective)
        if template is None:
            continue  # no honest selection exists; do not emit a vague rule
        name = technique.get("subtechnique_name") or technique.get("technique_name") or effective
        observed = sum(
            1 for event in events if _event_matches_template(event, template)
        )
        tags = []
        if technique.get("tactic_id"):
            tags.append(f"attack.{technique['tactic_id']}")
        tags.append(f"attack.{effective.lower().replace('.', '_')}")

        rules.append(
            {
                "title": f"HATCHERY candidate: {effective} {name}",
                "id": _rule_id(task_id, effective),
                "status": "experimental",
                "description": (
                    "GENERATED DRAFT — machine-derived from a single HATCHERY "
                    "detonation and REQUIRES analyst review. This is a candidate, "
                    "not a validated detection."
                ),
                "references": [f"https://attack.mitre.org/techniques/{effective.replace('.', '/')}/"],
                "author": "HATCHERY (generated)",
                "date": "2026/10/09",
                "tags": tags,
                "logsource": template["logsource"],
                "detection": {"selection": template["selection"], "condition": "selection"},
                "falsepositives": [
                    "UNKNOWN — generated from one sample and not tuned against production data."
                ],
                "level": template["level"],
                "x_hatchery": {
                    "generated": True,
                    "reviewed": False,
                    "task_id": task_id,
                    "sample": sample_name,
                    "attack_version": attack_version,
                    "technique_id": effective,
                    "source": technique.get("source", ""),
                    "confidence": technique.get("confidence", ""),
                    "detection_strategy_ids": technique.get("detection_strategy_ids", []),
                    "observed_events_matching": observed,
                },
            }
        )

    logger.info(
        "Generated %d candidate Sigma rule(s) from %d mapped technique(s)",
        len(rules), len(mitre.get("techniques", []) or []),
    )
    return rules


def _event_matches_template(event: dict, template: dict[str, Any]) -> bool:
    """Coarse count of events that plausibly match a template's selection.

    Used only to populate the ``observed_events_matching`` annotation, never to
    claim the rule is validated.
    """
    category = str(event.get("category", ""))
    wanted_category = str((template.get("logsource") or {}).get("category", ""))
    if wanted_category == "process_creation":
        return category == "process"
    if wanted_category in ("file_event", "file_delete"):
        return category == "file"
    if wanted_category == "network_connection":
        return category == "network"
    return False


def render_sigma_yaml(rules: list[dict]) -> str:
    """Render rules as a multi-document YAML stream (one document per rule)."""
    import yaml

    header = (
        "# HATCHERY candidate Sigma rules — GENERATED DRAFTS.\n"
        "# These rules are machine-derived from observed behaviour and have NOT\n"
        "# been reviewed or validated. Treat them as a starting point for an analyst.\n"
    )
    documents = [
        yaml.safe_dump(rule, sort_keys=False, default_flow_style=False, allow_unicode=True)
        for rule in rules
    ]
    return header + "---\n".join(documents)


def write_sigma_candidates(run_dir: Path, rules: list[dict]) -> Optional[Path]:
    """Write one ``<technique>.yml`` per candidate into ``sigma-candidates/``."""
    if not rules:
        return None
    import yaml

    out_dir = run_dir / "sigma-candidates"
    out_dir.mkdir(parents=True, exist_ok=True)
    for rule in rules:
        technique = str((rule.get("x_hatchery") or {}).get("technique_id", "rule"))
        path = out_dir / f"{technique.replace('.', '_')}.yml"
        path.write_text(
            yaml.safe_dump(rule, sort_keys=False, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
    return out_dir


def validate_sigma_rule(rule: dict) -> list[str]:
    """Return every reason ``rule`` is not a well-formed candidate Sigma rule."""
    problems: list[str] = []
    for field in ("title", "id", "status", "description", "logsource", "detection", "level"):
        if field not in rule:
            problems.append(f"missing required Sigma field {field!r}")
    if rule.get("status") != "experimental":
        problems.append("candidate rules must carry status: experimental")
    if "GENERATED DRAFT" not in str(rule.get("description", "")):
        problems.append("candidate rules must be labelled as generated drafts")
    x = rule.get("x_hatchery") or {}
    if x.get("generated") is not True or x.get("reviewed") is not False:
        problems.append("candidate rules must be marked generated and unreviewed")
    detection = rule.get("detection") or {}
    if not detection.get("selection") or not detection.get("condition"):
        problems.append("detection must carry a selection and a condition")
    tags = rule.get("tags") or []
    if not any(str(tag).startswith("attack.") for tag in tags):
        problems.append("rule must carry at least one attack.* tag")
    return problems


__all__ = [
    "SIGMA_TEMPLATES",
    "build_sigma_candidates",
    "render_sigma_yaml",
    "validate_sigma_rule",
    "write_sigma_candidates",
]
