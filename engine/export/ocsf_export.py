"""OCSF Detection Finding export — interoperable detection output.

HATCHERY already writes ``events.jsonl`` and an analysis bundle. This module
adds a third, standards-shaped view: OCSF **Detection Finding** events
(``class_uid`` 2004, ``category_uid`` 2 / Findings) derived from the behavioural
events, the run summary and the evasion assessment.

The schema is pinned to OCSF **1.9.0** in
``engine/export/ocsf/schema-1.9.0.json``, which records the source tag, commit
and a SHA256 over the schema files read. Field names and enum values are copied
from that schema — this module does not invent any. ``validate_finding`` checks
required fields and enum membership, and the test suite fails when a severity,
class or category is malformed.

One producer: the engine writes ``ocsf.json``; nothing else emits OCSF.
"""

from __future__ import annotations

import hashlib
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

OCSF_SCHEMA_VERSION = "1.9.0"
DETECTION_FINDING_CLASS_UID = 2004
FINDINGS_CATEGORY_UID = 2
DETECTION_FINDING_ACTIVITY_ID = 1  # Create
HATCHERY_VERSION = "0.1.0"

SCHEMA_PATH = Path(__file__).parent / "ocsf" / f"schema-{OCSF_SCHEMA_VERSION}.json"

_SEVERITY_BY_NAME: dict[str, int] = {
    "unknown": 0,
    "informational": 1,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
    "fatal": 6,
}
_CONFIDENCE_BY_NAME: dict[str, int] = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


@lru_cache(maxsize=1)
def load_schema(path: Optional[str] = None) -> dict:
    """Load the pinned OCSF schema artifact."""
    resolved = Path(path) if path else SCHEMA_PATH
    if not resolved.exists():
        raise FileNotFoundError(
            f"Pinned OCSF schema not found at {resolved}"
        )
    return json.loads(resolved.read_text(encoding="utf-8"))


def severity_id(name: str) -> int:
    return _SEVERITY_BY_NAME.get(str(name).strip().lower(), 0)


def confidence_id(name: str) -> int:
    return _CONFIDENCE_BY_NAME.get(str(name).strip().lower(), 0)


def _finding_uid(task_id: str, kind: str, key: str = "") -> str:
    digest = hashlib.sha1(f"{task_id}:{kind}:{key}".encode()).hexdigest()[:32]
    return digest


def _metadata() -> dict:
    # `metadata.product` and `metadata.version` are the two required metadata
    # fields in the schema. `version` is the OCSF schema version, which is how
    # the file cites the pinned schema.
    return {
        "version": OCSF_SCHEMA_VERSION,
        "product": {
            "name": "HATCHERY",
            "vendor_name": "HATCHERY",
            "version": HATCHERY_VERSION,
        },
    }


def _finding(
    *,
    task_id: str,
    title: str,
    severity: str,
    time_ms: int,
    uid_key: str,
    evidences: list[dict],
    confidence: str = "medium",
    description: str = "",
) -> dict:
    finding_info: dict[str, Any] = {
        "uid": _finding_uid(task_id, "technique" if uid_key else "analysis", uid_key),
        "title": title,
    }
    if description:
        finding_info["desc"] = description
    return {
        "activity_id": DETECTION_FINDING_ACTIVITY_ID,
        "activity_name": "Create",
        "category_uid": FINDINGS_CATEGORY_UID,
        "category_name": "Findings",
        "class_uid": DETECTION_FINDING_CLASS_UID,
        "class_name": "Detection Finding",
        "type_uid": DETECTION_FINDING_CLASS_UID * 100 + DETECTION_FINDING_ACTIVITY_ID,
        "severity_id": severity_id(severity),
        "severity": str(severity).capitalize(),
        "confidence_id": confidence_id(confidence),
        "confidence": str(confidence).capitalize(),
        "time": time_ms,
        "metadata": _metadata(),
        "finding_info": finding_info,
        "evidences": evidences,
    }


def _event_evidence(events: Iterable[dict], technique_id: str, limit: int = 3) -> list[dict]:
    """Evidence items drawn from real observed events for a technique."""
    wanted = _categories_for(technique_id)
    evidence: list[dict] = []
    for event in events:
        if len(evidence) >= limit:
            break
        if wanted and event.get("category") not in wanted:
            continue
        args = event.get("args")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"raw": args}
        data = {
            "timestamp": event.get("timestamp", ""),
            "pid": event.get("pid", 0),
            "syscall": event.get("syscall_name", ""),
            "category": event.get("category", ""),
            "severity": event.get("severity", ""),
            "source": event.get("source", ""),
        }
        if isinstance(args, dict) and args.get("path"):
            data["path"] = args["path"]
        item: dict[str, Any] = {"name": "behavioral-event", "data": data}
        pid = event.get("pid")
        if isinstance(pid, int) and pid > 0:
            item["process"] = {"pid": pid}
        evidence.append(item)
    return evidence


def _categories_for(technique_id: str) -> set[str]:
    if technique_id.startswith(("T1071", "T1571", "T1095")):
        return {"network"}
    if technique_id.startswith(("T1497", "T1622", "T1518", "T1003", "T1070", "T1222")):
        return {"file", "process"}
    if technique_id.startswith(("T1059", "T1055", "T1620")):
        return {"process", "memory"}
    return set()


def build_ocsf_findings(
    *,
    task_id: str,
    sample_name: str,
    mitre: Optional[dict] = None,
    evasion: Optional[dict] = None,
    events: Optional[list[dict]] = None,
    summary: Optional[dict] = None,
    limitations: Optional[list[str]] = None,
    generated_at_ms: Optional[int] = None,
) -> list[dict]:
    """Build the OCSF Detection Finding list for one run.

    One finding per mapped ATT&CK technique, plus an evasion finding when
    evasion was observed. The run summary and limitations are carried as the
    evidence ``data`` so a consumer can see what the engine could *not*
    establish without needing the Markdown report.
    """
    import time as _time

    events = list(events or [])
    mitre = mitre or {}
    summary = summary or {}
    limitations = list(limitations or [])
    time_ms = generated_at_ms if generated_at_ms is not None else int(_time.time() * 1000)

    context = {
        "sample": sample_name,
        "attack_version": mitre.get("attack_version", ""),
        "ocsf_schema_version": OCSF_SCHEMA_VERSION,
        "events_total": summary.get("events_total", len(events)),
        "limitations": limitations,
    }

    findings: list[dict] = []

    for technique in mitre.get("techniques", []) or []:
        tid = technique.get("subtechnique_id") or technique.get("technique_id") or ""
        name = technique.get("subtechnique_name") or technique.get("technique_name") or tid
        severity = _severity_for_confidence(technique.get("confidence", "medium"))
        evidence_data = {
            "attack_technique": {
                "id": technique.get("technique_id"),
                "subtechnique_id": technique.get("subtechnique_id", ""),
                "name": name,
                "tactic": technique.get("tactic", ""),
                "tactic_id": technique.get("tactic_id", ""),
                "source": technique.get("source", ""),
                "confidence": technique.get("confidence", ""),
                "detection_strategy_ids": technique.get("detection_strategy_ids", []),
            },
            "run": context,
        }
        evidences: list[dict] = [{"name": "attack-technique", "data": evidence_data}]
        evidences.extend(_event_evidence(events, tid))
        findings.append(
            _finding(
                task_id=task_id,
                title=f"ATT&CK {tid}: {name}",
                severity=severity,
                confidence=technique.get("confidence", "medium"),
                time_ms=time_ms,
                uid_key=tid,
                evidences=evidences,
                description=f"Observed behaviour maps to ATT&CK {tid} ({name}).",
            )
        )

    if evasion:
        verdict = str(evasion.get("verdict", "none"))
        score = int(evasion.get("score", 0))
        if verdict != "none":
            evidence_data = {
                "evasion": {
                    "score": score,
                    "verdict": verdict,
                    "impact_score": evasion.get("impact_score", 0),
                    "recon_then_quiet": evasion.get("recon_then_quiet", False),
                    "inconclusive": evasion.get("inconclusive", False),
                    "signals": evasion.get("signals", []),
                },
                "run": context,
            }
            findings.append(
                _finding(
                    task_id=task_id,
                    title=f"Evasion assessment: {verdict} ({score}/100)",
                    severity="high" if verdict == "evasive" else "medium",
                    confidence="medium",
                    time_ms=time_ms,
                    uid_key="evasion",
                    evidences=[{"name": "evasion-assessment", "data": evidence_data}],
                    description=(
                        "Recon-then-quiet behaviour is reported as inconclusive, "
                        "not clean." if evasion.get("inconclusive") else ""
                    ),
                )
            )

    if not findings:
        findings.append(
            _finding(
                task_id=task_id,
                title=f"No mapped ATT&CK behaviour: {sample_name}",
                severity="informational",
                confidence="low",
                time_ms=time_ms,
                uid_key="",
                evidences=[{"name": "run-summary", "data": context}],
                description=(
                    "No technique was mapped and no evasion was scored. This is not "
                    "evidence of benign behaviour; see the limitations."
                ),
            )
        )

    return findings


def _severity_for_confidence(confidence: str) -> str:
    return {"high": "high", "medium": "medium", "low": "low"}.get(
        str(confidence).lower(), "medium"
    )


# ---------------------------------------------------------------------------
# Validation against the pinned schema
# ---------------------------------------------------------------------------


def validate_finding(finding: dict, schema: Optional[dict] = None) -> list[str]:
    """Return every reason ``finding`` is not a valid OCSF Detection Finding."""
    schema = schema or load_schema()
    problems: list[str] = []

    for field_name in schema.get("required_fields", []):
        if field_name not in finding:
            problems.append(f"missing required field {field_name!r}")

    categories = schema.get("categories", {})
    category_uid = finding.get("category_uid")
    if category_uid is not None and str(category_uid) not in {str(k) for k in categories}:
        problems.append(f"category_uid {category_uid!r} is not a pinned OCSF category")

    classes = schema.get("classes", {})
    class_uid = finding.get("class_uid")
    class_def = classes.get(str(class_uid)) if class_uid is not None else None
    if class_uid is not None and class_def is None:
        problems.append(f"class_uid {class_uid!r} is not a pinned OCSF class")
    elif class_def is not None and category_uid is not None:
        if int(category_uid) != int(class_def.get("category_uid", -1)):
            problems.append(
                f"class_uid {class_uid} belongs to category {class_def.get('category_uid')}, "
                f"not {category_uid}"
            )

    for enum_field in ("severity_id", "confidence_id"):
        allowed = {str(k) for k in schema.get(enum_field, {})}
        value = finding.get(enum_field)
        if value is not None and str(value) not in allowed:
            problems.append(f"{enum_field} {value!r} is not a pinned OCSF enum value")

    metadata = finding.get("metadata") or {}
    for field_name in schema.get("metadata_required_fields", []):
        if field_name not in metadata:
            problems.append(f"metadata is missing required field {field_name!r}")
    if metadata.get("version") not in (OCSF_SCHEMA_VERSION,):
        problems.append(
            f"metadata.version {metadata.get('version')!r} does not cite OCSF {OCSF_SCHEMA_VERSION}"
        )

    finding_info = finding.get("finding_info") or {}
    for field_name in schema.get("finding_info_required_fields", []):
        if field_name not in finding_info:
            problems.append(f"finding_info is missing required field {field_name!r}")

    time_value = finding.get("time")
    if not isinstance(time_value, int) or time_value <= 0:
        problems.append("time must be a positive UTC epoch value in milliseconds")

    for index, evidence in enumerate(finding.get("evidences", []) or []):
        if not any(key in evidence for key in schema.get("evidence_required_any", [])):
            problems.append(f"evidences[{index}] has none of the schema's evidence fields")

    expected_type_uid = int(class_uid) * 100 + int(finding.get("activity_id", 0)) if class_uid is not None else None
    if expected_type_uid is not None and finding.get("type_uid") != expected_type_uid:
        problems.append(
            f"type_uid {finding.get('type_uid')!r} does not equal "
            f"class_uid*100+activity_id ({expected_type_uid})"
        )

    return problems


def validate_all(findings: list[dict], schema: Optional[dict] = None) -> list[str]:
    schema = schema or load_schema()
    problems: list[str] = []
    for index, finding in enumerate(findings):
        for problem in validate_finding(finding, schema):
            problems.append(f"finding[{index}]: {problem}")
    return problems


__all__ = [
    "DETECTION_FINDING_CLASS_UID",
    "OCSF_SCHEMA_VERSION",
    "build_ocsf_findings",
    "confidence_id",
    "load_schema",
    "severity_id",
    "validate_all",
    "validate_finding",
]
