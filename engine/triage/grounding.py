"""Grounding: a claim survives only if its citations resolve to real evidence.

An LLM asked to cite evidence will cite it — approximately. It appends
descriptions (``event:2 file CREATE /etc/cron.d/persist``), wraps ids in
backticks, or invents an id entirely. A triage result is only useful if every
surviving claim can be tied back to something the engine actually observed, so
this module:

* normalises a citation to the longest *known* evidence id it starts with, and
  only when the next character is a boundary (so ``event:1`` never matches
  ``event:12``);
* drops any finding left with no resolvable citation, and records why;
* validates any model-proposed ATT&CK technique id against the pinned dataset
  (D15) — a model may not introduce a technique the dataset does not contain,
  and an accepted association is labelled *model-suggested*, because validating
  an id is not proving the association.

The fail-closed decision itself lives in :mod:`engine.triage.triage`.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# A character that may follow a citation id without it being a longer id.
_CITATION_BOUNDARY = set(" \t,;:).]}-—/|")
_TECHNIQUE_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)")


def normalize_citation(raw: Any, ids: set[str]) -> Optional[str]:
    """Return the evidence id ``raw`` cites, or ``None`` if nothing resolves."""
    if not isinstance(raw, str):
        return None
    candidate = raw.strip().strip("`'\"()[]{}<>").strip()
    if not candidate:
        return None
    if candidate in ids:
        return candidate
    best: Optional[str] = None
    for known in ids:
        if not candidate.startswith(known):
            continue
        following = candidate[len(known) : len(known) + 1]
        if following and following not in _CITATION_BOUNDARY:
            continue
        if best is None or len(known) > len(best):
            best = known
    return best


@dataclass
class GroundingStats:
    """What grounding did to a model response."""

    findings_kept: int = 0
    findings_dropped: int = 0
    citations_valid: int = 0
    citations_invalid: int = 0
    techniques_accepted: list[str] = field(default_factory=list)
    techniques_rejected: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings_kept": self.findings_kept,
            "findings_dropped": self.findings_dropped,
            "citations_valid": self.citations_valid,
            "citations_invalid": self.citations_invalid,
            "techniques_accepted": list(self.techniques_accepted),
            "techniques_rejected": list(self.techniques_rejected),
        }


def ground_findings(
    findings: list[dict[str, Any]], ids: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], GroundingStats]:
    """Resolve citations on every finding; drop the ones that cannot be grounded."""
    stats = GroundingStats()
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []

    for finding in findings:
        claim = str(finding.get("claim") or "").strip()
        raw_citations = finding.get("grounding") or []
        resolved: list[str] = []
        invalid: list[str] = []
        for raw in raw_citations:
            match = normalize_citation(raw, ids)
            if match:
                stats.citations_valid += 1
                if match not in resolved:
                    resolved.append(match)
            else:
                stats.citations_invalid += 1
                invalid.append(str(raw))

        if not resolved:
            stats.findings_dropped += 1
            dropped.append(
                {
                    "claim": claim,
                    "reason": "no citation resolved to a known evidence id",
                    "citations": invalid,
                }
            )
            continue

        stats.findings_kept += 1
        kept.append(
            {
                "claim": claim,
                "grounding": resolved,
                "invalid_citations": invalid,
                "technique_ids": list(finding.get("technique_ids") or []),
            }
        )

    return kept, dropped, stats


def normalize_technique(value: Any) -> Optional[str]:
    """Extract a technique id from a model string, or ``None``."""
    if not isinstance(value, str):
        return None
    match = _TECHNIQUE_RE.match(value.strip().strip("`'\"[]"))
    return match.group(1) if match else None


def validate_techniques(
    values: list[Any], dataset: Any = None
) -> tuple[list[str], list[str]]:
    """Split model-proposed technique ids into validated and rejected (D15).

    Uses the pinned ATT&CK dataset so a model cannot introduce an unknown,
    revoked or deprecated technique. Rejected ids are recorded, never emitted.
    """
    if dataset is None:
        from engine.export.attack_dataset import default_dataset

        dataset = default_dataset()

    accepted: list[str] = []
    rejected: list[str] = []
    for value in values:
        technique_id = normalize_technique(value)
        if not technique_id:
            rejected.append(str(value))
            continue
        problems = dataset.validate_technique(technique_id)
        if problems:
            rejected.append(f"{technique_id}: {problems[0]}")
            continue
        if technique_id not in accepted:
            accepted.append(technique_id)
    return accepted, rejected


def apply_grounding(
    clean: dict[str, Any], ids: set[str], dataset: Any = None
) -> tuple[dict[str, Any], list[dict[str, Any]], GroundingStats]:
    """Ground a validated triage object. Returns ``(grounded, dropped, stats)``.

    Per-finding ``technique_ids`` are validated against the pinned dataset;
    accepted ids are returned on the finding marked ``model_suggested`` so
    nobody mistakes them for the engine's own validated mapping.
    """
    findings, dropped, stats = ground_findings(clean.get("findings") or [], ids)

    for finding in findings:
        accepted, rejected = validate_techniques(finding.pop("technique_ids", []), dataset)
        if accepted:
            finding["technique_ids"] = accepted
            finding["technique_source"] = "model-suggested (unvalidated association)"
        stats.techniques_accepted.extend(
            t for t in accepted if t not in stats.techniques_accepted
        )
        stats.techniques_rejected.extend(rejected)

    grounded = dict(clean)
    grounded["findings"] = findings
    return grounded, dropped, stats


__all__ = [
    "GroundingStats",
    "apply_grounding",
    "ground_findings",
    "normalize_citation",
    "normalize_technique",
    "validate_techniques",
]
