"""Run triage under a fail-closed contract. Nothing here trusts the model.

The orchestration is deliberately boring, because the interesting part is the
list of situations in which HATCHERY refuses to give a verdict:

* no Ollama, no model, no boundary  -> ``unavailable`` / ``error``
* the model times out              -> ``timeout``
* the response is not valid JSON, or fails the contract, after retries
                                   -> ``inconclusive`` (the error is recorded)
* there is no citable evidence     -> ``inconclusive``
* every finding failed grounding   -> ``inconclusive``
* the model returns a confident verdict but no surviving grounded finding
                                   -> ``inconclusive``

In every one of those cases ``inconclusive`` is ``True`` and the reason is a
plain-language string. A triage section is never rendered as "the model says the
sample is clean" when what actually happened is "the model said nothing that
could be tied to this run".
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Optional

from engine.triage.client import (
    DEFAULT_BASE_URL,
    OllamaClient,
    OllamaError,
    TriageClient,
)
from engine.triage.context import DEFAULT_MAX_CHARS, DEFAULT_MAX_EVENTS, build_evidence
from engine.triage.contract import (
    PROMPT_CONTRACT_VERSION,
    RESPONSE_SCHEMA,
    build_messages,
    contract_hash,
    parse_response,
)
from engine.triage.grounding import apply_grounding

logger = logging.getLogger(__name__)

TRIAGE_STATE_COMPLETED = "completed"
TRIAGE_STATE_INCONCLUSIVE = "inconclusive"
TRIAGE_STATE_UNAVAILABLE = "unavailable"
TRIAGE_STATE_ERROR = "error"
TRIAGE_STATE_TIMEOUT = "timeout"

_MAX_ERRORS_KEPT = 3


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


@dataclass
class TriageConfig:
    """Operator-tunable triage settings.

    Defaults are chosen for a weak machine and a privacy-first posture: a small
    local model, a bounded context, and a refusal to use anything remote.
    """

    model: str = ""
    base_url: str = DEFAULT_BASE_URL
    timeout: float = 180.0
    max_attempts: int = 2
    num_ctx: int = 8192
    temperature: float = 0.0
    seed: int = 0
    allow_remote: bool = False
    allow_cloud_model: bool = False
    keep_alive: str = "5m"
    max_evidence_chars: int = DEFAULT_MAX_CHARS
    max_events: int = DEFAULT_MAX_EVENTS

    @classmethod
    def from_env(cls) -> "TriageConfig":
        """Build from ``HATCHERY_TRIAGE_*`` / ``HATCHERY_OLLAMA_*`` variables."""
        def _float(name: str, default: float) -> float:
            try:
                return float(os.environ.get(name, "") or default)
            except (TypeError, ValueError):
                return default

        def _int(name: str, default: int) -> int:
            try:
                return int(os.environ.get(name, "") or default)
            except (TypeError, ValueError):
                return default

        return cls(
            model=os.environ.get("HATCHERY_TRIAGE_MODEL", "").strip(),
            base_url=(
                os.environ.get("HATCHERY_OLLAMA_URL", "").strip() or DEFAULT_BASE_URL
            ),
            timeout=_float("HATCHERY_TRIAGE_TIMEOUT", 180.0),
            max_attempts=_int("HATCHERY_TRIAGE_ATTEMPTS", 2),
            num_ctx=_int("HATCHERY_TRIAGE_NUM_CTX", 8192),
            allow_remote=_env_flag("HATCHERY_TRIAGE_ALLOW_REMOTE"),
            allow_cloud_model=_env_flag("HATCHERY_TRIAGE_ALLOW_CLOUD"),
        )


def _base_section(config: TriageConfig, evidence_ids: int, evidence_chars: int) -> dict[str, Any]:
    return {
        "available": False,
        "status": TRIAGE_STATE_UNAVAILABLE,
        "verdict": "inconclusive",
        "confidence": 0,
        "summary": "",
        "findings": [],
        "findings_dropped": 0,
        "dropped": [],
        "not_established": [],
        "recommended_actions": [],
        "techniques": [],
        "techniques_rejected": [],
        "grounding": {},
        "model": config.model,
        "base_url": config.base_url,
        "allowed_remote": config.allow_remote,
        "allowed_cloud_model": config.allow_cloud_model,
        "prompt_version": PROMPT_CONTRACT_VERSION,
        "contract_hash": contract_hash(),
        "evidence_ids": evidence_ids,
        "evidence_chars": evidence_chars,
        "evidence_truncated": False,
        "attempts": 0,
        "duration_ms": 0,
        "inconclusive": True,
        "reason": None,
        "error": None,
        "limitations": [],
    }


def _finish(section: dict[str, Any], *, reason: str) -> dict[str, Any]:
    section["reason"] = reason
    section["limitations"] = [reason]
    return section


def run_triage(
    bundle: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    config: Optional[TriageConfig] = None,
    client: Optional[TriageClient] = None,
    dataset: Any = None,
) -> dict[str, Any]:
    """Run triage on one bundle and return the ``triage`` bundle section.

    Never raises. Every failure path returns ``inconclusive=True`` with a plain
    reason, because a triage that failed is not a triage that found nothing.
    """
    cfg = config or TriageConfig()
    started = time.monotonic()

    evidence = build_evidence(
        bundle, events, max_events=cfg.max_events, max_chars=cfg.max_evidence_chars
    )
    rendered = evidence.render()
    section = _base_section(cfg, len(evidence.ids), len(rendered))
    section["evidence_truncated"] = evidence.truncated

    if not evidence.ids:
        return _finish(
            section,
            reason=(
                "No citable evidence was available for this run, so no triage "
                "verdict can be grounded. Treat as INCONCLUSIVE."
            ),
        )

    if client is None:
        try:
            client = OllamaClient(
                model=cfg.model,
                base_url=cfg.base_url,
                timeout=cfg.timeout,
                num_ctx=cfg.num_ctx,
                temperature=cfg.temperature,
                seed=cfg.seed,
                allow_remote=cfg.allow_remote,
                allow_cloud_model=cfg.allow_cloud_model,
                keep_alive=cfg.keep_alive,
            )
        except OllamaError as exc:
            section["status"] = TRIAGE_STATE_ERROR
            section["error"] = str(exc)
            return _finish(section, reason=f"Triage client could not start: {exc}")

    try:
        model = client.resolve_model()
    except OllamaError as exc:
        section["status"] = TRIAGE_STATE_UNAVAILABLE
        section["error"] = str(exc)
        return _finish(section, reason=f"Triage model unavailable: {exc}")

    section["model"] = model
    messages = build_messages(rendered)

    clean: dict[str, Any] = {}
    errors: list[str] = []
    attempts = 0
    transport_error = False
    while attempts < max(1, cfg.max_attempts):
        attempts += 1
        section["attempts"] = attempts
        try:
            raw = client.chat(messages, RESPONSE_SCHEMA, model=model)
        except OllamaError as exc:
            message = str(exc)
            errors.append(message)
            transport_error = True
            if "timed out" in message:
                section["status"] = TRIAGE_STATE_TIMEOUT
                section["error"] = message
                section["duration_ms"] = int((time.monotonic() - started) * 1000)
                return _finish(section, reason=f"Triage model timed out: {message}")
            section["status"] = TRIAGE_STATE_ERROR
            section["error"] = message
            continue

        clean, parse_errors = parse_response(raw)
        if not parse_errors:
            errors = []
            break
        clean = {}
        errors = parse_errors
        logger.warning("Triage attempt %d rejected: %s", attempts, parse_errors[0])

    section["duration_ms"] = int((time.monotonic() - started) * 1000)

    if not clean:
        section["status"] = TRIAGE_STATE_ERROR if transport_error else TRIAGE_STATE_INCONCLUSIVE
        section["error"] = "; ".join(errors[:_MAX_ERRORS_KEPT])
        return _finish(
            section,
            reason=(
                "The triage model did not return a usable response after "
                f"{attempts} attempt(s): {section['error'] or 'no response'}. "
                "Treat as INCONCLUSIVE."
            ),
        )

    invalid_findings = clean.pop("invalid_findings", [])
    grounded, dropped, stats = apply_grounding(clean, evidence.ids, dataset)
    if invalid_findings:
        stats.findings_dropped += len(invalid_findings)
        dropped = [
            {
                "claim": "<malformed finding>",
                "reason": str(item.get("reason") or "malformed"),
                "citations": [],
            }
            for item in invalid_findings
        ] + dropped
    section.update(
        {
            "verdict": grounded["verdict"],
            "confidence": grounded["confidence"],
            "summary": grounded["summary"],
            "findings": grounded["findings"],
            "findings_dropped": stats.findings_dropped,
            "dropped": dropped,
            "not_established": grounded["not_established"],
            "recommended_actions": grounded["recommended_actions"],
            "techniques": stats.techniques_accepted,
            "techniques_rejected": stats.techniques_rejected,
            "grounding": stats.to_dict(),
        }
    )

    if not grounded["findings"]:
        section["status"] = TRIAGE_STATE_INCONCLUSIVE
        section["verdict"] = "inconclusive"
        section["available"] = False
        section["inconclusive"] = True
        return _finish(
            section,
            reason=(
                f"The model returned {stats.findings_dropped} finding(s) but none "
                "cited evidence that exists in this run, so nothing it said can be "
                "tied to the analysis. Treat as INCONCLUSIVE."
            ),
        )

    section["status"] = TRIAGE_STATE_COMPLETED
    section["available"] = True
    section["inconclusive"] = grounded["verdict"] == "inconclusive"
    return section


def unavailable_section(reason: str, config: Optional[TriageConfig] = None) -> dict[str, Any]:
    """A declared 'triage was not run' section, for the opt-out path."""
    cfg = config or TriageConfig()
    section = _base_section(cfg, 0, 0)
    return _finish(section, reason=reason)


__all__ = [
    "TRIAGE_STATE_COMPLETED",
    "TRIAGE_STATE_ERROR",
    "TRIAGE_STATE_INCONCLUSIVE",
    "TRIAGE_STATE_TIMEOUT",
    "TRIAGE_STATE_UNAVAILABLE",
    "TriageConfig",
    "run_triage",
    "unavailable_section",
]
