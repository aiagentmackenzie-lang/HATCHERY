"""Signal extraction for replay (D26).

Two bundles are only comparable if the comparison separates what *must* match
from what *cannot*. This module pulls the signals out of an analysis bundle and
labels them deterministic or volatile. The classification is the design: a
sandbox that claims bit-for-bit reproducibility for event counts is lying, and a
replay that does not fail on a changed YARA match is useless.

Nothing here mutates a bundle. The replay section is written by
:mod:`engine.replay.replay`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Static facts about the bytes. These must be identical or the replay failed.
DETERMINISTIC_KINDS: dict[str, str] = {
    "sha256": "scalar",
    "md5": "scalar",
    "sha1": "scalar",
    "file_type": "scalar",
    "delivery_format": "scalar",
    "delivery_children": "set",
    "yara_rules": "set",
    "capa_capabilities": "set",
    "attack_techniques": "set",
    "static_iocs": "set",
}

# Observations a sandbox/emulator cannot guarantee bit-for-bit. Drift here is
# reported, never failed on.
VOLATILE_KINDS: dict[str, str] = {
    "events_total": "scalar",
    "events_by_category": "mapping",
    "events_by_severity": "mapping",
    "iocs_total": "scalar",
    "ioc_value_order": "sequence",
    "sandbox_status": "scalar",
    "sandbox_duration_seconds": "scalar",
    "evasion_score": "scalar",
    "emulation_api_calls": "scalar",
    "emulation_events_written": "scalar",
}

# IOC sources produced by the deterministic static pipeline. Behavioural
# sources (strace / file_watch / network / emulation) are excluded: they are
# volatile by nature and compared as part of the count, not the set.
STATIC_IOC_SOURCES: frozenset[str] = frozenset({"static", "yara", "capa", "delivery"})


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


@dataclass(frozen=True)
class Signals:
    """The comparable signals for one bundle."""

    deterministic: dict[str, Any] = field(default_factory=dict)
    volatile: dict[str, Any] = field(default_factory=dict)
    unknown: tuple[str, ...] = ()
    """Deterministic signal names whose source section is absent from the bundle."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "deterministic": {
                name: sorted(value) if isinstance(value, (set, frozenset)) else value
                for name, value in sorted(self.deterministic.items())
            },
            "volatile": dict(sorted(self.volatile.items())),
            "unknown": list(self.unknown),
        }


def _unknown_deterministic(bundle: dict[str, Any]) -> tuple[str, ...]:
    """Signal names the bundle cannot establish because its section is missing.

    An older bundle predates a stage (for example delivery intake before D19), so
    the replay has nothing to compare against. That is reported as UNKNOWN and
    makes the replay inconclusive, never a silent pass.
    """
    unknown: list[str] = []
    if not isinstance(bundle.get("sample"), dict):
        unknown += ["sha256", "md5", "sha1", "file_type"]
    static = bundle.get("static")
    if not isinstance(static, dict):
        unknown += [
            "delivery_format",
            "delivery_children",
            "yara_rules",
            "capa_capabilities",
            "static_iocs",
        ]
    else:
        if not isinstance(static.get("delivery"), dict):
            unknown += ["delivery_format", "delivery_children"]
        if not isinstance(static.get("yara"), dict):
            unknown.append("yara_rules")
        if not isinstance(static.get("capa"), dict):
            unknown.append("capa_capabilities")
    if not isinstance(bundle.get("mitre"), dict):
        unknown.append("attack_techniques")
    if not isinstance(bundle.get("iocs"), list):
        unknown.append("static_iocs")
    return tuple(unknown)


def extract_signals(bundle: dict[str, Any]) -> Signals:
    """Extract the deterministic and volatile signals from one bundle."""
    bundle = bundle if isinstance(bundle, dict) else {}
    sample = _mapping(bundle.get("sample"))
    static = _mapping(bundle.get("static"))
    delivery = _mapping(static.get("delivery"))
    yara = _mapping(static.get("yara"))
    capa = _mapping(static.get("capa"))
    mitre = _mapping(bundle.get("mitre"))
    iocs = _list(bundle.get("iocs"))
    sandbox = bundle.get("sandbox")
    sandbox = sandbox if isinstance(sandbox, dict) else {}
    summary = _mapping(bundle.get("summary"))
    evasion = _mapping(bundle.get("evasion"))
    emulation = _mapping(bundle.get("emulation"))

    delivery_children = {
        _text(child.get("sha256")) or _text(child.get("name"))
        for child in _list(delivery.get("children"))
        if isinstance(child, dict)
        and (_text(child.get("sha256")) or _text(child.get("name")))
    }

    yara_rules = {
        _text(match.get("rule"))
        for match in _list(yara.get("matches"))
        if isinstance(match, dict) and _text(match.get("rule"))
    }
    capa_capabilities = {
        _text(cap.get("name"))
        for cap in _list(capa.get("capabilities"))
        if isinstance(cap, dict) and _text(cap.get("name"))
    }
    attack_techniques = {
        _text(tech.get("technique_id")).upper()
        for tech in _list(mitre.get("techniques"))
        if isinstance(tech, dict) and _text(tech.get("technique_id"))
    }
    static_iocs = {
        f"{_text(ioc.get('type'))}:{_text(ioc.get('value'))}"
        for ioc in iocs
        if isinstance(ioc, dict)
        and _text(ioc.get("source")) in STATIC_IOC_SOURCES
        and (_text(ioc.get("type")) or _text(ioc.get("value")))
    }
    ioc_order = tuple(
        f"{_text(ioc.get('type'))}:{_text(ioc.get('value'))}"
        for ioc in iocs
        if isinstance(ioc, dict)
    )

    deterministic: dict[str, Any] = {
        "sha256": _text(sample.get("sha256")).lower(),
        "md5": _text(sample.get("md5")).lower(),
        "sha1": _text(sample.get("sha1")).lower(),
        "file_type": _text(sample.get("file_type")),
        "delivery_format": _text(delivery.get("format")) or "unknown",
        "delivery_children": frozenset(delivery_children),
        "yara_rules": frozenset(yara_rules),
        "capa_capabilities": frozenset(capa_capabilities),
        "attack_techniques": frozenset(attack_techniques),
        "static_iocs": frozenset(static_iocs),
    }

    volatile: dict[str, Any] = {
        "events_total": int(summary.get("events_total") or 0),
        "events_by_category": dict(_mapping(summary.get("events_by_category"))),
        "events_by_severity": dict(_mapping(summary.get("events_by_severity"))),
        "iocs_total": len(iocs),
        "ioc_value_order": ioc_order,
        "sandbox_status": _text(sandbox.get("status")),
        "sandbox_duration_seconds": round(float(sandbox.get("duration_seconds") or 0.0), 3),
        "evasion_score": int(evasion.get("score") or 0),
        "emulation_api_calls": int(emulation.get("api_calls") or 0),
        "emulation_events_written": int(emulation.get("events_written") or 0),
    }

    return Signals(
        deterministic=deterministic,
        volatile=volatile,
        unknown=_unknown_deterministic(bundle),
    )


__all__ = [
    "DETERMINISTIC_KINDS",
    "STATIC_IOC_SOURCES",
    "VOLATILE_KINDS",
    "Signals",
    "extract_signals",
]
