"""Derive a comparison fingerprint from an analysis bundle.

The fingerprint is a set of tokens per category — capabilities, YARA rules,
ATT&CK techniques, IOCs, PE imports, exports, section names, the import hash, the
compile timestamp, emulated APIs and classified strings. Every token is
normalised (lowercased, trimmed) so two runs that observed the same thing produce
the same token.

Only what the engine already recorded is used: the fingerprint cannot introduce a
fact the analysis did not establish. It is derived on demand and is never written
back into the bundle, so there is one producer of analysis data (D4).

Nothing here is PII beyond the sample's own artefacts, and nothing is uploaded —
clustering runs entirely on the local results directory.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from engine.bundle import ANALYSIS_FILENAME, load_bundle

logger = logging.getLogger(__name__)

# How much each category counts when two fingerprints are compared. An exact
# import-hash or export match is strong lineage evidence; a shared generic
# capability ("create process") is weak. The weights encode that.
CATEGORY_WEIGHTS: dict[str, float] = {
    "imphash": 2.5,
    "import": 2.0,
    "export": 2.0,
    "compile_time": 1.0,
    "capa": 1.5,
    "emulation_api": 1.5,
    "rule": 1.0,
    "technique": 1.0,
    "ioc": 1.0,
    "string": 0.5,
    "section": 0.5,
    "suspicious": 0.5,
}

ALL_CATEGORIES: tuple[str, ...] = tuple(CATEGORY_WEIGHTS)


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _tokens(value: Any, *, lower: bool = True) -> set[str]:
    out: set[str] = set()
    for item in _items(value):
        text = _text(item)
        if text:
            out.add(text.lower() if lower else text)
    return out


def _import_hash(imports: list[Any]) -> str:
    """A pefile-style import hash over ``dll.function`` pairs, or ``""``.

    The real imphash lowercases, strips extensions and joins with commas; this
    matches that shape so two binaries linked against the same libraries collide,
    which is the point. It is computed here rather than imported so a missing
    optional dependency cannot silently drop the strongest lineage signal.
    """
    pairs: list[str] = []
    for entry in imports:
        if not isinstance(entry, dict):
            continue
        dll = _text(entry.get("dll")).lower()
        if dll.endswith((".dll", ".ocx", ".sys")):
            dll = dll.rsplit(".", 1)[0]
        func = _text(entry.get("function")).lower()
        if func:
            pairs.append(f"{dll}.{func}" if dll else func)
    if not pairs:
        return ""
    return hashlib.md5(",".join(sorted(pairs)).encode("utf-8")).hexdigest()


def _strings_tokens(strings: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("urls", "ips", "domains", "file_paths", "registry_keys", "emails"):
        for value in _items(strings.get(key)):
            text = _text(value).lower()
            if text:
                tokens.add(f"{key}:{text}")
    return tokens


def features_from_bundle(bundle: dict[str, Any]) -> dict[str, set[str]]:
    """Build the per-category token sets for one bundle."""
    bundle = bundle if isinstance(bundle, dict) else {}
    static = bundle.get("static") or {}
    pe = static.get("pe") or {}
    strings = static.get("strings") or {}
    mitre = bundle.get("mitre") or {}
    emulation = bundle.get("emulation") or {}
    emulation_config = emulation.get("config") or {}

    features: dict[str, set[str]] = {}

    features["capa"] = {
        _text(cap.get("name")).lower()
        for cap in _items((static.get("capa") or {}).get("capabilities"))
        if isinstance(cap, dict) and _text(cap.get("name"))
    }
    features["rule"] = {
        _text(match.get("rule")).lower()
        for match in _items((static.get("yara") or {}).get("matches"))
        if isinstance(match, dict) and _text(match.get("rule"))
    }
    features["technique"] = {
        _text(tech.get("technique_id")).upper()
        for tech in _items(mitre.get("techniques"))
        if isinstance(tech, dict) and _text(tech.get("technique_id"))
    }
    features["ioc"] = {
        _text(ioc.get("value")).lower()
        for ioc in _items(bundle.get("iocs"))
        if isinstance(ioc, dict) and _text(ioc.get("value"))
    }

    features["import"] = {
        f"{_text(entry.get('dll')).lower()}!{_text(entry.get('function')).lower()}"
        for entry in _items(pe.get("imports"))
        if isinstance(entry, dict) and _text(entry.get("function"))
    }
    features["export"] = {
        _text(entry).lower() for entry in _items(pe.get("exports")) if _text(entry)
    }
    features["section"] = {
        _text(section.get("name")).lower()
        for section in _items(pe.get("sections"))
        if isinstance(section, dict) and _text(section.get("name"))
    }
    features["suspicious"] = {
        _text(item).lower()
        for item in _items(pe.get("suspicious_indicators"))
        if _text(item)
    }
    import_hash = _import_hash(_items(pe.get("imports")))
    features["imphash"] = {import_hash} if import_hash else set()

    compile_time = _text(pe.get("compile_timestamp"))
    # Zeroed/absent timestamps are common and must not become a shared "feature".
    if compile_time and not compile_time.startswith(("1970", "1970-01-01", "None")):
        features["compile_time"] = {compile_time}

    features["emulation_api"] = {
        _text(name).lower()
        for name in (emulation_config.get("api_calls") or {})
        if _text(name)
    }
    features["string"] = _strings_tokens(strings)

    return {key: value for key, value in features.items() if value}


@dataclass(frozen=True)
class Fingerprint:
    """A comparison fingerprint for one run."""

    task_id: str
    sha256: str = ""
    file_name: str = ""
    file_type: str = ""
    delivery_format: str = ""
    features: dict[str, frozenset[str]] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Stable id over the feature content (not the task id).

        Two runs of identical content share this id; it is a content address, not
        a run identity. Use :attr:`key` when you need a per-run handle.
        """
        payload = json.dumps(
            {key: sorted(value) for key, value in sorted(self.features.items())},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @property
    def key(self) -> str:
        """A handle unique to this run (task id, else the content id)."""
        return self.task_id or self.id

    @property
    def token_count(self) -> int:
        return sum(len(value) for value in self.features.values())

    def tokens(self) -> list[str]:
        """Every token, prefixed by category, for the simhash."""
        out: list[str] = []
        for category, values in self.features.items():
            out.extend(f"{category}:{token}" for token in values)
        return sorted(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "sha256": self.sha256,
            "file_name": self.file_name,
            "file_type": self.file_type,
            "delivery_format": self.delivery_format,
            "token_count": self.token_count,
            "features": {key: sorted(value) for key, value in sorted(self.features.items())},
        }


def fingerprint_from_bundle(bundle: dict[str, Any], *, task_id: str = "") -> Fingerprint:
    """Build a fingerprint from an already-loaded bundle."""
    bundle = bundle if isinstance(bundle, dict) else {}
    sample = bundle.get("sample") or {}
    delivery = (bundle.get("static") or {}).get("delivery") or {}
    features = features_from_bundle(bundle)
    return Fingerprint(
        task_id=task_id or _text(bundle.get("task_id")),
        sha256=_text(sample.get("sha256")),
        file_name=_text(sample.get("file_name")),
        file_type=_text(sample.get("file_type")),
        delivery_format=_text(delivery.get("format")),
        features={key: frozenset(value) for key, value in features.items()},
    )


def fingerprint_from_run(run_dir: Path) -> Fingerprint:
    """Load ``analysis.json`` from a run directory and fingerprint it."""
    return fingerprint_from_bundle(load_bundle(run_dir))


def find_run_dirs(root: Path) -> list[Path]:
    """Every directory under ``root`` containing an ``analysis.json``.

    Accepts both ``results/<task>/bundle/analysis.json`` and a bare run
    directory, so ``hatchery cluster results/`` and ``hatchery cluster
    results/<task>`` both work.
    """
    root = Path(root)
    if not root.exists():
        return []
    if (root / ANALYSIS_FILENAME).exists():
        return [root]
    return sorted({path.parent for path in root.rglob(ANALYSIS_FILENAME)})


def load_fingerprints(root: Path, *, limit: Optional[int] = None) -> list[Fingerprint]:
    """Fingerprint every run under ``root``, skipping unreadable bundles.

    A broken run is logged and skipped: clustering one bad bundle must not abort
    the whole campaign view.
    """
    fingerprints: list[Fingerprint] = []
    for run_dir in find_run_dirs(root):
        try:
            fingerprints.append(fingerprint_from_run(run_dir))
        except (OSError, ValueError, KeyError) as exc:
            logger.warning("Skipping %s: %s", run_dir, exc)
        if limit is not None and len(fingerprints) >= limit:
            break
    return fingerprints


__all__ = [
    "ALL_CATEGORIES",
    "CATEGORY_WEIGHTS",
    "Fingerprint",
    "features_from_bundle",
    "find_run_dirs",
    "fingerprint_from_bundle",
    "fingerprint_from_run",
    "load_fingerprints",
]
