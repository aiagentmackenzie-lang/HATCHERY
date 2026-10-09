"""Pinned MITRE ATT&CK Enterprise dataset — the single source of truth.

`engine.export.mitre_map` no longer hardcodes technique names, tactics or
deprecation state; it resolves them here. The pinned artifact is derived from
MITRE's `attack-stix-data` repository by ``scripts/refresh_attack_dataset.py``
and carries the source URL, the ATT&CK version string and the SHA256 of the
source bytes in its header, so a mapping mistake is a test failure rather than a
silent lie.

Why this exists (docs/DECISIONS.md D15): the previous mapper hardcoded IDs and
got several wrong — `clone` was "Process Injection", `bind` was
"Lateral Tool Transfer" labelled Non-Standard Port, `/etc/hosts` was
"Modify Registry" on Linux, every `connect` was T1071 regardless of protocol.
A hand-maintained lookup with no validation drifts silently. This module cannot
invent a technique: an unknown, revoked or deprecated ID is an error.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

ATTACK_VERSION = "19.2"
ATTACK_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
ATTACK_SOURCE_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"

DATASET_DIR = Path(__file__).parent / "attack"
DEFAULT_DATASET_PATH = DATASET_DIR / f"dataset-{ATTACK_VERSION}.json"


class AttackMappingError(RuntimeError):
    """Raised when a mapping emits a technique the pinned dataset rejects."""


@dataclass(frozen=True)
class TechniqueRecord:
    """One ATT&CK technique as pinned in the dataset."""

    technique_id: str
    name: str
    tactics: tuple[str, ...]
    url: str = ""
    parent: str = ""
    is_subtechnique: bool = False
    is_revoked: bool = False
    is_deprecated: bool = False
    detection_strategy_ids: tuple[str, ...] = field(default_factory=tuple)

    @property
    def usable(self) -> bool:
        """A technique an observation may map to: not revoked, not deprecated."""
        return not (self.is_revoked or self.is_deprecated)


class AttackDataset:
    """The pinned ATT&CK dataset, loaded from the compact artifact."""

    def __init__(self, data: dict, path: Optional[Path] = None) -> None:
        self._data = data
        self.path = path
        meta = data.get("meta", {})
        self.version: str = str(meta.get("version", ATTACK_VERSION))
        self.spec_version: str = str(meta.get("spec_version", ""))
        self.source_url: str = str(meta.get("source_url", ATTACK_SOURCE_URL))
        self.source_sha256: str = str(meta.get("source_sha256", ""))
        self.tactic_names: dict[str, str] = dict(data.get("tactics", {}))
        self._techniques: dict[str, TechniqueRecord] = {}
        for tid, raw in (data.get("techniques") or {}).items():
            self._techniques[tid] = TechniqueRecord(
                technique_id=tid,
                name=str(raw.get("name", "")),
                tactics=tuple(raw.get("tactics") or ()),
                url=str(raw.get("url", "")),
                parent=str(raw.get("parent", "")),
                is_subtechnique=bool(raw.get("is_subtechnique", False)),
                is_revoked=bool(raw.get("is_revoked", False)),
                is_deprecated=bool(raw.get("is_deprecated", False)),
                detection_strategy_ids=tuple(raw.get("detection_strategy_ids") or ()),
            )

    # ------------------------------------------------------------- accessors

    @property
    def techniques(self) -> dict[str, TechniqueRecord]:
        return dict(self._techniques)

    def __len__(self) -> int:
        return len(self._techniques)

    def get(self, technique_id: str) -> Optional[TechniqueRecord]:
        return self._techniques.get(technique_id)

    def tactic_display(self, shortname: str) -> str:
        """Human name for a tactic shortname (``stealth`` -> ``Stealth``)."""
        return self.tactic_names.get(shortname, shortname)

    def tactics_for(self, technique_id: str) -> tuple[str, ...]:
        record = self.get(technique_id)
        return record.tactics if record else ()

    # ------------------------------------------------------------ validation

    def validate_technique(self, technique_id: str, tactic: str = "") -> list[str]:
        """Return every reason ``technique_id``/``tactic`` is not valid.

        An empty list means valid. Unknown, revoked, deprecated or
        wrong-tactic mappings each produce a message. ``tactic`` may be a
        shortname (``stealth``), which is what the artifact stores; a display
        name is accepted too so callers using either representation validate.
        """
        problems: list[str] = []
        record = self.get(technique_id)
        if record is None:
            return [f"{technique_id!r} is not a technique in ATT&CK {self.version}"]
        if record.is_revoked:
            problems.append(f"{technique_id!r} ({record.name}) is revoked in ATT&CK {self.version}")
        if record.is_deprecated:
            problems.append(
                f"{technique_id!r} ({record.name}) is deprecated in ATT&CK {self.version}"
            )
        if tactic:
            wanted = tactic.strip().lower()
            display = {self.tactic_display(t).lower() for t in record.tactics}
            if wanted not in record.tactics and wanted not in display:
                problems.append(
                    f"{technique_id!r} ({record.name}) is not in tactic {tactic!r}; "
                    f"pinned tactics are {list(record.tactics)}"
                )
        return problems

    def require(self, technique_id: str, tactic: str = "") -> TechniqueRecord:
        """Return the record, or raise :class:`AttackMappingError`."""
        problems = self.validate_technique(technique_id, tactic)
        if problems:
            raise AttackMappingError("; ".join(problems))
        record = self.get(technique_id)
        assert record is not None  # validate_technique guarantees it
        return record


def load_dataset(path: Optional[Path] = None) -> AttackDataset:
    """Load the pinned artifact. Raises a clear error when it is missing."""
    resolved = path or DEFAULT_DATASET_PATH
    if not resolved.exists():
        raise FileNotFoundError(
            f"Pinned ATT&CK dataset not found at {resolved}. "
            "Run: python scripts/refresh_attack_dataset.py"
        )
    data = json.loads(resolved.read_text(encoding="utf-8"))
    return AttackDataset(data, path=resolved)


@lru_cache(maxsize=1)
def default_dataset() -> AttackDataset:
    """Process-wide cached dataset, loaded once from the pinned artifact."""
    return load_dataset()


__all__ = [
    "ATTACK_SOURCE_SHA256",
    "ATTACK_SOURCE_URL",
    "ATTACK_VERSION",
    "DATASET_DIR",
    "DEFAULT_DATASET_PATH",
    "AttackDataset",
    "AttackMappingError",
    "TechniqueRecord",
    "default_dataset",
    "load_dataset",
]
