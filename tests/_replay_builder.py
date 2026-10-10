"""Shared helpers for the replay tests.

Builds a synthetic bundle that exercises every signal the replay compares, and a
fake submit runner that writes the replayed bundle where ``submit -o`` would.
No Docker, no Ollama and no real subprocess are needed for these tests.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any


def content_sha256(data: bytes = b"hatchery-replay-fixture\n") -> str:
    return hashlib.sha256(data).hexdigest()


def bundle_with(**overrides: Any) -> dict[str, Any]:
    """A static-only bundle that establishes every deterministic signal."""
    sha = overrides.pop("sha256", None) or content_sha256()
    base: dict[str, Any] = {
        "schema_version": "1.0",
        "task_id": "original-task",
        "sample": {
            "file_name": "sample.bin",
            "file_path": "sample.bin",
            "file_size": 24,
            "file_type": "Unknown",
            "md5": "0" * 32,
            "sha1": "0" * 40,
            "sha256": sha,
        },
        "isolation": {"tier": 0},
        "static": {
            "strings": {},
            "yara": {
                "matches": [
                    {"rule": "HATCHERY_EICAR_TestFile"},
                    {"rule": "suspicious_base64"},
                ]
            },
            "capa": {"capabilities": [{"name": "create process"}, {"name": "write file"}]},
            "packer": {"packers": []},
            "delivery": {"format": "unknown", "children": []},
        },
        "sandbox": None,
        "iocs": [
            {"type": "yara_match", "value": "HATCHERY_EICAR_TestFile", "source": "yara"},
            {"type": "domain", "value": "evil.example", "source": "static"},
        ],
        "mitre": {
            "attack_version": "19.2",
            "techniques": [{"technique_id": "T1059.001"}],
            "technique_count": 1,
        },
        "evasion": None,
        "emulation": None,
        "triage": None,
        "summary": {
            "events_total": 0,
            "events_by_category": {},
            "events_by_severity": {},
            "yara_matches": 2,
            "capa_capabilities": 2,
            "iocs_total": 2,
        },
        "limitations": [],
        "errors": [],
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merged = copy.deepcopy(base[key])
            merged.update(value)
            base[key] = merged
        else:
            base[key] = value
    return base


def dynamic_bundle_with(**overrides: Any) -> dict[str, Any]:
    """A bundle whose original detonated at tier 1 under strace."""
    base = bundle_with(
        isolation={"tier": 1},
        sandbox={
            "status": "completed",
            "duration_seconds": 12.5,
            "monitoring": {"collector": "strace-ptrace"},
        },
        summary={
            "events_total": 100,
            "events_by_category": {"process": 10, "file": 60, "network": 30},
            "events_by_severity": {"info": 80, "high": 20},
        },
        evasion={"score": 0, "verdict": "none"},
    )
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merged = copy.deepcopy(base[key])
            merged.update(value)
            base[key] = merged
        else:
            base[key] = value
    return base


def make_sample(tmp_path: Path, data: bytes = b"hatchery-replay-fixture\n") -> tuple[Path, str]:
    """Write a real sample file and return ``(path, sha256)``."""
    path = tmp_path / "fixtures" / "sample.bin"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def write_run(root: Path, bundle: dict[str, Any], name: str = "run") -> Path:
    """Write ``root/name/bundle/analysis.json`` and return the bundle dir."""
    bundle_dir = root / name / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "analysis.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return bundle_dir


def fake_submit_runner(replay_bundle: dict[str, Any], *, returncode: int = 0):
    """A submit runner that writes ``replay_bundle`` where ``-o`` points."""

    def run(command: list[str], timeout: float) -> tuple[int, str, str]:
        out = Path(command[command.index("-o") + 1])
        bundle_dir = out / "bundle"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / "analysis.json").write_text(
            json.dumps(replay_bundle, indent=2), encoding="utf-8"
        )
        return returncode, "", ""

    return run


def output_arg(command: list[str]) -> Path:
    return Path(command[command.index("-o") + 1])
