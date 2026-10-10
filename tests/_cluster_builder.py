"""Shared helpers for the cluster tests."""

from __future__ import annotations

from typing import Any, Iterable

from engine.cluster.fingerprint import Fingerprint


def fingerprint(task_id: str, **features: Iterable[str]) -> Fingerprint:
    """Build a fingerprint directly from category sets."""
    return Fingerprint(
        task_id=task_id,
        sha256=features.pop("sha256", ""),  # type: ignore[arg-type]
        file_name=features.pop("file_name", ""),  # type: ignore[arg-type]
        file_type=features.pop("file_type", ""),  # type: ignore[arg-type]
        delivery_format=features.pop("delivery_format", ""),  # type: ignore[arg-type]
        features={key: frozenset(value) for key, value in features.items()},
    )


def twin(task_id: str, **features: Iterable[str]) -> Fingerprint:
    return fingerprint(task_id, **features)


def bundle_with(**overrides: Any) -> dict[str, Any]:
    """A bundle exercising every fingerprint category."""
    base: dict[str, Any] = {
        "task_id": "t1",
        "sample": {
            "file_name": "dropper.exe",
            "sha256": "a" * 64,
            "file_type": "PE32",
        },
        "static": {
            "capa": {"capabilities": [
                {"name": "create process"},
                {"name": "write file"},
            ]},
            "yara": {"matches": [
                {"rule": "suspicious_powershell"},
                {"rule": "packed_upx"},
            ]},
            "pe": {
                "compile_timestamp": "2026-03-04 05:06:07",
                "imports": [
                    {"dll": "KERNEL32.dll", "function": "CreateProcessA"},
                    {"dll": "WS2_32.dll", "function": "connect"},
                ],
                "exports": ["DllRegisterServer"],
                "sections": [{"name": ".text"}, {"name": ".rsrc"}],
                "suspicious_indicators": ["high entropy section"],
            },
            "strings": {
                "urls": ["http://evil.example/gate.php"],
                "ips": ["185.220.101.5"],
                "domains": ["evil.example"],
                "file_paths": ["C:\\Windows\\Temp\\a.exe"],
                "registry_keys": ["HKCU\\Software\\Run"],
                "emails": ["ops@evil.example"],
            },
            "delivery": {"format": "zip"},
        },
        "mitre": {"techniques": [{"technique_id": "T1059.001"}]},
        "iocs": [{"value": "evil.example"}],
        "emulation": {"available": True, "config": {"api_calls": {"CreateFileW": 3}}},
    }
    base.update(overrides)
    return base
