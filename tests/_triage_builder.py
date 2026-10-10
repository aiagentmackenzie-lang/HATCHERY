"""Shared fixtures for the triage tests: a small but representative bundle."""

from __future__ import annotations

import json
from typing import Any


def bundle(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "sample": {
            "file_name": "sample.bin",
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "file_type": "ELF",
            "file_size": 4096,
        },
        "isolation": {"tier": 2, "name": "sandboxed-kernel"},
        "limitations": ["Network egress was blocked."],
        "static": {
            "yara": {"matches": [
                {"rule": "linux_persistence_cron", "severity": "high",
                 "namespace": "hatchery", "matched_strings": ["cron"]},
            ]},
            "capa": {"capabilities": [
                {"name": "create process", "namespace": "host-interaction/process"},
            ]},
            "delivery": {"format": "zip", "children": [
                {"name": "payload.exe", "file_type": "pe", "sha256": "c" * 64},
            ]},
        },
        "iocs": [
            {"type": "url", "value": "http://185.220.101.5/gate.php",
             "severity": "high", "source": "strings", "context": "in .data"},
        ],
        "mitre": {"attack_version": "19.2", "techniques": [
            {"technique_id": "T1059.004", "technique_name": "Unix Shell",
             "tactic": "execution", "source": "yara"},
        ]},
        "evasion": {"score": 40, "verdict": "suspicious",
                    "signals": ["proc_cpuinfo"], "recon_then_quiet": False,
                    "inconclusive": False},
        "emulation": {"available": False, "status": "unavailable", "config": {}},
    }
    base.update(overrides)
    return base


def events() -> list[dict[str, Any]]:
    return [
        {"timestamp": "t1", "category": "process", "severity": "high",
         "syscall_name": "execve", "args": json.dumps({"raw": 'execve("/tmp/a.sh")'})},
        {"timestamp": "t2", "category": "file", "severity": "high",
         "syscall_name": "CREATE", "args": json.dumps({"path": "/etc/cron.d/persist"})},
    ]


class FakeClient:
    """A stand-in for :class:`OllamaClient` that replays canned responses."""

    def __init__(
        self,
        responses: str | list[str] = "",
        *,
        model: str = "fake:7b",
        fail: str = "",
        base_url: str = "http://127.0.0.1:11434",
    ) -> None:
        self._responses = responses
        self._fail = fail
        self.model = model
        self.base_url = base_url
        self.calls = 0
        self.last_messages: list[dict[str, str]] = []

    def resolve_model(self) -> str:
        if self._fail == "resolve":
            raise _error("no usable local model is installed")
        return self.model

    def chat(self, messages, schema, *, model=None) -> str:  # type: ignore[no-untyped-def]
        self.last_messages = messages
        if self._fail == "timeout":
            raise _error("Ollama request timed out after 1.0s")
        if self._fail == "transport":
            raise _error("Ollama chat failed (ConnectError)")
        if isinstance(self._responses, list):
            reply = self._responses[min(self.calls, len(self._responses) - 1)]
        else:
            reply = self._responses
        self.calls += 1
        return reply


def _error(message: str) -> Exception:
    from engine.triage.client import OllamaError

    return OllamaError(message)


def verdict_json(**overrides: Any) -> str:
    payload: dict[str, Any] = {
        "verdict": "malicious",
        "confidence": 70,
        "summary": "Cron persistence and an outbound URL.",
        "findings": [
            {"claim": "cron persistence", "grounding": ["event:1"]},
        ],
        "not_established": ["payload purpose"],
    }
    payload.update(overrides)
    return json.dumps(payload)
