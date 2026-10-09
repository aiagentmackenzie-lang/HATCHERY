"""Collector-agnostic accessors for parsed syscall events.

strace and gVisor's Sentry trace describe the same syscalls with different
grammar. The evasion scorer, the ATT&CK mapper and sample-subtree attribution
all need to read a path, an argument string or an ``execve`` target from either
shape, so the parsing lives in exactly one place — here.
"""

from __future__ import annotations

import re
from typing import Any

# gVisor renders an address-prefixed path as ``0x<addr> /path``; strace renders
# it as a double-quoted string.
ADDRESS_PATH_PATTERN = re.compile(r"0x[0-9a-fA-F]+\s+(/[^\s,\]]*)")
QUOTED_PATH_PATTERN = re.compile(r'"(/[^"]*)"')
INET_MARKERS = ("AF_INET", "AF_INET6")
PORT_PATTERN = re.compile(r"(?:Port:\s*|sin_port=htons\()(\d+)")


def field(event: Any, name: str, default: Any = "") -> Any:
    """Read a field from a dict event or an object event."""
    if isinstance(event, dict):
        return event.get(name, default)
    return getattr(event, name, default)


def raw_args(event: Any) -> str:
    """The syscall's raw argument string, whatever shape the event uses."""
    args = field(event, "args", "")
    if isinstance(args, dict):
        return str(args.get("raw", ""))
    return str(args or "")


def event_paths(event: Any) -> list[str]:
    """Every path-like argument, preferring a collector's pre-extracted list."""
    cached = field(event, "paths", None)
    if cached:
        return [str(p) for p in cached]
    return [p for p in QUOTED_PATH_PATTERN.findall(raw_args(event)) if p and p != "/"]


def exec_target(event: Any) -> str:
    """The executable an ``execve``/``execveat`` event actually ran."""
    args = raw_args(event)
    match = ADDRESS_PATH_PATTERN.search(args)
    if match:
        return match.group(1)
    match = QUOTED_PATH_PATTERN.search(args)
    return match.group(1) if match else ""


def basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1].lower()


def extract_port(args: str) -> int | None:
    match = PORT_PATTERN.search(args)
    return int(match.group(1)) if match else None


def is_inet(args: str) -> bool:
    return any(marker in args for marker in INET_MARKERS)


__all__ = [
    "basename",
    "event_paths",
    "exec_target",
    "extract_port",
    "field",
    "is_inet",
    "raw_args",
]
