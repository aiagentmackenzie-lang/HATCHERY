"""Attribute a container-wide trace to the sample's process subtree.

The gVisor Sentry trace is **container-wide**: the entrypoint, the in-guest
``strace``, ``inotifywait``, ``tcpdump``, ``find`` and the cleanup commands all
appear alongside the sample. Scoring evasion or mapping ATT&CK over the whole
trace therefore measures HATCHERY's own instrumentation as much as the sample.
The earlier mitigation was to exclude a few paths from impact scoring; that is a
symptom fix. This module does the root-cause fix: it finds the process whose
``execve`` target is ``/hatchery/sample/<name>``, follows ``clone``/``fork``/
``clone3``/``vfork`` children, and keeps only that subtree.

Nothing is dropped silently. The returned :class:`TraceAttribution` records the
root PID, the included and excluded event counts, the PIDs involved and a
plain-language reason, and the bundle states the excluded count in its
limitations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from engine.monitor.event_utils import exec_target, field as event_field

logger = logging.getLogger(__name__)

SAMPLE_PREFIX = "/hatchery/sample/"
CLONE_SYSCALLS = frozenset({"clone", "clone3", "fork", "vfork"})
EXEC_SYSCALLS = frozenset({"execve", "execveat"})


@dataclass
class TraceAttribution:
    """What the sample-subtree filter included and excluded, and why."""

    sample_root_pid: Optional[int] = None
    included: int = 0
    excluded: int = 0
    root_target: str = ""
    reason: str = ""
    included_pids: list[int] = field(default_factory=list)

    @property
    def attributed(self) -> bool:
        return self.sample_root_pid is not None

    def to_dict(self) -> dict:
        return {
            "sample_root_pid": self.sample_root_pid,
            "root_target": self.root_target,
            "included": self.included,
            "excluded": self.excluded,
            "attributed": self.attributed,
            "included_pids": sorted(self.included_pids),
            "reason": self.reason,
        }


def _child_pid(return_value: str) -> Optional[int]:
    """The child PID from a clone/fork return value (``2 (0x2)`` or ``2``)."""
    text = str(return_value or "").strip()
    if not text:
        return None
    token = text.split()[0]
    # gVisor prints the decimal first: "2 (0x2)". strace prints "2" or "-1 ...".
    try:
        pid = int(token)
    except ValueError:
        return None
    return pid if pid > 0 else None


def find_sample_root(events: Iterable[Any], sample_name: str = "") -> tuple[Optional[int], str]:
    """Find the PID whose ``execve`` target is the sample.

    Returns ``(pid, target)`` or ``(None, "")``. When ``sample_name`` is given,
    only a target that ends with that name matches; otherwise any
    ``/hatchery/sample/...`` target matches.
    """
    suffix = f"/{sample_name}" if sample_name else ""
    for event in events:
        syscall = str(event_field(event, "syscall", "") or "")
        if syscall not in EXEC_SYSCALLS:
            continue
        target = exec_target(event)
        if not target.startswith(SAMPLE_PREFIX):
            continue
        if suffix and not target.endswith(suffix):
            continue
        pid = event_field(event, "pid", 0)
        if isinstance(pid, int) and pid > 0:
            return pid, target
    return None, ""


def build_subtree(events: Iterable[Any], root_pid: int) -> set[int]:
    """All PIDs in ``root_pid``'s process subtree, from clone/fork return values."""
    events = list(events)
    subtree: set[int] = {root_pid}
    changed = True
    while changed:
        changed = False
        for event in events:
            pid = event_field(event, "pid", 0)
            if pid not in subtree:
                continue
            syscall = str(event_field(event, "syscall", "") or "")
            if syscall not in CLONE_SYSCALLS:
                continue
            child = _child_pid(str(event_field(event, "return_value", "")))
            if child is not None and child not in subtree:
                subtree.add(child)
                changed = True
    return subtree


def attribute_to_sample(
    events: Iterable[Any],
    sample_name: str = "",
) -> tuple[list[Any], TraceAttribution]:
    """Split a trace into the sample subtree and everything else.

    When the root cannot be identified the function keeps **every** event and
    says so in the attribution's ``reason``; it never silently drops the trace.
    """
    events = list(events)
    attribution = TraceAttribution()
    if not events:
        attribution.reason = "no events to attribute"
        return events, attribution

    root_pid, target = find_sample_root(events, sample_name)
    if root_pid is None:
        attribution.included = len(events)
        attribution.reason = (
            "could not find an execve target under /hatchery/sample/ in this trace; "
            "no events were excluded, and the trace is container-wide"
        )
        attribution.included_pids = sorted(
            {event_field(e, "pid", 0) for e in events if event_field(e, "pid", 0)}
        )
        logger.warning("Sample-subtree attribution failed: %s", attribution.reason)
        return events, attribution

    subtree = build_subtree(events, root_pid)
    included = [e for e in events if event_field(e, "pid", 0) in subtree]
    excluded = [e for e in events if event_field(e, "pid", 0) not in subtree]

    attribution.sample_root_pid = root_pid
    attribution.root_target = target
    attribution.included = len(included)
    attribution.excluded = len(excluded)
    attribution.included_pids = sorted(subtree)
    attribution.reason = (
        f"kept the subtree of PID {root_pid} ({target}); included "
        f"{len(included)} of {len(events)} events and excluded {len(excluded)} "
        "entrypoint/monitor events"
    )
    logger.info(
        "Sample-subtree attribution: root=%s target=%s included=%d excluded=%d pids=%s",
        root_pid, target, len(included), len(excluded), sorted(subtree),
    )
    return included, attribution


__all__ = [
    "TraceAttribution",
    "attribute_to_sample",
    "build_subtree",
    "find_sample_root",
]
