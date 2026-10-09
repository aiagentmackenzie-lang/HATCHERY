"""Evasion detection — a first-class signal, not a footnote.

A sample that reconnoiters an environment and then exits quietly is the
hardest case for a sandbox: the run is *event-thin*, so a naive "no malicious
syscalls observed" reading scores it clean. This module turns the recon itself
into the finding. It scores **density and ordering**, not single events: a
benign installer reads a couple of system properties and carries on; an evasive
loader reads a dozen properties across several categories and then does
nothing.

Signals it can see under ``strace`` (tier 1):

  * reads of hypervisor / DMI / VM-tool artifact paths;
  * reads of ``/proc/cpuinfo`` and ``/proc/self/auxv`` (the syscall surrogates
    for a CPUID hypervisor-vendor query);
  * reads of ``/proc/uptime`` (short-uptime check, often paired with an
    accelerated-sleep check);
  * reads of ``/proc/self/status`` (``TracerPid``) and ``ptrace`` (anti-debug);
  * enumeration of analysis-tool paths (``strace``, ``gdb``, ``ltrace``,
    ``tcpdump``, ``inotifywait``, ...);
  * repeated ``nanosleep``/``clock_nanosleep``, especially sub-second, i.e. a
    timing-check loop;
  * the *ordering*: recon first, then a quiet, normal exit with no impact.

What it **cannot** see, and must never pretend to (see ``docs/DECISIONS.md``):

  * ``RDTSC``/``RDTSCP`` — CPU instructions, never syscalls;
  * ``CPUID`` hypervisor-bit / vendor-leaf queries — CPU instructions;
  * ``clock_gettime``/``gettimeofday`` served by the vDSO — a pure userspace
    call. This is empirically verified in this repository: the captured probe
    ``tests/fixtures/strace-evasive-real.log`` ran ``date +%s`` in a loop and
    the strace log contains *no* clock syscall at all, because glibc resolved
    it in the vDSO. A sample's accelerated-sleep check is therefore usually
    invisible to ptrace-based tracing. It will be visible to eBPF, which hooks
    the syscall entry regardless of the vDSO fast path.

That asymmetry is an argument for the per-tier monitoring strategy, not
something to paper over with a guess.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class EvasionSeverity(str, Enum):
    """Severity of an evasion signal, derived from its weight."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvasionSignal(str, Enum):
    """A class of environment-reconnaissance behavior."""

    VM_ARTIFACT_PROBE = "vm-artifact-probe"
    VM_TOOL_PROBE = "vm-tool-probe"
    CPU_PROBE = "cpu-probe"
    UPTIME_PROBE = "uptime-probe"
    DEBUGGER_PROBE = "debugger-probe"
    SELF_MAPS_PROBE = "self-maps-probe"
    ANALYSIS_TOOL_HUNT = "analysis-tool-hunt"
    SLEEP_LOOP = "sleep-loop"
    RECON_THEN_QUIET = "recon-then-quiet-exit"


# Weight of each signal. These are deliberately coarse: the point is to
# separate "read one property" from "reconnoiter across half a dozen
# categories and then go quiet", not to pretend to a calibrated probability.
SIGNAL_WEIGHTS: dict[EvasionSignal, int] = {
    EvasionSignal.VM_TOOL_PROBE: 20,
    EvasionSignal.DEBUGGER_PROBE: 18,
    EvasionSignal.VM_ARTIFACT_PROBE: 15,
    EvasionSignal.ANALYSIS_TOOL_HUNT: 15,
    EvasionSignal.SELF_MAPS_PROBE: 5,
    EvasionSignal.CPU_PROBE: 8,
    EvasionSignal.SLEEP_LOOP: 8,
    EvasionSignal.UPTIME_PROBE: 6,
    EvasionSignal.RECON_THEN_QUIET: 20,
}

SIGNAL_DESCRIPTIONS: dict[EvasionSignal, str] = {
    EvasionSignal.VM_ARTIFACT_PROBE: (
        "Read hypervisor/DMI identifiers — a classic virtual-machine check"
    ),
    EvasionSignal.VM_TOOL_PROBE: (
        "Read VM-guest-tool paths (/usr/bin/vmtoolsd, VBoxService, qemu-ga, ...)"
    ),
    EvasionSignal.CPU_PROBE: (
        "Read /proc/cpuinfo or /proc/self/auxv — the syscall surrogate for a "
        "CPUID feature/vendor query"
    ),
    EvasionSignal.UPTIME_PROBE: "Read /proc/uptime — a short-system-uptime check",
    EvasionSignal.DEBUGGER_PROBE: (
        "Read /proc/self/status (TracerPid) or call ptrace — anti-debugging"
    ),
    EvasionSignal.SELF_MAPS_PROBE: "Read /proc/self/maps — mapped-image inspection",
    EvasionSignal.ANALYSIS_TOOL_HUNT: (
        "Enumerated analysis-tool paths (strace, gdb, ltrace, tcpdump, "
        "inotifywait, or similar)"
    ),
    EvasionSignal.SLEEP_LOOP: (
        "Repeated nanosleep/clock_nanosleep — timing checks or accelerated-sleep"
    ),
    EvasionSignal.RECON_THEN_QUIET: (
        "Reconnoitered the environment, then exited without observable impact"
    ),
}

# Paths whose mere *existence* is a VM fingerprint.
HYPERVISOR_PATH_MARKERS: tuple[str, ...] = (
    "/sys/hypervisor",
    "/sys/class/dmi/id",
    "/sys/devices/virtual/dmi/id",
    "/proc/xen",
    "/sys/module/xen",
    "/dev/vboxguest",
    "/dev/vboxuser",
    "/dev/vmci",
    "/sys/module/vbox",
    "/sys/module/vmware",
)
VM_TOOL_PATH_MARKERS: tuple[str, ...] = (
    "vmtoolsd",
    "vboxservice",
    "vboxsf",
    "qemu-ga",
    "spice-vdagent",
    "/etc/vmware-tools",
    "/usr/lib/vmware",
)
CPU_PROBE_PATHS: tuple[str, ...] = (
    "/proc/cpuinfo",
    "/proc/self/auxv",
)
DEBUGGER_PATHS: tuple[str, ...] = (
    "/proc/self/status",
    "/proc/self/wchan",
    "/proc/self/mem",
)
SELF_MAPS_PATHS: tuple[str, ...] = ("/proc/self/maps",)
# Basenames of tools an evasive sample hunts for. Matched on the final path
# component so /usr/bin/strace and /usr/local/sbin/strace both count.
ANALYSIS_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "strace", "ltrace", "ftrace", "gdb", "lldb", "gcore", "radare2", "rizin",
        "ida", "ida64", "x64dbg", "ollydbg", "windbg", "procmon", "procexp",
        "processhacker", "wireshark", "tshark", "dumpcap", "tcpdump",
        "inotifywait", "frida", "apktool", "jadx", "capa", "floss", "volatility",
        "vol3", "sysdig", "bpftrace", "perf", "auditd", "sysmon", "osquery",
    }
)

SLEEP_SYSCALLS: frozenset[str] = frozenset({"nanosleep", "clock_nanosleep"})
# File-mutating syscalls used to decide whether a run had any impact at all.
WRITE_FLAGS: tuple[str, ...] = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
FS_MUTATORS: frozenset[str] = frozenset(
    {"unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat",
     "chmod", "fchmod", "fchmodat", "truncate", "ftruncate", "creat"}
)
# Writes here are instrumentation noise (the shell redirecting to /dev/null,
# the sample writing its own log, /proc and /sys pseudo-files), not impact.
IMPACT_EXCLUDED_PREFIXES: tuple[str, ...] = (
    "/dev/null", "/dev/tty", "/dev/stdout", "/dev/stderr", "/dev/pts/",
    "/proc/", "/sys/", "/hatchery/",
)

SLEEP_LOOP_MIN = 3
QUIET_IMPACT_MAX = 0  # no observable impact at all

# Score thresholds.
EVASION_HIGH = 60
EVASION_SUSPICIOUS = 30


def _quoted_paths(args: str) -> list[str]:
    """Return every double-quoted string in a syscall's arguments.

    strace renders paths as ``openat(AT_FDCWD, "/proc/cpuinfo", O_RDONLY)``;
    the first quoted string is the path for the syscalls we care about. We
    return all of them and let the caller match markers, because some syscalls
    put the path in the second slot and some in the first.
    """
    paths: list[str] = []
    # Simple state machine: avoids a regex that would also match \" escapes.
    i = 0
    while i < len(args):
        if args[i] == '"':
            j = i + 1
            buf: list[str] = []
            while j < len(args):
                ch = args[j]
                if ch == "\\" and j + 1 < len(args):
                    buf.append(args[j + 1])
                    j += 2
                    continue
                if ch == '"':
                    break
                buf.append(ch)
                j += 1
            paths.append("".join(buf))
            i = j + 1
        else:
            i += 1
    return paths


def _path_matches(path: str, markers: tuple[str, ...]) -> bool:
    lower = path.lower()
    return any(marker in lower for marker in markers)


def _basename_matches(path: str, names: frozenset[str]) -> bool:
    base = path.rstrip("/").rsplit("/", 1)[-1].lower()
    return base in names


def _timestamp_seconds(ts: str) -> Optional[float]:
    """Parse an strace ``HH:MM:SS.ffffff`` timestamp into seconds."""
    if not ts:
        return None
    try:
        hh, mm, ss = ts.split(":")
        return int(hh) * 3600 + int(mm) * 60 + float(ss)
    except (ValueError, AttributeError):
        return None


@dataclass
class EvasionFinding:
    """One signal class observed in a run."""

    signal: EvasionSignal
    severity: EvasionSeverity
    count: int
    evidence: list[str] = field(default_factory=list)
    first_timestamp: str = ""
    last_timestamp: str = ""

    @property
    def weight(self) -> int:
        return SIGNAL_WEIGHTS.get(self.signal, 0)

    def to_dict(self) -> dict:
        return {
            "signal": self.signal.value,
            "severity": self.severity.value,
            "weight": self.weight,
            "count": self.count,
            "description": SIGNAL_DESCRIPTIONS.get(self.signal, ""),
            "evidence": self.evidence,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
        }


@dataclass
class EvasionReport:
    """The evasion assessment for one run."""

    score: int = 0
    verdict: str = "none"  # none | low | suspicious | evasive
    findings: list[EvasionFinding] = field(default_factory=list)
    impact_score: int = 0
    recon_then_quiet: bool = False
    probe_events: int = 0
    event_count: int = 0
    inconclusive: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def signals(self) -> list[str]:
        return [f.signal.value for f in self.findings]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "impact_score": self.impact_score,
            "recon_then_quiet": self.recon_then_quiet,
            "inconclusive": self.inconclusive,
            "probe_events": self.probe_events,
            "event_count": self.event_count,
            "signals": self.signals,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }

    def normalized_events(self) -> list[dict]:
        """Render the findings as normalised ``events.jsonl`` rows.

        Category ``evasion`` is a first-class category alongside file/network/
        process: it lands in the same stream so the dashboard timeline and the
        API see it without a second data path.
        """
        rows: list[dict] = []
        for finding in self.findings:
            rows.append(
                {
                    "timestamp": finding.first_timestamp,
                    "pid": 0,
                    "syscall_name": f"evasion:{finding.signal.value}",
                    "category": "evasion",
                    "severity": finding.severity.value,
                    "args": _json_dumps(
                        {
                            "signal": finding.signal.value,
                            "count": finding.count,
                            "description": SIGNAL_DESCRIPTIONS.get(finding.signal, ""),
                        }
                    ),
                    "return_value": "",
                    "raw_line": (
                        f"evasion signal {finding.signal.value} "
                        f"x{finding.count}: {SIGNAL_DESCRIPTIONS.get(finding.signal, '')}"
                    ),
                    "source": "evasion-analysis",
                    "indicators": finding.evidence[:20],
                }
            )
        return rows


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, default=str)


def _severity_for(weight: int) -> EvasionSeverity:
    if weight >= 18:
        return EvasionSeverity.HIGH
    if weight >= 12:
        return EvasionSeverity.MEDIUM
    if weight >= 6:
        return EvasionSeverity.LOW
    return EvasionSeverity.INFO


def _collect_findings(events: list[Any]) -> dict[EvasionSignal, EvasionFinding]:
    """Scan ordered events and bucket the reconnaissance signals."""
    findings: dict[EvasionSignal, EvasionFinding] = {}
    sleep_count = 0
    sleep_first: list[str] = []

    def add(signal: EvasionSignal, evidence: str, ts: str) -> None:
        finding = findings.get(signal)
        if finding is None:
            finding = EvasionFinding(
                signal=signal,
                severity=_severity_for(SIGNAL_WEIGHTS.get(signal, 0)),
                count=0,
                evidence=[],
                first_timestamp=ts,
            )
            findings[signal] = finding
        finding.count += 1
        if len(finding.evidence) < 40 and evidence not in finding.evidence:
            finding.evidence.append(evidence)
        if ts:
            if not finding.first_timestamp:
                finding.first_timestamp = ts
            finding.last_timestamp = ts

    for event in events:
        syscall = getattr(event, "syscall", "") or ""
        args = getattr(event, "args", "") or ""
        ts = getattr(event, "timestamp", "") or ""
        paths = _quoted_paths(args)

        if syscall in ("ptrace",):
            add(EvasionSignal.DEBUGGER_PROBE, f"ptrace({args})", ts)

        if syscall in SLEEP_SYSCALLS:
            sleep_count += 1
            if len(sleep_first) < 5:
                sleep_first.append(f"{syscall}({args})")

        for path in paths:
            if _path_matches(path, HYPERVISOR_PATH_MARKERS):
                add(EvasionSignal.VM_ARTIFACT_PROBE, f"{syscall}({path})", ts)
            if _path_matches(path, VM_TOOL_PATH_MARKERS):
                add(EvasionSignal.VM_TOOL_PROBE, f"{syscall}({path})", ts)
            if any(path == p or path.startswith(p) for p in CPU_PROBE_PATHS):
                add(EvasionSignal.CPU_PROBE, f"{syscall}({path})", ts)
            if path == "/proc/uptime":
                add(EvasionSignal.UPTIME_PROBE, f"{syscall}({path})", ts)
            if any(path == p for p in DEBUGGER_PATHS):
                add(EvasionSignal.DEBUGGER_PROBE, f"{syscall}({path})", ts)
            if any(path == p for p in SELF_MAPS_PATHS):
                add(EvasionSignal.SELF_MAPS_PROBE, f"{syscall}({path})", ts)
            if _basename_matches(path, ANALYSIS_TOOL_NAMES):
                add(EvasionSignal.ANALYSIS_TOOL_HUNT, f"{syscall}({path})", ts)

    if sleep_count >= SLEEP_LOOP_MIN:
        findings[EvasionSignal.SLEEP_LOOP] = EvasionFinding(
            signal=EvasionSignal.SLEEP_LOOP,
            severity=_severity_for(SIGNAL_WEIGHTS[EvasionSignal.SLEEP_LOOP]),
            count=sleep_count,
            evidence=list(sleep_first),
        )

    return findings


def _count_impact(events: list[Any]) -> int:
    """Count events that change system state or reach the network.

    Reads, stats and exits do not count. Writes to ``/dev/null``, ``/proc``,
    ``/sys`` and the sandbox's own directory do not count either — they are
    instrumentation, not impact. This is what separates "reconnoitered and did
    nothing" from "reconnoitered and then dropped a payload".
    """
    impact = 0
    for event in events:
        syscall = getattr(event, "syscall", "") or ""
        args = getattr(event, "args", "") or ""

        if syscall in ("connect", "sendto", "sendmsg"):
            # A connect() to a blocked egress still counts: the sample tried.
            # AF_UNIX connects are local IPC (glibc's nscd socket churn) and are
            # not egress, so they must not be read as network impact.
            if "AF_INET" in args:
                impact += 1
            continue

        if syscall in FS_MUTATORS:
            paths = _quoted_paths(args)
            target = paths[0] if paths else ""
            if target and not _path_matches(target, IMPACT_EXCLUDED_PREFIXES):
                impact += 1
            continue

        if syscall in ("open", "openat", "openat2", "creat"):
            if any(flag in args for flag in WRITE_FLAGS):
                paths = _quoted_paths(args)
                target = paths[0] if paths else ""
                if target and not _path_matches(target, IMPACT_EXCLUDED_PREFIXES):
                    impact += 1
    return impact


def _recon_then_quiet(events: list[Any], findings: dict[EvasionSignal, EvasionFinding]) -> bool:
    """Detect the sequence *recon -> branch -> quiet exit*.

    Requires breadth (>= 3 recon categories), a quiet tail (no impact after the
    last recon event), and at least one recon event. The point is that the
    sample spent its time looking around and then stopped.
    """
    recon_signals = [
        s for s in findings
        if s is not EvasionSignal.RECON_THEN_QUIET
    ]
    if len(recon_signals) < 3:
        return False

    last_recon_ts = ""
    for finding in findings.values():
        if finding.last_timestamp and finding.last_timestamp > last_recon_ts:
            last_recon_ts = finding.last_timestamp
    if not last_recon_ts:
        return False

    tail = [e for e in events if (getattr(e, "timestamp", "") or "") > last_recon_ts]
    if not tail:
        return True
    return _count_impact(tail) <= QUIET_IMPACT_MAX


def analyze_evasion(parse_result: Any) -> EvasionReport:
    """Assess a parsed strace run for evasion signals.

    Args:
        parse_result: A :class:`~engine.monitor.strace_parser.StraceParseResult`
            (or anything with an ``events`` list of objects exposing
            ``syscall``, ``args`` and ``timestamp``).

    Returns:
        An :class:`EvasionReport`. Never raises on malformed input; a run with
        no parse result simply scores zero.
    """
    events = list(getattr(parse_result, "events", []) or [])
    report = EvasionReport(event_count=len(events))
    if not events:
        report.notes.append("No events to assess.")
        return report

    findings = _collect_findings(events)
    impact = _count_impact(events)
    report.impact_score = impact

    # Base score: distinct categories (breadth), with a small depth term.
    base = sum(f.weight for f in findings.values())
    breadth_bonus = 5 * max(0, len(findings) - 2)
    depth_bonus = min(18, int(8 * _log10(1 + sum(f.count for f in findings.values()))))
    score = base + breadth_bonus + depth_bonus

    recon_then_quiet = _recon_then_quiet(events, findings)
    if recon_then_quiet:
        findings[EvasionSignal.RECON_THEN_QUIET] = EvasionFinding(
            signal=EvasionSignal.RECON_THEN_QUIET,
            severity=_severity_for(SIGNAL_WEIGHTS[EvasionSignal.RECON_THEN_QUIET]),
            count=1,
            evidence=[
                f"{len([s for s in findings if s is not EvasionSignal.RECON_THEN_QUIET])} "
                f"recon categories observed; no impact afterward"
            ],
        )
        score += SIGNAL_WEIGHTS[EvasionSignal.RECON_THEN_QUIET]

    report.score = min(100, score)
    report.probe_events = sum(f.count for f in findings.values())
    report.recon_then_quiet = recon_then_quiet

    if report.score >= EVASION_HIGH:
        report.verdict = "evasive"
    elif report.score >= EVASION_SUSPICIOUS:
        report.verdict = "suspicious"
    elif report.score > 0:
        report.verdict = "low"
    else:
        report.verdict = "none"

    # An evasive run that produced no observable impact is inconclusive, not
    # clean. This is the whole point of the module.
    if report.verdict == "evasive" and impact <= QUIET_IMPACT_MAX:
        report.inconclusive = True
        report.notes.append(
            "The sample reconnoitered across multiple categories and then "
            "exited without observable impact. This is consistent with evasion: "
            "treat the run as INCONCLUSIVE, not clean."
        )
    report.notes.append(
        "RDTSC/CPUID and vDSO clock reads are CPU/userspace operations and are "
        "not visible to ptrace-based tracing at this tier."
    )

    report.findings = sorted(
        findings.values(), key=lambda f: (-f.weight, f.signal.value)
    )
    logger.info(
        "Evasion assessment: score=%d verdict=%s impact=%d signals=%s",
        report.score, report.verdict, impact, report.signals,
    )
    return report


def _log10(x: float) -> float:
    import math

    return math.log10(x) if x > 0 else 0.0
