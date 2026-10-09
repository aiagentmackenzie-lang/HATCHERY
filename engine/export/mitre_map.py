"""MITRE ATT&CK mapping — data-driven from the pinned v19 dataset.

Every technique this module emits is resolved and validated against
``engine/export/attack/dataset-<version>.json`` (see
:mod:`engine.export.attack_dataset`). It never invents an ID: an unknown,
revoked, deprecated or wrong-tactic technique is recorded as an **error** and
the invalid technique is *not* emitted (fail-closed). ``MITREMapper.validate()``
raises :class:`~engine.export.attack_dataset.AttackMappingError` when any error
was recorded, and the test suite fails on it.

What changed from the hand-maintained lookup (docs/DECISIONS.md D15):

* technique names and tactics now come from the dataset, not a literal;
* ``clone`` no longer maps to Process Injection; ``bind`` no longer claims to be
  Lateral Tool Transfer "Non-Standard Port (Listen)"; ``mmap`` no longer claims
  Process Hollowing; ``/etc/hosts`` no longer claims Modify Registry (a Windows
  technique, and a Linux path); ``connect`` is protocol/port aware instead of
  always T1071; ``fork`` is no longer Native API; and the YARA ``mitre_attck``
  path no longer emits ``tactic="Unknown"``.

What was verified, not assumed, against ATT&CK 19.2: the tactic ``Defense
Evasion`` no longer exists (it is split into ``stealth`` and
``defense-impairment``); ``Rootkit`` (T1014) and ``Modify Registry`` (T1112)
still exist as *active* techniques in 19.2 rather than being deleted; and
``Indicator Blocking`` (T1562.006) *is* revoked. The last of those is why
``/etc/hosts`` has no mapping: there is no correct standalone technique for it,
and guessing one is exactly what D15 forbids.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from engine.export.attack_dataset import (
    ATTACK_VERSION,
    AttackDataset,
    AttackMappingError,
    default_dataset,
)
from engine.monitor.event_utils import (
    basename as _basename,
    event_paths as _event_paths,
    exec_target,
    extract_port as _extract_port,
    field as _field,
    is_inet as _is_inet,
    raw_args as _raw_args,
)

logger = logging.getLogger(__name__)
# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ATTCKTechnique:
    """One ATT&CK technique resolved against the pinned dataset."""

    tactic: str
    technique_id: str
    technique_name: str
    tactic_id: str = ""
    subtechnique_id: str = ""
    subtechnique_name: str = ""
    source: str = ""
    confidence: str = "medium"
    detection_strategy_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "subtechnique_id": self.subtechnique_id,
            "subtechnique_name": self.subtechnique_name,
            "source": self.source,
            "confidence": self.confidence,
            "detection_strategy_ids": self.detection_strategy_ids,
        }


@dataclass
class MITREMappingResult:
    """Complete MITRE ATT&CK mapping result."""

    techniques: list[ATTCKTechnique] = field(default_factory=list)
    tactics_covered: list[str] = field(default_factory=list)
    technique_count: int = 0
    attack_version: str = ATTACK_VERSION
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "attack_version": self.attack_version,
            "techniques": [t.to_dict() for t in self.techniques],
            "tactics_covered": sorted(set(self.tactics_covered)),
            "technique_count": self.technique_count,
            "errors": self.errors,
        }


@dataclass(frozen=True)
class ObservedTechnique:
    """An authored observation -> technique association.

    ``technique_id`` may be a base technique or a subtechnique; the dataset
    decides which. ``tactic`` is the tactic the author intends, as a dataset
    shortname, and is validated against the dataset. An empty ``tactic`` means
    "use the dataset's first tactic" (used for capa/YARA meta, whose own tactic
    strings still carry pre-v19 names such as ``defense-evasion``).
    """

    technique_id: str
    tactic: str = ""
    confidence: str = "medium"


# ---------------------------------------------------------------------------
# Authored mapping tables
#
# These are the *observations*. The technique metadata is never authored here:
# the dataset supplies the name, the tactic set and the deprecation state, and
# validation rejects anything that disagrees.
# ---------------------------------------------------------------------------

# Syscalls whose ATT&CK meaning does not depend on their arguments.
SYSCALL_TECHNIQUE_MAP: dict[str, ObservedTechnique] = {
    # Anti-analysis / debugger detection.
    "ptrace": ObservedTechnique("T1622", "stealth", "medium"),
    # File destruction and permission changes.
    "unlink": ObservedTechnique("T1070.004", "stealth", "medium"),
    "unlinkat": ObservedTechnique("T1070.004", "stealth", "medium"),
    "chmod": ObservedTechnique("T1222", "defense-impairment", "medium"),
    "fchmod": ObservedTechnique("T1222", "defense-impairment", "medium"),
    "fchmodat": ObservedTechnique("T1222", "defense-impairment", "medium"),
    # Fileless/reflective loading via an anonymous in-memory file.
    "memfd_create": ObservedTechnique("T1620", "stealth", "low"),
}

# Shells and interpreters an execve target can be.
SHELL_BASENAMES: frozenset[str] = frozenset(
    {"sh", "bash", "dash", "ash", "zsh", "ksh", "busybox", "rbash"}
)
INTERPRETER_BASENAMES: frozenset[str] = frozenset(
    {"python", "python3", "perl", "ruby", "php", "node", "nodejs", "lua", "awk", "gawk", "sed", "expect"}
)

# Sensitive files whose *read* is credential access.
CREDENTIAL_PATHS: tuple[str, ...] = ("/etc/shadow", "/etc/passwd", "/etc/gshadow", "/etc/security/opasswd")

# Environment-reconnaissance paths and the technique they represent.
# CPU/virtualisation/uptime probes are "System Checks"; tracer inspection is
# "Debugger Evasion"; the /sys and DMI reads are hypervisor checks.
SYSTEM_CHECK_PATHS: tuple[str, ...] = (
    "/proc/cpuinfo", "/proc/self/auxv", "/proc/uptime", "/proc/version",
    "/sys/hypervisor", "/sys/class/dmi", "/sys/devices/virtual/dmi",
    "/proc/xen", "/dev/vboxguest", "/dev/vboxuser",
)
DEBUGGER_PATHS: tuple[str, ...] = ("/proc/self/status", "/proc/self/wchan", "/proc/self/mem")

# Analysis-tool basenames a sample hunts for. Matched on the final component.
ANALYSIS_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "strace", "ltrace", "ftrace", "gdb", "lldb", "gcore", "radare2", "rizin",
        "ida", "ida64", "x64dbg", "ollydbg", "windbg", "procmon", "procexp",
        "wireshark", "tshark", "dumpcap", "tcpdump", "inotifywait", "frida",
        "capa", "floss", "volatility", "vol3", "sysdig", "bpftrace", "perf",
        "auditd", "sysmon", "osquery",
    }
)

# Ports that indicate a well-known application protocol; anything else on a
# successful/attempted INET connect is "non-standard".
WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443, 8000, 8888})
DNS_PORTS: frozenset[int] = frozenset({53, 5353})

# File patterns -> technique, ordered so the most specific matches first.
FILE_PATTERN_MAP: tuple[tuple[str, ObservedTechnique], ...] = (
    (".ssh/authorized_keys", ObservedTechnique("T1098.004", "persistence", "high")),
    (".ssh/authorized_keys2", ObservedTechnique("T1098.004", "persistence", "high")),
    (".bashrc", ObservedTechnique("T1546.004", "persistence", "high")),
    (".bash_profile", ObservedTechnique("T1546.004", "persistence", "high")),
    (".profile", ObservedTechnique("T1546.004", "persistence", "high")),
    ("/etc/cron", ObservedTechnique("T1053.003", "persistence", "high")),
    ("/etc/init.d", ObservedTechnique("T1037.004", "persistence", "high")),
    ("/etc/rc.local", ObservedTechnique("T1037.004", "persistence", "high")),
    ("/etc/rc.d", ObservedTechnique("T1037.004", "persistence", "high")),
    (".ssh", ObservedTechnique("T1098", "persistence", "medium")),
)

# YARA rule tags -> technique.
YARA_TAG_MAP: dict[str, ObservedTechnique] = {
    "anti_debug": ObservedTechnique("T1622", "stealth", "high"),
    "sandbox_evasion": ObservedTechnique("T1497", "stealth", "high"),
    "packing": ObservedTechnique("T1027.002", "stealth", "high"),
    "persistence": ObservedTechnique("T1546.004", "persistence", "medium"),
    "c2": ObservedTechnique("T1071", "command-and-control", "medium"),
}

SLEEP_SYSCALLS: frozenset[str] = frozenset({"nanosleep", "clock_nanosleep"})
SLEEP_LOOP_MIN = 3


def _path_matches_any(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == p or path.startswith(p) for p in prefixes)


# ---------------------------------------------------------------------------
# The mapper
# ---------------------------------------------------------------------------


class MITREMapper:
    """Map HATCHERY observations to validated MITRE ATT&CK techniques.

    Uses capa output, behavioural events (strace or gVisor Sentry trace), file
    watcher results and YARA matches. Every emitted ID is checked against the
    pinned dataset.
    """

    def __init__(self, dataset: Optional[AttackDataset] = None) -> None:
        self.dataset = dataset or default_dataset()
        self.errors: list[str] = []

    # -------------------------------------------------------------- validation

    def validate_technique(self, technique_id: str, tactic: str = "") -> list[str]:
        """Expose dataset validation for callers and tests."""
        return self.dataset.validate_technique(technique_id, tactic)

    def validate(self) -> None:
        """Raise when any mapping emitted an invalid technique."""
        if self.errors:
            raise AttackMappingError("; ".join(self.errors))

    # ---------------------------------------------------------------- mapping

    def map_all(
        self,
        capa_data: Optional[dict] = None,
        strace_data: Any = None,
        file_watch_data: Optional[dict] = None,
        yara_data: Optional[dict] = None,
        behavior_result: Any = None,
    ) -> MITREMappingResult:
        """Map every analysis source to ATT&CK techniques.

        ``behavior_result`` is a :class:`StraceParseResult` or
        :class:`GvisorParseResult` (or a dict with an ``events`` list). It is
        preferred over ``strace_data`` when both are given.
        """
        self.errors = []
        seen: set[str] = set()
        techniques: list[ATTCKTechnique] = []

        behavior = behavior_result if behavior_result is not None else strace_data
        if behavior is not None:
            self._emit_all(
                self._map_behavior(behavior), techniques, seen, _behavior_source(behavior)
            )

        if capa_data:
            self._emit_all(self._map_capa(capa_data), techniques, seen, "capa")

        if file_watch_data:
            self._emit_all(self._map_file_watch(file_watch_data), techniques, seen, "file_watch")

        if yara_data:
            self._emit_all(self._map_yara(yara_data), techniques, seen, "yara")

        result = MITREMappingResult(
            techniques=techniques,
            tactics_covered=[t.tactic_id or t.tactic for t in techniques],
            technique_count=len(techniques),
            attack_version=self.dataset.version,
            errors=list(self.errors),
        )
        if self.errors:
            # Loud, but never fatal to a run: the bundle records them and the
            # invalid technique is simply not emitted.
            for problem in self.errors:
                logger.error("ATT&CK mapping rejected: %s", problem)
        logger.info(
            "MITRE ATT&CK %s mapping: %d techniques across %d tactics (%d rejected)",
            self.dataset.version,
            result.technique_count,
            len(set(result.tactics_covered)),
            len(self.errors),
        )
        return result

    # ------------------------------------------------------------ emit + dedup

    def _emit_all(
        self,
        mappings: list[ObservedTechnique],
        techniques: list[ATTCKTechnique],
        seen: set[str],
        source: str,
    ) -> None:
        for mapping in mappings:
            self._emit(mapping, techniques, seen, source)

    def _emit(
        self,
        mapping: ObservedTechnique,
        techniques: list[ATTCKTechnique],
        seen: set[str],
        source: str,
    ) -> None:
        problems = self.dataset.validate_technique(mapping.technique_id, mapping.tactic)
        if problems:
            self.errors.extend(problems)
            return

        record = self.dataset.get(mapping.technique_id)
        if record is None:  # validate_technique guarantees this, but be explicit
            self.errors.append(f"{mapping.technique_id!r} missing from the pinned dataset")
            return

        tactic_id = mapping.tactic or (record.tactics[0] if record.tactics else "")
        tactic_display = self.dataset.tactic_display(tactic_id) if tactic_id else ""

        if record.is_subtechnique and record.parent:
            parent = self.dataset.get(record.parent)
            technique_id = parent.technique_id if parent else record.parent
            technique_name = parent.name if parent else record.parent
            sub_id = record.technique_id
            sub_name = record.name
        else:
            technique_id = record.technique_id
            technique_name = record.name
            sub_id = ""
            sub_name = ""

        key = f"{technique_id}:{sub_id}"
        if key in seen:
            return
        seen.add(key)

        techniques.append(
            ATTCKTechnique(
                tactic=tactic_display,
                tactic_id=tactic_id,
                technique_id=technique_id,
                technique_name=technique_name,
                subtechnique_id=sub_id,
                subtechnique_name=sub_name,
                source=source,
                confidence=mapping.confidence,
                detection_strategy_ids=list(record.detection_strategy_ids),
            )
        )

    # --------------------------------------------------------------- behaviour

    def _map_behavior(self, behavior: Any) -> list[ObservedTechnique]:
        events = list(getattr(behavior, "events", None) or (behavior.get("events") if isinstance(behavior, dict) else []) or [])
        found: list[ObservedTechnique] = []
        sleep_count = 0

        for event in events:
            syscall = str(_field(event, "syscall", "") or "")
            args = _raw_args(event)
            paths = _event_paths(event)

            static = SYSCALL_TECHNIQUE_MAP.get(syscall)
            if static is not None:
                found.append(static)

            if syscall in ("execve", "execveat"):
                target = exec_target(event)
                base = _basename(target)
                if base in SHELL_BASENAMES:
                    found.append(ObservedTechnique("T1059.004", "execution", "medium"))
                elif base in INTERPRETER_BASENAMES:
                    found.append(ObservedTechnique("T1059", "execution", "medium"))

            if syscall == "mprotect" and "PROT_EXEC" in args:
                found.append(ObservedTechnique("T1055", "stealth", "low"))

            if syscall in ("connect", "sendto", "sendmsg") and _is_inet(args):
                port = _extract_port(args)
                if port in DNS_PORTS:
                    found.append(ObservedTechnique("T1071.004", "command-and-control", "medium"))
                elif port in WEB_PORTS:
                    found.append(ObservedTechnique("T1071.001", "command-and-control", "medium"))
                elif port is not None:
                    found.append(ObservedTechnique("T1571", "command-and-control", "low"))
                else:
                    # INET connect with no parseable port: do not claim T1071.
                    found.append(ObservedTechnique("T1095", "command-and-control", "low"))

            if syscall in ("bind", "listen"):
                port = _extract_port(args)
                if port is not None and port not in WEB_PORTS and port not in DNS_PORTS:
                    found.append(ObservedTechnique("T1571", "command-and-control", "low"))

            if syscall in ("open", "openat", "openat2", "creat"):
                for path in paths:
                    if any(cred in path for cred in CREDENTIAL_PATHS):
                        found.append(ObservedTechnique("T1003.008", "credential-access", "medium"))
                    if _path_matches_any(path, SYSTEM_CHECK_PATHS):
                        found.append(ObservedTechnique("T1497.001", "stealth", "medium"))
                    if any(path == p for p in DEBUGGER_PATHS):
                        found.append(ObservedTechnique("T1622", "stealth", "medium"))
                    if _basename(path) in ANALYSIS_TOOL_NAMES:
                        found.append(ObservedTechnique("T1518.001", "discovery", "low"))

            if syscall in SLEEP_SYSCALLS:
                sleep_count += 1

        if sleep_count >= SLEEP_LOOP_MIN:
            found.append(ObservedTechnique("T1497.003", "stealth", "low"))

        return found

    # ------------------------------------------------------------------- capa

    def _map_capa(self, capa_data: dict) -> list[ObservedTechnique]:
        found: list[ObservedTechnique] = []
        for attack in capa_data.get("attack_techniques", []) or []:
            technique_id = str(attack.get("id", "") or "")
            if not technique_id:
                continue
            # The tactic is deliberately derived from the pinned dataset, not
            # taken from capa: capa 9.x still emits pre-v19 tactic shortnames
            # such as "defense-evasion", which no longer exist.
            found.append(ObservedTechnique(technique_id, "", "high"))
        return found

    # ------------------------------------------------------------ file watcher

    def _map_file_watch(self, file_watch_data: dict) -> list[ObservedTechnique]:
        found: list[ObservedTechnique] = []
        for event in file_watch_data.get("events", []) or []:
            path = _file_watch_path(event)
            if not path:
                continue
            matched = False
            for pattern, mapping in FILE_PATTERN_MAP:
                if pattern in path:
                    found.append(mapping)
                    matched = True
                    break
            if not matched:
                for cred in CREDENTIAL_PATHS:
                    if cred in path:
                        found.append(ObservedTechnique("T1003.008", "credential-access", "high"))
                        break
        return found

    # ------------------------------------------------------------------- yara

    def _map_yara(self, yara_data: dict) -> list[ObservedTechnique]:
        found: list[ObservedTechnique] = []
        for match in yara_data.get("matches", []) or []:
            for tag in match.get("tags", []) or []:
                mapping = YARA_TAG_MAP.get(str(tag))
                if mapping is not None:
                    found.append(mapping)

            meta = match.get("meta", {}) or {}
            reference = str(meta.get("mitre_attck", "") or "")
            if reference:
                technique_id = reference.split(":", 1)[0].strip()
                if technique_id:
                    # This previously emitted tactic="Unknown" with a truncated
                    # ID. The dataset now supplies both name and tactic.
                    found.append(ObservedTechnique(technique_id, "", "high"))
        return found


def _behavior_source(behavior: Any) -> str:
    """Name the collector that produced a behaviour result."""
    explicit = getattr(behavior, "source", None)
    if explicit:
        return str(explicit)
    if isinstance(behavior, dict):
        return str(behavior.get("source", "strace"))
    return "strace"


def _file_watch_path(event: Any) -> str:
    """Path from either a raw file-watch event or a normalized event row."""
    if isinstance(event, dict):
        if event.get("path"):
            return str(event["path"])
        args = event.get("args")
        if isinstance(args, dict) and args.get("path"):
            return str(args["path"])
        if isinstance(args, str):
            try:
                parsed = json.loads(args)
                if isinstance(parsed, dict) and parsed.get("path"):
                    return str(parsed["path"])
            except json.JSONDecodeError:
                return ""
    return str(getattr(event, "path", "") or "")


__all__ = [
    "ATTCKTechnique",
    "MITREMapper",
    "MITREMappingResult",
    "ObservedTechnique",
    "exec_target",
]
