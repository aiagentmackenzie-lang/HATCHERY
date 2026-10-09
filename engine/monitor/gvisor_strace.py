"""gVisor Sentry trace parser — read syscalls from inside the sandbox kernel.

Why this exists
---------------
`strace` cannot see `RDTSC`, `CPUID` or a vDSO-served `clock_gettime` (see
`docs/DECISIONS.md` D2/D11). gVisor provides its own syscall trace, emitted by
the Sentry — the user-space kernel inside `runsc` — and its `strace`,
`strace-syscalls` and `strace-log-size` flags are in gVisor's
OCI-annotation override allow-list. That lets a single analysis container turn
the trace on without a global runtime flag and without
`--allow-flag-override` (D14).

Format
------
This is *not* strace's format. It is gVisor's, captured from a real run
(`tests/fixtures/gvisor-strace-real.log`, release-20261005.0)::

    I1009 15:34:32.684395       1 strace.go:572] [   1:   1] bash E openat(AT_FDCWD /, 0xaaeed566a680 /proc/cpuinfo, O_RDONLY|0x0, 0o0)
    I1009 15:34:32.685477       1 strace.go:601] [   1:   1] bash X exit_group(0x0) = 0 (0x0) (291ns)

The fields are:

  * ``I``/``D``/``W``  log level, then ``MMDD`` and ``HH:MM:SS.ffffff``;
  * the runsc host PID (always ``1`` inside the sandbox);
  * ``strace.go:<line>]`` — the emitting source, the marker that separates a
    trace line from boot noise in the same debug log;
  * ``[tgid:tid]`` the sandbox thread, then the process ``comm``;
  * ``E`` (syscall entry) or ``X`` (exit). ``X`` lines carry the return value
    and the duration; ``E`` lines carry the arguments. They are paired here
    into a single event per syscall.

Argument rendering differs from strace: string arguments are shown as
``<hex-address> <value>`` rather than ``"value"``. ``_extract_paths`` handles
both shapes, so the evasion scorer (which is path-based) sees the same paths it
would under ptrace.

Where the trace lands
---------------------
`--debug-to-user-log` does **not** put the trace on the container's stdout, so
`container.logs()` (the route D14 originally intended) is empty. The trace goes
to the runsc debug log, one ``.boot.txt`` per sandbox. `GvisorLogReader` locates
the file belonging to a given container ID and reads it — directly on a Linux
host, or through ``colima ssh`` inside the colima VM on macOS. This is the
fallback D14 authorises, and it keeps the per-container annotation scoping (no
global ``--strace``).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from engine.monitor.evasion import _quoted_paths
from engine.monitor.strace_parser import (
    StraceEvent,
    StraceParseResult,
    StraceParser,
)

logger = logging.getLogger(__name__)

# One gVisor trace line. The `strace.go:<n>]` marker is what distinguishes a
# trace line from the boot/timing noise that shares the same debug log.
GVISOR_LINE_PATTERN = re.compile(
    r"^[A-Z](\d{4})\s+"                       # level + MMDD
    r"(\d{2}:\d{2}:\d{2}\.\d+)\s+"             # HH:MM:SS.ffffff
    r"(\d+)\s+"                                # runsc host pid
    r"strace\.go:\d+\]\s+"                     # source marker
    r"\[\s*(\d+):\s*(\d+)\]\s+"                # [tgid:tid]
    r"(\S+)\s+"                                # comm
    r"([EX])\s+"                               # phase
    r"(.*)$"                                   # syscall(...) [= ret (dur)]
)

# `name(args)` with a trailing `)`; args are greedy so `)` inside them survives.
GVISOR_ENTRY_PATTERN = re.compile(r"^([A-Za-z0-9_]+)\((.*)\)$")

# `name(args) = ret (duration)`; greedy args, anchored on the final duration.
GVISOR_EXIT_PATTERN = re.compile(
    r"^([A-Za-z0-9_]+)\((.*)\)\s*=\s*(.*?)\s*\(([^()]*)\)$"
)

# gVisor renders a string argument as `<address> <value>`. Only
# address-prefixed paths are real arguments: `AT_FDCWD <cwd>` is the directory
# file descriptor's cwd, not the syscall's target, and treating it as one made
# HATCHERY's own /hatchery directory look like sample impact.
GVISOR_PATH_PATTERN = re.compile(r"0x[0-9a-fA-F]+\s+(/[^\s,\]]*)")


def _extract_paths(args: str) -> list[str]:
    """Every path-like argument, from gVisor's rendering and from quotes."""
    found: list[str] = list(_quoted_paths(args))
    for match in GVISOR_PATH_PATTERN.finditer(args):
        found.append(match.group(1))

    out: list[str] = []
    for path in found:
        if not path or path == "/":
            continue
        if path not in out:
            out.append(path)
    return out


@dataclass
class GvisorStraceEvent(StraceEvent):
    """A parsed gVisor syscall event, with the paths pre-extracted.

    ``paths`` exists because gVisor renders paths unquoted, so the generic
    strace path extractor would miss them. Carrying them here keeps the
    evasion scorer path-based and identical across collectors.
    """

    tid: int = 0
    comm: str = ""
    phase: str = "E"
    paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({"tid": self.tid, "comm": self.comm, "paths": self.paths})
        return data


@dataclass
class GvisorParseResult:
    """Result of parsing a gVisor Sentry trace."""

    source: str = "gvisor-sentry"
    total_lines: int = 0
    parsed_events: int = 0
    events: list[GvisorStraceEvent] = field(default_factory=list)
    process_tree: dict[int, list[int]] = field(default_factory=dict)
    network_connections: list[dict] = field(default_factory=list)
    file_operations: list[dict] = field(default_factory=list)
    process_operations: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    parse_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "events": [e.to_dict() for e in self.events],
            "process_tree": {str(k): v for k, v in self.process_tree.items()},
            "network_connections": self.network_connections,
            "file_operations": self.file_operations,
            "process_operations": self.process_operations,
            "errors": self.errors,
            "parse_time_ms": self.parse_time_ms,
        }


class GvisorStraceParser:
    """Parse gVisor Sentry trace lines into typed behavioral events.

    Reuses the strace parser's classification, severity and indicator rules so
    there is exactly one source of truth for what a syscall *means*; only the
    line grammar differs.
    """

    def __init__(self) -> None:
        self._classifier = StraceParser()

    def parse_file(self, log_path: Path) -> GvisorParseResult:
        import time

        if not log_path.exists():
            result = GvisorParseResult()
            result.errors.append(f"File not found: {log_path}")
            return result

        start = time.monotonic()
        text = log_path.read_text(encoding="utf-8", errors="replace")
        result = self.parse_text(text)
        result.parse_time_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Parsed gVisor trace: %d/%d lines, %d events, %.1fms",
            result.parsed_events, result.total_lines, len(result.events),
            result.parse_time_ms,
        )
        return result

    def parse_text(self, text: str) -> GvisorParseResult:
        result = GvisorParseResult()
        # Pending entry events per thread, so an X line can complete its E.
        pending: dict[int, list[GvisorStraceEvent]] = {}

        for line in text.splitlines():
            result.total_lines += 1
            match = GVISOR_LINE_PATTERN.match(line)
            if not match:
                continue
            _mmdd, timestamp, _host_pid, tgid_s, tid_s, comm, phase, tail = (
                match.groups()
            )
            tid = int(tid_s)
            tgid = int(tgid_s)

            if phase == "E":
                event = self._parse_entry(tail, timestamp, tgid, tid, comm)
                if event is None:
                    continue
                result.events.append(event)
                result.parsed_events += 1
                pending.setdefault(tid, []).append(event)
                self._aggregate(event, result)
            else:
                ret = self._parse_exit(tail)
                if ret is None:
                    continue
                name, return_value = ret
                stack = pending.get(tid)
                completed = False
                if stack:
                    # The X belongs to the most recent matching E on this thread.
                    for candidate in reversed(stack):
                        if candidate.syscall == name:
                            candidate.return_value = return_value
                            stack.remove(candidate)
                            completed = True
                            break
                if not completed:
                    # No entry seen (truncated log, or a syscall that began
                    # before tracing); keep the observation rather than drop it.
                    event = self._parse_entry(tail, timestamp, tgid, tid, comm)
                    if event is None:
                        continue
                    event.phase = "X"
                    event.return_value = return_value
                    result.events.append(event)
                    result.parsed_events += 1
                    self._aggregate(event, result)

        return result

    # -------------------------------------------------------------- internals

    def _parse_entry(
        self, tail: str, timestamp: str, tgid: int, tid: int, comm: str
    ) -> Optional[GvisorStraceEvent]:
        match = GVISOR_ENTRY_PATTERN.match(tail)
        if not match:
            # An X line has a ` = ` suffix; tolerate it when called as a fallback.
            exit_match = GVISOR_EXIT_PATTERN.match(tail)
            if exit_match:
                name, args, _, _ = exit_match.groups()
                return self._make_event(name, args, "", timestamp, tgid, tid, comm)
            return None
        name, args = match.groups()
        return self._make_event(name, args, "", timestamp, tgid, tid, comm)

    def _parse_exit(self, tail: str) -> Optional[tuple[str, str]]:
        match = GVISOR_EXIT_PATTERN.match(tail)
        if not match:
            return None
        name, _args, return_value, _duration = match.groups()
        return name, return_value

    def _make_event(
        self,
        name: str,
        args: str,
        return_value: str,
        timestamp: str,
        tgid: int,
        tid: int,
        comm: str,
    ) -> GvisorStraceEvent:
        event = GvisorStraceEvent(
            timestamp=timestamp,
            pid=tgid,
            syscall=name,
            args=args,
            return_value=return_value,
            tid=tid,
            comm=comm,
            phase="E",
            paths=_extract_paths(args),
        )
        event.category = self._classifier._classify_syscall(name)
        event.severity = self._classifier._assess_severity(event)
        event.indicators = self._classifier._find_indicators(event)
        return event

    def _aggregate(self, event: GvisorStraceEvent, result: GvisorParseResult) -> None:
        """Build process/network/file summaries from the shared strace logic."""
        scratch = StraceParseResult()
        self._classifier._extract_structured_info(event, scratch)
        result.process_tree = scratch.process_tree
        result.network_connections.extend(scratch.network_connections)
        result.file_operations.extend(scratch.file_operations)
        result.process_operations.extend(scratch.process_operations)


# ---------------------------------------------------------------------------
# Reading the trace out of the runsc debug log
# ---------------------------------------------------------------------------


DEFAULT_GVISOR_LOG_DIR = "/var/log/hatchery-gvisor"


class GvisorLogReader:
    """Locate and read runsc debug logs, locally or through a VM.

    gVisor writes one ``*.boot.txt`` per sandbox into its ``--debug-log``
    directory. That directory is on the Docker host: directly readable on a
    Linux host, and inside the colima VM on macOS. This reader abstracts the
    two so the engine does not hardcode a host layout.
    """

    def __init__(
        self,
        log_dir: str = DEFAULT_GVISOR_LOG_DIR,
        remote: str = "",
        timeout: int = 30,
    ) -> None:
        self.log_dir = log_dir
        self.remote = remote
        self.timeout = timeout

    def available(self) -> tuple[bool, str]:
        """Whether this reader can read traces, and why not if it cannot."""
        if self.remote:
            return True, ""
        if Path(self.log_dir).is_dir():
            return True, ""
        return False, (
            f"gVisor debug log directory {self.log_dir!r} is not readable from "
            "this process; set HATCHERY_GVISOR_LOG_DIR or HATCHERY_GVISOR_REMOTE."
        )

    def find_for_container(self, container_id: str) -> Optional[str]:
        """Return the ``.boot.txt`` file belonging to ``container_id``."""
        if not container_id:
            return None
        if self.remote:
            script = (
                f"grep -l -- {_shquote(container_id)} "
                f"{_shquote(self.log_dir)}/*.boot.txt 2>/dev/null | head -1"
            )
            out = self._remote(script).strip()
            return out or None

        for path in sorted(Path(self.log_dir).glob("*.boot.txt")):
            try:
                if container_id in path.read_text(encoding="utf-8", errors="replace"):
                    return str(path)
            except OSError as e:  # pragma: no cover - permissions/races
                logger.warning("Could not read %s while searching for trace: %s", path, e)
        return None

    def read(self, path: str) -> str:
        """Read a trace file, remotely when configured."""
        if self.remote:
            return self._remote(f"cat {_shquote(path)}")
        return Path(path).read_text(encoding="utf-8", errors="replace")

    def _remote(self, script: str) -> str:
        cmd = [self.remote, "ssh", "--", "sudo", "bash", "-lc", script]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"{self.remote} ssh failed (rc={proc.returncode}): "
                f"{proc.stderr.strip()[:400]}"
            )
        return proc.stdout


def _shquote(value: str) -> str:
    """Single-quote a value for the remote shell."""
    return "'" + value.replace("'", "'\\''") + "'"


def default_gvisor_log_reader() -> GvisorLogReader:
    """Build a reader for this host, detecting the colima VM when relevant.

    Order of resolution:
      1. ``HATCHERY_GVISOR_REMOTE`` names a VM command (e.g. ``colima``).
      2. A readable ``HATCHERY_GVISOR_LOG_DIR`` (default
         ``/var/log/hatchery-gvisor``) is used directly.
      3. If neither holds and ``colima`` is on PATH with a colima Docker
         socket, read through ``colima ssh``.
    """
    import os

    log_dir = os.environ.get("HATCHERY_GVISOR_LOG_DIR", DEFAULT_GVISOR_LOG_DIR)
    remote = os.environ.get("HATCHERY_GVISOR_REMOTE", "")
    if not remote and not Path(log_dir).is_dir() and shutil.which("colima"):
        # The debug log lives inside the colima VM. Detect it by the daemon
        # actually running rather than by how DOCKER_HOST happens to be set,
        # because the active Docker context leaves DOCKER_HOST empty.
        try:
            status = subprocess.run(
                ["colima", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if status.returncode == 0:
                remote = "colima"
        except (OSError, subprocess.SubprocessError):
            pass
    return GvisorLogReader(log_dir=log_dir, remote=remote)


def read_gvisor_trace(
    container_id: str,
    reader: Optional[GvisorLogReader] = None,
) -> tuple[Optional[str], str]:
    """Read the gVisor Sentry trace for a container.

    Returns:
        ``(text, source)`` where ``source`` is the path read on success, or a
        human-readable reason on failure. Never raises.
    """
    reader = reader or default_gvisor_log_reader()
    ok, why = reader.available()
    if not ok:
        return None, why
    try:
        path = reader.find_for_container(container_id)
    except (RuntimeError, subprocess.SubprocessError) as e:
        return None, f"could not search the gVisor debug log: {e}"
    if not path:
        return None, (
            f"no gVisor .boot.txt in {reader.log_dir} references container "
            f"{container_id[:12]}"
        )
    try:
        return reader.read(path), path
    except (RuntimeError, subprocess.SubprocessError, OSError) as e:
        return None, f"could not read {path}: {e}"


__all__ = [
    "DEFAULT_GVISOR_LOG_DIR",
    "GvisorLogReader",
    "GvisorParseResult",
    "GvisorStraceEvent",
    "GvisorStraceParser",
    "default_gvisor_log_reader",
    "read_gvisor_trace",
]
