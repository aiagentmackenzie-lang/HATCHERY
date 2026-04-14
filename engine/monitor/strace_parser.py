"""strace output parser — convert raw syscall traces into structured events.

Parses strace -f -tt output into typed event objects organized by:
- Category: file, network, process, memory, system
- Severity: info, low, medium, high, critical
- Timestamp: microsecond precision from strace -tt

Supports real-time streaming (tail -f) and batch parsing of completed logs.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class EventCategory(str, Enum):
    """Behavioral event categories."""
    FILE = "file"
    NETWORK = "network"
    PROCESS = "process"
    MEMORY = "memory"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class EventSeverity(str, Enum):
    """Event severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# strace line patterns
# Format: HH:MM:SS.microseconds pid syscall(args) = retval
STRACE_LINE_PATTERN = re.compile(
    r"^(\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(\d+)\s+"
    r"(\w+)\s*"
    r"\((.*?)\)\s*"
    r"=\s*(.+)$"
)

# Process lifecycle lines
STRACE_CLONE_PATTERN = re.compile(
    r"^(clone|fork|vfork)\s*"
)

# Signal lines
STRACE_SIGNAL_PATTERN = re.compile(
    r"--- SIG(\w+) .+ ---"
)

# Process exit lines
STRACE_EXIT_PATTERN = re.compile(
    r"^\+\+\+ exited with (\d+) \+\+\+"
)

# Network-related syscalls
NETWORK_SYSCALLS: set[str] = {
    "socket", "bind", "listen", "accept", "accept4",
    "connect", "send", "sendto", "sendmsg",
    "recv", "recvfrom", "recvmsg",
    "getsockopt", "setsockopt", "getsockname", "getpeername",
    "shutdown", "getaddrinfo", "gethostbyname",
}

# Process-related syscalls
PROCESS_SYSCALLS: set[str] = {
    "execve", "execveat", "fork", "vfork", "clone", "clone3",
    "wait4", "waitpid", "kill", "tkill", "tgkill",
    "exit", "exit_group", "prctl",
}

# File-related syscalls
FILE_SYSCALLS: set[str] = {
    "open", "openat", "openat2", "read", "write", "close",
    "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "chmod", "fchmod", "fchmodat",
    "mkdir", "mkdirat", "rmdir",
    "creat", "link", "linkat", "symlink", "symlinkat",
    "stat", "lstat", "fstat", "statx",
    "access", "faccessat", "faccessat2",
    "truncate", "ftruncate",
    "chdir", "fchdir",
}

# Memory-related syscalls
MEMORY_SYSCALLS: set[str] = {
    "mmap", "mmap2", "munmap", "mremap",
    "mprotect", "pkey_mprotect",
    "brk", "sbrk",
    "shmget", "shmat", "shmdt", "shmctl",
}

# High-severity indicators
CRITICAL_INDICATORS: dict[str, list[str]] = {
    "connect": ["evil", "c2", "botnet", "callback"],
    "execve": ["/bin/sh", "/bin/bash", "cmd.exe", "powershell"],
    "openat": ["/etc/shadow", "/etc/passwd", "/root/.ssh", "/home/.ssh"],
    "write": [".bashrc", ".ssh", "crontab", "/etc/cron"],
}

# Suspicious path patterns
SUSPICIOUS_PATHS: list[re.Pattern] = [
    re.compile(r"/tmp/", re.IGNORECASE),
    re.compile(r"/dev/shm/", re.IGNORECASE),
    re.compile(r"/var/tmp/", re.IGNORECASE),
    re.compile(r"\.bashrc", re.IGNORECASE),
    re.compile(r"\.ssh/", re.IGNORECASE),
    re.compile(r"/etc/cron", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"/etc/shadow", re.IGNORECASE),
]


@dataclass
class StraceEvent:
    """A single parsed strace event."""
    timestamp: str
    pid: int
    syscall: str
    args: str
    return_value: str
    category: EventCategory = EventCategory.UNKNOWN
    severity: EventSeverity = EventSeverity.INFO
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "pid": self.pid,
            "syscall": self.syscall,
            "args": self.args,
            "return_value": self.return_value,
            "category": self.category.value,
            "severity": self.severity.value,
            "indicators": self.indicators,
        }


@dataclass
class StraceParseResult:
    """Complete result of parsing an strace log."""
    total_lines: int = 0
    parsed_events: int = 0
    events: list[StraceEvent] = field(default_factory=list)
    process_tree: dict[int, list[int]] = field(default_factory=dict)
    network_connections: list[dict] = field(default_factory=list)
    file_operations: list[dict] = field(default_factory=list)
    process_operations: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    parse_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
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


class StraceParser:
    """Parse strace output into structured behavioral events.

    Handles the output of `strace -f -tt -s 1024 -e trace=all` and
    classifies each syscall into categories with severity scoring.
    """

    def parse_file(self, log_path: Path) -> StraceParseResult:
        """Parse a complete strace log file.

        Args:
            log_path: Path to the strace output log.

        Returns:
            StraceParseResult with all parsed events.
        """
        import time

        if not log_path.exists():
            result = StraceParseResult()
            result.errors.append(f"File not found: {log_path}")
            return result

        start = time.monotonic()
        result = StraceParseResult()

        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            result.errors.append(f"Failed to read log: {e}")
            return result

        for line in content.splitlines():
            result.total_lines += 1
            event = self._parse_line(line)
            if event is not None:
                result.events.append(event)
                result.parsed_events += 1
                self._extract_structured_info(event, result)

        result.parse_time_ms = (time.monotonic() - start) * 1000

        logger.info(
            "Parsed strace log: %d/%d lines, %d events, %.1fms",
            result.parsed_events, result.total_lines,
            len(result.events), result.parse_time_ms,
        )
        return result

    def parse_stream(self, line: str) -> Optional[StraceEvent]:
        """Parse a single strace output line (for real-time streaming).

        Args:
            line: A single line from strace output.

        Returns:
            Parsed StraceEvent, or None if the line is not a syscall.
        """
        return self._parse_line(line)

    def _parse_line(self, line: str) -> Optional[StraceEvent]:
        """Parse a single strace output line.

        Args:
            line: Raw strace output line.

        Returns:
            Structured StraceEvent, or None.
        """
        line = line.strip()
        if not line:
            return None

        # Try matching standard syscall line
        match = STRACE_LINE_PATTERN.match(line)
        if match:
            timestamp, pid_str, syscall, args, retval = match.groups()
            try:
                pid = int(pid_str)
            except ValueError:
                return None

            event = StraceEvent(
                timestamp=timestamp,
                pid=pid,
                syscall=syscall,
                args=args,
                return_value=retval,
            )

            # Classify
            event.category = self._classify_syscall(syscall)
            event.severity = self._assess_severity(event)
            event.indicators = self._find_indicators(event)

            return event

        # Handle signal lines
        sig_match = STRACE_SIGNAL_PATTERN.match(line)
        if sig_match:
            return None  # Skip for now

        # Handle exit lines
        exit_match = STRACE_EXIT_PATTERN.match(line)
        if exit_match:
            return None  # Skip for now

        return None

    def _classify_syscall(self, syscall: str) -> EventCategory:
        """Classify a syscall into an event category."""
        if syscall in NETWORK_SYSCALLS:
            return EventCategory.NETWORK
        if syscall in PROCESS_SYSCALLS:
            return EventCategory.PROCESS
        if syscall in FILE_SYSCALLS:
            return EventCategory.FILE
        if syscall in MEMORY_SYSCALLS:
            return EventCategory.MEMORY
        return EventCategory.SYSTEM

    def _assess_severity(self, event: StraceEvent) -> EventSeverity:
        """Assess the severity of a syscall event."""
        syscall = event.syscall
        args_lower = event.args.lower()

        # Critical: connects to suspicious endpoints or executes shells
        if syscall in CRITICAL_INDICATORS:
            for indicator in CRITICAL_INDICATORS[syscall]:
                if indicator in args_lower:
                    return EventSeverity.CRITICAL

        # High: process creation, network connections, sensitive file access
        if syscall in PROCESS_SYSCALLS:
            return EventSeverity.HIGH
        if syscall in NETWORK_SYSCALLS and syscall == "connect":
            return EventSeverity.HIGH
        if syscall in ("openat", "open") and any(
            p.search(args_lower) for p in SUSPICIOUS_PATHS
        ):
            return EventSeverity.HIGH

        # Medium: network operations, sensitive writes
        if syscall in NETWORK_SYSCALLS:
            return EventSeverity.MEDIUM
        if syscall in ("write", "chmod") and any(
            p.search(args_lower) for p in SUSPICIOUS_PATHS
        ):
            return EventSeverity.MEDIUM
        if syscall in MEMORY_SYSCALLS and syscall == "mprotect":
            # mprotect with PROT_EXEC is suspicious
            if "PROT_EXEC" in args_lower:
                return EventSeverity.HIGH
            return EventSeverity.MEDIUM

        # Low: basic file operations
        if syscall in FILE_SYSCALLS:
            return EventSeverity.LOW

        return EventSeverity.INFO

    def _find_indicators(self, event: StraceEvent) -> list[str]:
        """Find suspicious indicators in a syscall event."""
        indicators: list[str] = []
        args_lower = event.args.lower()

        if event.syscall in CRITICAL_INDICATORS:
            for indicator in CRITICAL_INDICATORS[event.syscall]:
                if indicator in args_lower:
                    indicators.append(f"Suspicious {event.syscall}: {indicator}")

        for pattern in SUSPICIOUS_PATHS:
            if pattern.search(args_lower):
                indicators.append(f"Suspicious path in {event.syscall}")
                break

        # Check for process injection patterns
        if event.syscall in ("ptrace", "process_vm_readv", "process_vm_writev"):
            indicators.append(f"Process manipulation: {event.syscall}")

        # Check for memory protection changes
        if event.syscall == "mprotect" and "PROT_EXEC" in args_lower:
            indicators.append("Memory made executable (possible shellcode)")

        return indicators

    def _extract_structured_info(
        self, event: StraceEvent, result: StraceParseResult
    ) -> None:
        """Extract structured information from events into result collections.

        Builds process trees, network connection lists, and file operation
        summaries as we parse.
        """
        # Process tree: track clone/fork/vfork
        if event.syscall in ("clone", "fork", "vfork", "clone3"):
            # Parse child PID from return value
            try:
                child_pid = int(event.return_value.strip())
                if child_pid > 0:
                    if event.pid not in result.process_tree:
                        result.process_tree[event.pid] = []
                    result.process_tree[event.pid].append(child_pid)
            except (ValueError, AttributeError):
                pass

        # Network connections
        if event.syscall == "connect":
            conn_info = self._parse_connect_args(event.args)
            if conn_info:
                conn_info["pid"] = event.pid
                conn_info["timestamp"] = event.timestamp
                result.network_connections.append(conn_info)

        # File operations summary
        if event.syscall in ("openat", "open", "unlink", "unlinkat", "rename"):
            file_op = self._parse_file_op(event)
            if file_op:
                result.file_operations.append(file_op)

        # Process operations summary
        if event.syscall in ("execve", "execveat"):
            proc_op = self._parse_execve(event)
            if proc_op:
                result.process_operations.append(proc_op)

    def _parse_connect_args(self, args: str) -> Optional[dict]:
        """Extract connection details from connect() arguments.

        Parses: connect(3, {sa_family=AF_INET, sin_port=htons(80),
                  sin_addr=inet_addr("185.x.x.x")}, 16)
        """
        # Extract IP and port from inet_addr format
        ip_match = re.search(r'inet_addr\("([^"]+)"\)', args)
        port_match = re.search(r'sin_port=htons\((\d+)\)', args)

        # Also handle AF_INET6
        ip6_match = re.search(r'inet_pton\(AF_INET6,\s*"([^"]+)"\)', args)

        ip = ip_match.group(1) if ip_match else (ip6_match.group(1) if ip6_match else None)
        port = int(port_match.group(1)) if port_match else None

        if ip or port:
            return {"ip": ip or "unknown", "port": port or 0}

        # Handle AF_UNIX
        if "AF_UNIX" in args:
            path_match = re.search(r'"([^"]+)"', args)
            return {"ip": "unix", "port": 0, "path": path_match.group(1) if path_match else ""}

        return None

    def _parse_file_op(self, event: StraceEvent) -> Optional[dict]:
        """Extract file operation details from an event."""
        # Try to extract the file path from arguments
        path_match = re.search(r'"([^"]+)"', event.args)
        path = path_match.group(1) if path_match else ""

        if not path:
            return None

        return {
            "pid": event.pid,
            "timestamp": event.timestamp,
            "operation": event.syscall,
            "path": path,
            "result": event.return_value,
        }

    def _parse_execve(self, event: StraceEvent) -> Optional[dict]:
        """Extract execve details from an event."""
        path_match = re.search(r'"([^"]+)"', event.args)
        path = path_match.group(1) if path_match else ""

        # Try to extract argv
        argv_match = re.search(r'\[([^\]]+)\]', event.args)
        argv_str = argv_match.group(1) if argv_match else ""

        return {
            "pid": event.pid,
            "timestamp": event.timestamp,
            "operation": "execve",
            "path": path,
            "argv": argv_str,
            "result": event.return_value,
        }