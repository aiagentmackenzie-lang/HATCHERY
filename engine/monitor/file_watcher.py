"""File system event watcher — parse inotifywait output for behavioral analysis.

Monitors file creation, modification, deletion, and attribute changes
inside the sandbox. Flags suspicious patterns like:
- Writing to /tmp, /dev/shm (dropper behavior)
- Modifying .bashrc, .ssh (persistence)
- Creating hidden files (dot-prefix)
- Writing executables (ELF/PE magic bytes)
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class FileEventType(str, Enum):
    """Types of file system events."""
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    MOVE = "move"
    ATTRIB = "attrib"
    UNKNOWN = "unknown"


class FileEventSeverity(str, Enum):
    """Severity levels for file events."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# inotifywait output format: TIMESTAMP PATH EVENT_NAMES
# e.g., 2026-04-14T12:00:00 /tmp/payload CREATE;ISDIR
INOTIFY_LINE_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(.+)$"
)

# Suspicious paths and their risk levels
SUSPICIOUS_PATH_RULES: list[tuple[re.Pattern, FileEventSeverity, str]] = [
    (re.compile(r"/tmp/"), FileEventSeverity.MEDIUM, "Temp directory write (dropper behavior)"),
    (re.compile(r"/dev/shm/"), FileEventSeverity.HIGH, "Shared memory write (stealthy file drop)"),
    (re.compile(r"/var/tmp/"), FileEventSeverity.MEDIUM, "Persistent temp write"),
    (re.compile(r"\.bashrc"), FileEventSeverity.CRITICAL, "Shell profile modification (persistence)"),
    (re.compile(r"\.ssh/"), FileEventSeverity.CRITICAL, "SSH directory modification (persistence)"),
    (re.compile(r"/etc/cron"), FileEventSeverity.CRITICAL, "Cron modification (persistence)"),
    (re.compile(r"/etc/init\.d"), FileEventSeverity.CRITICAL, "Init script modification (persistence)"),
    (re.compile(r"/etc/ld\.so"), FileEventSeverity.CRITICAL, "Dynamic linker modification (rootkit)"),
    (re.compile(r"/etc/passwd"), FileEventSeverity.HIGH, "Password file modification"),
    (re.compile(r"/etc/shadow"), FileEventSeverity.HIGH, "Shadow file modification"),
    (re.compile(r"/etc/hosts"), FileEventSeverity.MEDIUM, "Hosts file modification (DNS hijacking)"),
]

# Suspicious filename patterns
SUSPICIOUS_FILENAME_RULES: list[tuple[re.Pattern, FileEventSeverity, str]] = [
    (re.compile(r"^\."), FileEventSeverity.MEDIUM, "Hidden file (dot-prefix)"),
    (re.compile(r"\.sh$"), FileEventSeverity.MEDIUM, "Shell script created"),
    (re.compile(r"\.py$"), FileEventSeverity.LOW, "Python script created"),
    (re.compile(r"\.so$"), FileEventSeverity.HIGH, "Shared library created (possible LD_PRELOAD)"),
    (re.compile(r"\.dll$"), FileEventSeverity.HIGH, "DLL created (possible injection)"),
    (re.compile(r"\.exe$"), FileEventSeverity.HIGH, "Executable created"),
]

# Executable magic bytes
EXEC_MAGIC: dict[bytes, str] = {
    b"\x7fELF": "ELF",
    b"MZ": "PE",
    b"\xfe\xed\xfa": "Mach-O",
    b"#!": "Script",
}


@dataclass
class FileEvent:
    """A single file system event from inotifywait."""
    timestamp: str
    path: str
    event_type: FileEventType = FileEventType.UNKNOWN
    severity: FileEventSeverity = FileEventSeverity.INFO
    is_directory: bool = False
    indicators: list[str] = field(default_factory=list)
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    file_type: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "path": self.path,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "is_directory": self.is_directory,
            "indicators": self.indicators,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "file_type": self.file_type,
        }


@dataclass
class FileWatchResult:
    """Complete result of file system monitoring."""
    total_events: int = 0
    events: list[FileEvent] = field(default_factory=list)
    created_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    suspicious_events: list[FileEvent] = field(default_factory=list)
    dropped_executables: list[dict] = field(default_factory=list)
    persistence_attempts: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_events": self.total_events,
            "events": [e.to_dict() for e in self.events],
            "created_files": self.created_files,
            "modified_files": self.modified_files,
            "deleted_files": self.deleted_files,
            "suspicious_events": [e.to_dict() for e in self.suspicious_events],
            "dropped_executables": self.dropped_executables,
            "persistence_attempts": self.persistence_attempts,
            "errors": self.errors,
        }


class FileWatcher:
    """Parse and analyze inotifywait output for file system behavioral events.

    Processes inotifywait logs from the sandbox container, classifying
    each event by severity and flagging suspicious patterns.
    """

    def parse_log(self, log_path: Path) -> FileWatchResult:
        """Parse a complete inotifywait log file.

        Args:
            log_path: Path to the inotifywait output log.

        Returns:
            FileWatchResult with classified events.
        """
        if not log_path.exists():
            result = FileWatchResult()
            result.errors.append(f"File not found: {log_path}")
            return result

        content = log_path.read_text(encoding="utf-8", errors="replace")
        return self.parse_content(content)

    def parse_content(self, content: str) -> FileWatchResult:
        """Parse inotifywait log content from a string.

        Args:
            content: Raw inotifywait output text.

        Returns:
            FileWatchResult with classified events.
        """
        result = FileWatchResult()

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            event = self._parse_line(line)
            if event is not None:
                result.events.append(event)
                result.total_events += 1

                # Categorize
                if event.event_type == FileEventType.CREATE:
                    result.created_files.append(event.path)
                elif event.event_type == FileEventType.MODIFY:
                    result.modified_files.append(event.path)
                elif event.event_type == FileEventType.DELETE:
                    result.deleted_files.append(event.path)

                if event.severity in (
                    FileEventSeverity.HIGH, FileEventSeverity.CRITICAL
                ):
                    result.suspicious_events.append(event)

                # Track persistence attempts
                if any(
                    "persistence" in ind.lower() for ind in event.indicators
                ):
                    result.persistence_attempts.append(event.to_dict())

        logger.info(
            "Parsed inotify log: %d events, %d suspicious, %d persistence attempts",
            result.total_events,
            len(result.suspicious_events),
            len(result.persistence_attempts),
        )
        return result

    def _parse_line(self, line: str) -> Optional[FileEvent]:
        """Parse a single inotifywait output line.

        Format: 2026-04-14T12:00:00 /path/to/file CREATE;ISDIR
        """
        match = INOTIFY_LINE_PATTERN.match(line)
        if not match:
            return None

        timestamp, path, event_str = match.groups()

        # Parse event type and flags
        is_dir = "ISDIR" in event_str
        event_str = event_str.replace(";ISDIR", "").replace(",ISDIR", "").strip()

        event_type = self._map_event_type(event_str)

        event = FileEvent(
            timestamp=timestamp,
            path=path,
            event_type=event_type,
            is_directory=is_dir,
        )

        # Assess severity and find indicators
        event.severity, event.indicators = self._assess_event(event)

        return event

    def _map_event_type(self, event_str: str) -> FileEventType:
        """Map inotifywait event string to FileEventType."""
        event_str = event_str.upper().strip()
        mapping: dict[str, FileEventType] = {
            "CREATE": FileEventType.CREATE,
            "MODIFY": FileEventType.MODIFY,
            "DELETE": FileEventType.DELETE,
            "MOVED_FROM": FileEventType.MOVE,
            "MOVED_TO": FileEventType.MOVE,
            "ATTRIB": FileEventType.ATTRIB,
            "ACCESS": FileEventType.UNKNOWN,
            "CLOSE_WRITE": FileEventType.MODIFY,
            "CLOSE_NOWRITE": FileEventType.UNKNOWN,
            "OPEN": FileEventType.UNKNOWN,
        }
        # Handle comma-separated events
        for part in event_str.split(","):
            part = part.strip()
            if part in mapping:
                return mapping[part]
        return FileEventType.UNKNOWN

    def _assess_event(
        self, event: FileEvent
    ) -> tuple[FileEventSeverity, list[str]]:
        """Assess severity and find indicators for a file event.

        Returns:
            Tuple of (severity, indicators_list).
        """
        max_severity = FileEventSeverity.INFO
        indicators: list[str] = []

        path = event.path

        # Check suspicious path rules
        for pattern, severity, description in SUSPICIOUS_PATH_RULES:
            if pattern.search(path):
                if severity.value > max_severity.value:
                    max_severity = severity
                indicators.append(description)

        # Check suspicious filename rules (only for CREATE/MODIFY)
        if event.event_type in (FileEventType.CREATE, FileEventType.MODIFY):
            filename = path.rsplit("/", 1)[-1] if "/" in path else path
            for pattern, severity, description in SUSPICIOUS_FILENAME_RULES:
                if pattern.search(filename):
                    if severity.value > max_severity.value:
                        max_severity = severity
                    indicators.append(description)

        # Persistence: modifying shell profiles or SSH config
        if event.event_type == FileEventType.MODIFY:
            if any(p in path for p in (".bashrc", ".bash_profile", ".zshrc", ".profile")):
                max_severity = FileEventSeverity.CRITICAL
                indicators.append("Shell profile modification — persistence mechanism")

        return max_severity, indicators

    def classify_dropped_file(self, file_path: Path) -> Optional[dict]:
        """Classify a dropped file by hash, size, and magic bytes.

        Args:
            file_path: Path to the dropped file.

        Returns:
            Dict with file classification, or None if file doesn't exist.
        """
        if not file_path.exists():
            return None

        data = file_path.read_bytes()
        file_size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()

        # Detect file type from magic bytes
        file_type = "Unknown"
        for magic, ftype in EXEC_MAGIC.items():
            if data[:len(magic)] == magic:
                file_type = ftype
                break

        result = {
            "path": str(file_path),
            "sha256": sha256,
            "md5": md5,
            "size": file_size,
            "type": file_type,
            "is_executable": file_type in ("ELF", "PE", "Mach-O"),
        }

        if result["is_executable"]:
            logger.warning(
                "Dropped executable detected: %s (%s, %s)",
                file_path.name, file_type, sha256[:16],
            )

        return result