"""Tests for HATCHERY file watcher (inotify parser)."""

import pytest
from pathlib import Path

from engine.monitor.file_watcher import (
    FileWatcher,
    FileEvent,
    FileEventType,
    FileEventSeverity,
    FileWatchResult,
    SUSPICIOUS_PATH_RULES,
)


class TestFileWatcher:
    """Test inotifywait log parsing and classification."""

    def setup_method(self):
        self.watcher = FileWatcher()

    def test_parse_create_event(self):
        """Test parsing a file creation event."""
        content = '2026-04-14T12:00:00 /tmp/payload CREATE'
        result = self.watcher.parse_content(content)

        assert result.total_events == 1
        assert len(result.created_files) == 1
        assert "/tmp/payload" in result.created_files

    def test_parse_modify_event(self):
        """Test parsing a file modification event."""
        content = '2026-04-14T12:00:01 /home/user/.bashrc MODIFY'
        result = self.watcher.parse_content(content)

        assert result.total_events == 1
        assert len(result.modified_files) == 1
        assert "/home/user/.bashrc" in result.modified_files

    def test_parse_delete_event(self):
        """Test parsing a file deletion event."""
        content = '2026-04-14T12:00:02 /tmp/important.log DELETE'
        result = self.watcher.parse_content(content)

        assert result.total_events == 1
        assert len(result.deleted_files) == 1

    def test_parse_directory_event(self):
        """Test parsing an event with ISDIR flag."""
        content = '2026-04-14T12:00:03 /tmp/malware_dir CREATE;ISDIR'
        result = self.watcher.parse_content(content)

        assert result.total_events == 1
        event = result.events[0]
        assert event.is_directory is True

    def test_suspicious_path_tmp(self):
        """Test that /tmp writes get MEDIUM severity."""
        content = '2026-04-14T12:00:00 /tmp/payload CREATE'
        result = self.watcher.parse_content(content)

        assert result.total_events == 1
        event = result.events[0]
        assert event.severity == FileEventSeverity.MEDIUM
        assert any("Temp directory" in ind for ind in event.indicators)

    def test_suspicious_path_dev_shm(self):
        """Test that /dev/shm writes get HIGH severity."""
        content = '2026-04-14T12:00:00 /dev/shm/backdoor CREATE'
        result = self.watcher.parse_content(content)

        event = result.events[0]
        assert event.severity == FileEventSeverity.HIGH
        assert any("Shared memory" in ind for ind in event.indicators)

    def test_suspicious_bashrc(self):
        """Test that .bashrc modifications get CRITICAL severity."""
        content = '2026-04-14T12:00:00 /home/user/.bashrc MODIFY'
        result = self.watcher.parse_content(content)

        event = result.events[0]
        assert event.severity == FileEventSeverity.CRITICAL
        assert any("persistence" in ind.lower() for ind in event.indicators)

    def test_suspicious_ssh(self):
        """Test that .ssh modifications get CRITICAL severity."""
        content = '2026-04-14T12:00:00 /home/user/.ssh/authorized_keys MODIFY'
        result = self.watcher.parse_content(content)

        event = result.events[0]
        assert event.severity == FileEventSeverity.CRITICAL

    def test_suspicious_cron(self):
        """Test that /etc/cron modifications get CRITICAL severity."""
        content = '2026-04-14T12:00:00 /etc/cron.d/backdoor MODIFY'
        result = self.watcher.parse_content(content)

        event = result.events[0]
        assert event.severity == FileEventSeverity.CRITICAL
        assert any("Cron" in ind for ind in event.indicators)

    def test_multiple_events(self):
        """Test parsing multiple inotifywait events."""
        content = """2026-04-14T12:00:00 /tmp/payload CREATE
2026-04-14T12:00:01 /tmp/payload MODIFY
2026-04-14T12:00:02 /home/user/.bashrc MODIFY
2026-04-14T12:00:03 /etc/hosts MODIFY
"""
        result = self.watcher.parse_content(content)

        assert result.total_events == 4
        assert len(result.created_files) == 1
        assert len(result.modified_files) == 3
        # suspicious_events only includes HIGH and CRITICAL severity events
        # .bashrc MODIFY = CRITICAL (persistence); /tmp and /etc/hosts are MEDIUM
        # So only .bashrc appears in suspicious_events
        assert len(result.suspicious_events) >= 1
        assert any(
            e.severity in (FileEventSeverity.HIGH, FileEventSeverity.CRITICAL)
            for e in result.suspicious_events
        )

    def test_persistence_detection(self):
        """Test that persistence attempts are tracked separately."""
        content = '2026-04-14T12:00:00 /home/user/.bashrc MODIFY'
        result = self.watcher.parse_content(content)

        assert len(result.persistence_attempts) >= 1

    def test_empty_content(self):
        """Test parsing empty content."""
        result = self.watcher.parse_content("")
        assert result.total_events == 0
        assert result.events == []

    def test_malformed_lines_skipped(self):
        """Test that malformed lines are skipped."""
        content = """some random text
another bad line
2026-04-14T12:00:00 /tmp/ok CREATE
"""
        result = self.watcher.parse_content(content)
        assert result.total_events == 1

    def test_parse_log_from_file(self, tmp_path):
        """Test parsing from an actual file."""
        log_content = "2026-04-14T12:00:00 /tmp/test CREATE\n"
        log_file = tmp_path / "inotify.log"
        log_file.write_text(log_content)

        result = self.watcher.parse_log(log_file)
        assert result.total_events == 1

    def test_parse_log_nonexistent_file(self):
        """Test parsing a nonexistent file."""
        result = self.watcher.parse_log(Path("/nonexistent/path"))
        assert len(result.errors) > 0

    def test_file_event_to_dict(self):
        """Test FileEvent serialization."""
        event = FileEvent(
            timestamp="2026-04-14T12:00:00",
            path="/tmp/test",
            event_type=FileEventType.CREATE,
            severity=FileEventSeverity.MEDIUM,
        )
        d = event.to_dict()
        assert d["path"] == "/tmp/test"
        assert d["event_type"] == "create"
        assert d["severity"] == "medium"

    def test_classify_dropped_file(self, tmp_path):
        """Test classifying a dropped file by magic bytes."""
        test_file = tmp_path / "dropped"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)  # ELF magic

        result = self.watcher.classify_dropped_file(test_file)
        assert result is not None
        assert result["type"] == "ELF"
        assert result["is_executable"] is True

    def test_classify_dropped_pe_file(self, tmp_path):
        """Test classifying a dropped PE file."""
        test_file = tmp_path / "dropped.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)  # PE magic

        result = self.watcher.classify_dropped_file(test_file)
        assert result is not None
        assert result["type"] == "PE"

    def test_classify_dropped_nonexistent(self):
        """Test classifying a nonexistent dropped file."""
        result = self.watcher.classify_dropped_file(Path("/nonexistent"))
        assert result is None

    def test_hidden_file_detection(self):
        """Test that hidden files (dot-prefix) are flagged."""
        content = '2026-04-14T12:00:00 /tmp/.hidden CREATE'
        result = self.watcher.parse_content(content)

        event = result.events[0]
        assert any("Hidden file" in ind for ind in event.indicators)

    def test_executable_extension_detection(self):
        """Test that .exe creation is flagged."""
        content = '2026-04-14T12:00:00 /tmp/payload.exe CREATE'
        result = self.watcher.parse_content(content)

        event = result.events[0]
        assert any("Executable" in ind or ".exe" in ind.lower() for ind in event.indicators)

    def test_so_file_detection(self):
        """Test that .so file creation is flagged."""
        content = '2026-04-14T12:00:00 /tmp/libmalicious.so CREATE'
        result = self.watcher.parse_content(content)

        event = result.events[0]
        assert any("Shared library" in ind for ind in event.indicators)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])