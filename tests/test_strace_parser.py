"""Tests for HATCHERY strace parser."""

import pytest
from pathlib import Path
from engine.monitor.strace_parser import StraceParser, EventCategory, EventSeverity


class TestStraceParser:
    """Test strace output parsing."""

    def setup_method(self):
        self.parser = StraceParser()

    def test_parse_openat_syscall(self):
        """Test parsing a simple openat syscall."""
        line = '12:00:00.123456 1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
        event = self.parser.parse_stream(line)

        assert event is not None
        assert event.syscall == "openat"
        assert event.pid == 1234
        assert event.category == EventCategory.FILE
        assert "/etc/passwd" in event.args

    def test_parse_connect_syscall(self):
        """Test parsing a connect syscall (network)."""
        line = '12:00:01.234567 5678 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("185.1.2.3")}, 16) = 0'
        event = self.parser.parse_stream(line)

        assert event is not None
        assert event.syscall == "connect"
        assert event.category == EventCategory.NETWORK
        assert event.severity == EventSeverity.HIGH

    def test_parse_execve_syscall(self):
        """Test parsing execve (process execution)."""
        line = '12:00:02.345678 91011 execve("/bin/sh", ["/bin/sh", "-c", "whoami"], 0x7fff...) = 0'
        event = self.parser.parse_stream(line)

        assert event is not None
        assert event.syscall == "execve"
        assert event.category == EventCategory.PROCESS
        assert event.severity == EventSeverity.HIGH

    def test_parse_mmap_syscall(self):
        """Test parsing mmap (memory operation)."""
        line = '12:00:03.456789 1112 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1234567000'
        event = self.parser.parse_stream(line)

        assert event is not None
        assert event.syscall == "mmap"
        assert event.category == EventCategory.MEMORY

    def test_parse_empty_line(self):
        """Test that empty lines return None."""
        event = self.parser.parse_stream("")
        assert event is None

    def test_parse_non_syscall_line(self):
        """Test that non-syscall lines return None."""
        event = self.parser.parse_stream("some random text")
        assert event is None

    def test_parse_clone_for_process_tree(self):
        """Test that clone/fork syscalls build process tree."""
        line = '12:00:04.567890 1000 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|...) = 2000'
        event = self.parser.parse_stream(line)

        assert event is not None
        assert event.syscall == "clone"
        assert event.category == EventCategory.PROCESS

    def test_parse_file(self, tmp_path):
        """Test parsing a complete strace log file."""
        log_content = """12:00:00.100000 100 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3
12:00:00.200000 100 read(3, "127.0.0.1\\tlocalhost", 4096) = 20
12:00:01.100000 100 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
12:00:02.100000 100 execve("/bin/sh", ["/bin/sh"], 0x0) = 0
12:00:03.100000 200 clone(child_stack=0, flags=...) = 300
"""
        log_file = tmp_path / "strace.log"
        log_file.write_text(log_content)

        result = self.parser.parse_file(log_file)

        assert result.parsed_events == 5
        assert result.total_lines == 5
        assert len(result.network_connections) >= 1
        assert len(result.process_operations) >= 1
        assert 100 in result.process_tree
        assert 200 in result.process_tree[100]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])