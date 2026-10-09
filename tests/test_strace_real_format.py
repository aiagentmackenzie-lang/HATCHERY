"""Regression tests for the on-disk strace format.

This file exists because the parser was written against an assumed line format
(`TIMESTAMP PID syscall(...)`) that strace does not produce with `-f -tt` to a
file (it writes `PID TIMESTAMP syscall(...)`). The unit tests passed, the parser
matched 0 of 227 lines of genuine output, and every dynamic analysis silently
reported "no behavioral events".

The fixture is a real capture, not a hand-written string. Keep it that way.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.monitor.strace_parser import EventCategory, StraceParser

FIXTURE = Path(__file__).parent / "fixtures" / "strace-real.log"


@pytest.fixture
def parser() -> StraceParser:
    return StraceParser()


def test_fixture_is_a_real_capture_with_pid_before_timestamp():
    first = next(
        line for line in FIXTURE.read_text().splitlines() if line and not line.startswith("#")
    )
    # PID, whitespace, timestamp — not the other way round.
    pid, timestamp, *_ = first.split(maxsplit=2)
    assert pid.isdigit()
    assert timestamp.count(":") == 2


def test_real_capture_parses_most_lines(parser: StraceParser):
    result = parser.parse_file(FIXTURE)
    assert result.errors == []
    assert result.parsed_events >= 30, "parser failed to match real strace output"
    assert result.parsed_events == len(result.events)


def test_real_capture_yields_expected_syscalls(parser: StraceParser):
    result = parser.parse_file(FIXTURE)
    syscalls = {e.syscall for e in result.events}
    # These names were chosen from what the capture demonstrably contains.
    for expected in ("execve", "openat", "brk", "mmap"):
        assert expected in syscalls, f"{expected} missing from parsed events"


def test_real_capture_pids_are_populated(parser: StraceParser):
    result = parser.parse_file(FIXTURE)
    assert all(e.pid > 0 for e in result.events)


def test_categories_are_assigned(parser: StraceParser):
    result = parser.parse_file(FIXTURE)
    categories = {e.category for e in result.events}
    assert EventCategory.PROCESS in categories
    assert EventCategory.FILE in categories
    assert EventCategory.MEMORY in categories


def test_execve_of_the_sample_is_classified_as_process(parser: StraceParser):
    result = parser.parse_file(FIXTURE)
    execve = [e for e in result.events if e.syscall == "execve"]
    assert execve
    assert all(e.category == EventCategory.PROCESS for e in execve)


def test_legacy_timestamp_first_format_still_parses(parser: StraceParser):
    """Older captures and hand-written examples use the other field order."""
    event = parser.parse_stream(
        '12:00:00.123456 1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
    )
    assert event is not None
    assert event.pid == 1234
    assert event.syscall == "openat"
    assert event.category == EventCategory.FILE


def test_bracketed_pid_prefix_parses(parser: StraceParser):
    """On a tty, strace wraps the pid in `[pid N]`."""
    event = parser.parse_stream('[pid  4321] 12:00:00.123456 close(3) = 0')
    assert event is not None
    assert event.pid == 4321
    assert event.syscall == "close"


def test_non_syscall_lines_are_ignored(parser: StraceParser):
    assert parser.parse_stream("") is None
    assert parser.parse_stream("+++ exited with 0 +++") is None
    assert parser.parse_stream("--- SIGCHLD {si_signo=SIGCHLD} ---") is None
