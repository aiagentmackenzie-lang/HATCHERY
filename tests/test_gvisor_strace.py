"""gVisor Sentry trace parser tests.

Everything here is written against a **real capture**
(``tests/fixtures/gvisor-strace-real.log``), taken from a runsc-annotated
container executing the recon-then-quiet probe. Inventing the gVisor line
format is the exact mistake ``docs/DECISIONS.md`` D6 records for the strace
parser; this suite deliberately does not repeat it.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.bundle import events_from_gvisor
from engine.monitor.evasion import EvasionSignal, analyze_evasion
from engine.monitor.gvisor_strace import (
    GVISOR_PATH_PATTERN,
    GvisorLogReader,
    GvisorStraceParser,
    read_gvisor_trace,
)

FIXTURE = Path(__file__).parent / "fixtures" / "gvisor-strace-real.log"


def parse():
    return GvisorStraceParser().parse_file(FIXTURE)


def test_real_fixture_parses_without_errors():
    result = parse()
    assert result.errors == []
    assert result.total_lines > 1000
    assert result.parsed_events > 100
    assert len(result.events) > 100


def test_boot_noise_is_filtered_out():
    """The debug log carries cli/config/timing lines too; only ``strace.go``
    lines are syscalls."""
    result = parse()
    assert result.parsed_events < result.total_lines


def test_entry_and_exit_lines_are_paired():
    """An ``E`` line carries the arguments and its following ``X`` line carries
    the return value. They must become one event, not two."""
    result = parse()
    opens = [
        e for e in result.events
        if e.syscall == "openat" and any("/proc/cpuinfo" in p for p in e.paths)
    ]
    assert opens, "the probe's /proc/cpuinfo openat must be captured"
    assert opens[0].return_value != ""
    # Pairing means events are not duplicated: no event is an X-only tail.
    assert all(e.phase == "E" for e in result.events)


def test_unquoted_gvisor_paths_are_extracted():
    """gVisor renders paths as ``<address> /path`` with no quotes; the parser
    must pull them out or the whole evasion path-matching breaks."""
    result = parse()
    cpu = [e for e in result.events if "/proc/cpuinfo" in e.paths]
    assert cpu
    assert "/proc/cpuinfo" in cpu[0].paths


def test_at_fdcwd_cwd_is_not_treated_as_a_target_path():
    """``AT_FDCWD /`` is the dirfd's cwd, not the syscall's target. Treating it
    as a path made HATCHERY's own directory look like sample impact."""
    result = parse()
    for event in result.events:
        assert "/" not in event.paths
        # The pattern deliberately only matches address-prefixed paths.
        assert "AT_FDCWD" not in GVISOR_PATH_PATTERN.pattern


def test_clock_gettime_is_visible_at_tier_two():
    """The empirical win over ptrace: gVisor's Sentry services the vDSO clock
    path, so clock_gettime appears in the trace even though ptrace cannot see
    it (the probe's strace capture contains none)."""
    result = parse()
    assert any(e.syscall == "clock_gettime" for e in result.events)


def test_rdtsc_and_cpuid_are_not_emitted_as_syscalls():
    """They are CPU instructions, not syscalls; --strace does not turn them
    into syscall lines. The collector's blind-spot list says so."""
    result = parse()
    assert not any(e.syscall in ("rdtsc", "rdtscp", "cpuid") for e in result.events)


def test_recon_signals_are_all_detected_from_the_gvisor_source():
    report = analyze_evasion(parse())
    for signal in (
        EvasionSignal.VM_ARTIFACT_PROBE,
        EvasionSignal.CPU_PROBE,
        EvasionSignal.UPTIME_PROBE,
        EvasionSignal.DEBUGGER_PROBE,
        EvasionSignal.ANALYSIS_TOOL_HUNT,
    ):
        assert signal.value in report.signals, signal


def test_gvisor_recon_run_is_evasive_and_inconclusive():
    """The required proof at tier 2: a recon-heavy, zero-impact run is reported
    evasive/INCONCLUSIVE from the gVisor event source."""
    report = analyze_evasion(parse())
    assert report.verdict == "evasive"
    assert report.score >= 60
    assert report.impact_score == 0
    assert report.recon_then_quiet is True
    assert report.inconclusive is True


def test_normalised_events_use_the_gvisor_sentry_source():
    rows = events_from_gvisor(parse())
    assert rows
    expected = {
        "timestamp", "pid", "syscall_name", "category", "severity",
        "args", "return_value", "raw_line", "source", "indicators",
    }
    for row in rows:
        assert set(row) == expected
        assert row["source"] == "gvisor-sentry"
        assert json.loads(row["args"])["paths"] is not None


def test_evasion_events_from_gvisor_source_keep_the_same_row_shape():
    report = analyze_evasion(parse())
    for row in report.normalized_events():
        assert row["category"] == "evasion"
        assert row["source"] == "evasion-analysis"


# ---------------------------------------------------------------------------
# Reading the trace out of the runsc debug log
# ---------------------------------------------------------------------------


def test_log_reader_finds_the_boot_log_for_a_container(tmp_path: Path):
    container_id = "b83cfd2ddbd75c1ad64245455a7805e246cae7fa6b3f7f119b6b4c5abca03c60"
    (tmp_path / "other.boot.txt").write_text("unrelated sandbox\n")
    target = tmp_path / "runsc.log.20261009-153309.780304.boot.txt"
    target.write_text(f"Args: [runsc-sandbox ... {container_id}]\n")
    reader = GvisorLogReader(log_dir=str(tmp_path), remote="")
    assert reader.find_for_container(container_id) == str(target)
    assert reader.find_for_container("0" * 64) is None


def test_read_gvisor_trace_returns_text_and_source(tmp_path: Path):
    container_id = "abc" * 20
    target = tmp_path / "runsc.log.1.boot.txt"
    target.write_text(f"container {container_id}\nI1009 strace.go:1]\n")
    reader = GvisorLogReader(log_dir=str(tmp_path), remote="")
    text, source = read_gvisor_trace(container_id, reader)
    assert text is not None
    assert source == str(target)


def test_read_gvisor_trace_reports_unavailable_without_raising(tmp_path: Path):
    reader = GvisorLogReader(log_dir=str(tmp_path / "missing"), remote="")
    text, source = read_gvisor_trace("deadbeef", reader)
    assert text is None
    assert "not readable" in source


def test_reader_reports_availability(tmp_path: Path):
    ok, why = GvisorLogReader(log_dir=str(tmp_path), remote="").available()
    assert ok and why == ""
    ok, why = GvisorLogReader(log_dir=str(tmp_path / "nope"), remote="").available()
    assert not ok and "HATCHERY_GVISOR_LOG_DIR" in why
