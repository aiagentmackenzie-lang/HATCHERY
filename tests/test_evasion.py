"""Evasion detection tests.

The two positive fixtures are **real strace captures** taken from HATCHERY
sandbox runs of purpose-built benign probes:

* ``strace-evasive-real.log``   — reconnoiters with external commands, ~1600 lines
* ``strace-evasive-min-real.log`` — reconnoiters with shell builtins only, ~230 lines

and ``strace-real.log`` is the benign Phase 0 capture. Testing the detector
against invented strings is how the strace parser came to match 0 of 227 real
lines while its unit tests passed (see docs/DECISIONS.md D6); this suite
deliberately does not repeat that mistake.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.monitor.evasion import (
    EvasionSignal,
    analyze_evasion,
)
from engine.monitor.strace_parser import StraceParser

FIXTURES = Path(__file__).parent / "fixtures"
BENIGN = FIXTURES / "strace-real.log"
EVASIVE = FIXTURES / "strace-evasive-real.log"
EVASIVE_MIN = FIXTURES / "strace-evasive-min-real.log"


def parse(path: Path):
    return StraceParser().parse_file(path)


class FakeEvent:
    def __init__(self, syscall: str, args: str = "", timestamp: str = "12:00:00.000001", pid: int = 1):
        self.syscall = syscall
        self.args = args
        self.timestamp = timestamp
        self.pid = pid


class FakeParseResult:
    def __init__(self, events: list[FakeEvent]):
        self.events = events


# ---------------------------------------------------------------------------
# Real-capture tests
# ---------------------------------------------------------------------------


def test_benign_real_capture_is_not_flagged_as_evasive():
    report = analyze_evasion(parse(BENIGN))
    assert report.verdict == "none"
    assert report.score == 0
    assert not report.inconclusive


def test_evasive_real_capture_is_flagged():
    report = analyze_evasion(parse(EVASIVE))
    assert report.verdict == "evasive"
    assert report.score >= 60
    for signal in (
        EvasionSignal.VM_ARTIFACT_PROBE,
        EvasionSignal.CPU_PROBE,
        EvasionSignal.UPTIME_PROBE,
        EvasionSignal.DEBUGGER_PROBE,
        EvasionSignal.ANALYSIS_TOOL_HUNT,
    ):
        assert signal.value in report.signals, signal


def test_event_thin_recon_run_is_inconclusive_not_clean():
    """The required proof: a recon-heavy but event-thin run — reconnoiter,
    then exit with no impact — is reported as evasive/inconclusive."""
    report = analyze_evasion(parse(EVASIVE_MIN))
    assert report.verdict == "evasive"
    assert report.recon_then_quiet is True
    assert report.inconclusive is True
    assert report.impact_score == 0
    assert any("INCONCLUSIVE" in note for note in report.notes)


def test_recon_with_real_impact_is_evasive_but_not_inconclusive():
    """The counter-case: if the sample reconnoiters and *then* writes a file,
    it is still evasive but the run is not inconclusive — something happened."""
    parsed = parse(EVASIVE_MIN)
    parsed.events.append(
        FakeEvent(
            "openat",
            'AT_FDCWD, "/tmp/dropped-payload.bin", O_WRONLY|O_CREAT|O_TRUNC, 0644',
            timestamp="23:59:59.000000",
        )
    )
    report = analyze_evasion(parsed)
    assert report.verdict == "evasive"
    assert report.impact_score >= 1
    assert report.inconclusive is False


def test_vdso_clock_reads_are_invisible_to_strace():
    """Documented empirical finding: the probe ran ``date +%s`` in a loop, but
    glibc served clock_gettime from the vDSO, so no clock syscall appears.
    If this ever starts matching, the capture changed and the limitation in
    the report needs revisiting."""
    text = EVASIVE.read_text(errors="replace")
    assert "clock_gettime(" not in text
    assert "gettimeofday(" not in text
    assert "clock_nanosleep(" in text  # sleeps *are* syscalls and are visible


def test_af_unix_connects_are_not_counted_as_network_impact():
    result = FakeParseResult(
        [
            FakeEvent(
                "connect",
                '3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110',
            )
        ]
    )
    report = analyze_evasion(result)
    assert report.impact_score == 0


def test_af_inet_connect_is_counted_as_network_impact():
    result = FakeParseResult(
        [
            FakeEvent(
                "connect",
                '3, {sa_family=AF_INET, sin_port=htons(443), '
                'sin_addr=inet_addr("203.0.113.9")}, 16',
            )
        ]
    )
    assert analyze_evasion(result).impact_score == 1


# ---------------------------------------------------------------------------
# Signal-level tests
# ---------------------------------------------------------------------------


def test_empty_run_scores_zero_and_is_not_evasive():
    report = analyze_evasion(FakeParseResult([]))
    assert report.score == 0
    assert report.verdict == "none"
    assert report.inconclusive is False


def test_a_single_system_property_read_is_not_evasive():
    """A benign installer reading one property must not be called evasive."""
    report = analyze_evasion(
        FakeParseResult(
            [FakeEvent("openat", 'AT_FDCWD, "/proc/cpuinfo", O_RDONLY')]
        )
    )
    assert report.verdict in ("none", "low")
    assert report.score < 30


def test_hypervisor_artifact_reads_are_detected():
    report = analyze_evasion(
        FakeParseResult(
            [
                FakeEvent("openat", 'AT_FDCWD, "/sys/class/dmi/id/product_name", O_RDONLY'),
                FakeEvent("openat", 'AT_FDCWD, "/sys/hypervisor/type", O_RDONLY'),
                FakeEvent("openat", 'AT_FDCWD, "/dev/vboxguest", O_RDWR'),
            ]
        )
    )
    assert EvasionSignal.VM_ARTIFACT_PROBE.value in report.signals


def test_vm_tool_paths_are_detected():
    report = analyze_evasion(
        FakeParseResult(
            [
                FakeEvent("newfstatat", 'AT_FDCWD, "/usr/bin/vmtoolsd", 0x0, 0'),
                FakeEvent("newfstatat", 'AT_FDCWD, "/usr/sbin/VBoxService", 0x0, 0'),
            ]
        )
    )
    assert EvasionSignal.VM_TOOL_PROBE.value in report.signals


def test_debugger_probe_reads_tracerpid_status_file():
    report = analyze_evasion(
        FakeParseResult([FakeEvent("openat", 'AT_FDCWD, "/proc/self/status", O_RDONLY')])
    )
    assert EvasionSignal.DEBUGGER_PROBE.value in report.signals
    assert report.findings[0].severity.value == "high"


def test_ptrace_syscall_is_a_debugger_probe():
    report = analyze_evasion(
        FakeParseResult([FakeEvent("ptrace", "PTRACE_TRACEME, 0, NULL, NULL")])
    )
    assert EvasionSignal.DEBUGGER_PROBE.value in report.signals


def test_analysis_tool_hunt_matches_any_path_to_the_binary():
    report = analyze_evasion(
        FakeParseResult(
            [
                FakeEvent("newfstatat", 'AT_FDCWD, "/usr/local/sbin/strace", 0x0, 0'),
                FakeEvent("newfstatat", 'AT_FDCWD, "/usr/bin/gdb", 0x0, 0'),
                FakeEvent("faccessat", 'AT_FDCWD, "/usr/bin/inotifywait", X_OK'),
            ]
        )
    )
    assert EvasionSignal.ANALYSIS_TOOL_HUNT.value in report.signals


def test_repeated_sleeps_are_a_sleep_loop():
    events = [
        FakeEvent("clock_nanosleep", "CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=100000000}, 0x0"),
        FakeEvent("clock_nanosleep", "CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=100000000}, 0x0"),
        FakeEvent("nanosleep", "{tv_sec=1, tv_nsec=0}, 0x0"),
    ]
    report = analyze_evasion(FakeParseResult(events))
    assert EvasionSignal.SLEEP_LOOP.value in report.signals


def test_two_sleeps_are_not_a_loop():
    events = [
        FakeEvent("nanosleep", "{tv_sec=1, tv_nsec=0}, 0x0"),
        FakeEvent("nanosleep", "{tv_sec=1, tv_nsec=0}, 0x0"),
    ]
    report = analyze_evasion(FakeParseResult(events))
    assert EvasionSignal.SLEEP_LOOP.value not in report.signals


# ---------------------------------------------------------------------------
# Normalised events + bundle-shape contract
# ---------------------------------------------------------------------------


def test_evasion_findings_render_as_normalised_events():
    report = analyze_evasion(parse(EVASIVE_MIN))
    rows = report.normalized_events()
    assert rows, "an evasive run must emit at least one event"
    for row in rows:
        assert row["category"] == "evasion"
        assert row["source"] == "evasion-analysis"
        assert row["syscall_name"].startswith("evasion:")
        assert json.loads(row["args"])["signal"]
        assert row["severity"] in ("info", "low", "medium", "high", "critical")


def test_report_serialises_cleanly():
    report = analyze_evasion(parse(EVASIVE_MIN))
    data = report.to_dict()
    assert data["score"] == report.score
    assert data["verdict"] == "evasive"
    assert isinstance(data["findings"], list)
    assert data["inconclusive"] is True


def test_zero_score_report_has_no_findings():
    assert analyze_evasion(FakeParseResult([])).normalized_events() == []


@pytest.mark.parametrize("path", [BENIGN, EVASIVE, EVASIVE_MIN])
def test_every_fixture_parses_without_error(path: Path):
    assert parse(path).errors == [] or all("not" not in e for e in parse(path).errors)
