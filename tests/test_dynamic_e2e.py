"""End-to-end detonation test.

Opt-in, because it builds nothing but does start a container and takes a few
seconds. Enable with:

    HATCHERY_E2E=1 pytest tests/test_dynamic_e2e.py -v

It is skipped otherwise so the fast unit suite stays fast and portable.

What it proves: a sample really is executed, syscalls really are captured,
filesystem events really are recorded, artifacts really are recovered, and the
bundle really describes what happened. Every one of those steps was broken in
the revision this test was written against, and none of them was covered by a
test.

The suite is tier-aware. At tier 1 the collector is in-guest ``strace`` and its
filesystem/network artifacts are copied out. At tier 2 the collector is the
gVisor Sentry trace and Docker's ``get_archive`` cannot see files written
inside a gVisor container (the rootfs overlay is in-memory), so the artifact
tests skip there and the syscall tests read the Sentry trace instead.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from engine.bundle import ANALYSIS_FILENAME, EVENTS_FILENAME
from engine.sandbox.container import ContainerConfig, ContainerManager
from engine.sandbox.isolation import IsolationTier

pytestmark = pytest.mark.skipif(
    os.environ.get("HATCHERY_E2E") != "1",
    reason="set HATCHERY_E2E=1 to run the container-based detonation test",
)

SAMPLE_SCRIPT = """#!/bin/sh
# Benign behavioral probe. Writes files, reads /etc/passwd, attempts DNS.
echo probe > /tmp/hatchery-e2e-write.txt
cat /etc/passwd > /tmp/hatchery-e2e-read.txt
mkdir -p /dev/shm/hatchery-e2e
echo marker > /dev/shm/hatchery-e2e/marker
getent hosts example.com > /tmp/hatchery-e2e-dns.txt 2>&1 || true
sleep 1
"""


@pytest.fixture(scope="module")
def manager() -> ContainerManager:
    mgr = ContainerManager(ContainerConfig(timeout=30))
    ready, problems = mgr.readiness()
    if not ready:
        pytest.skip("sandbox not ready: " + "; ".join(problems))
    return mgr


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("sample") / "probe.sh"
    path.write_text(SAMPLE_SCRIPT)
    path.chmod(0o755)
    return path


@pytest.fixture(scope="module")
def detonation(manager: ContainerManager, sample: Path, tmp_path_factory):
    run_dir = tmp_path_factory.mktemp("run")
    result = manager.execute(sample, run_dir)
    return result, run_dir


def _tier(result) -> IsolationTier:
    return IsolationTier(int(result.isolation["tier"]))


def _parsed_syscalls(result):
    """Parse whichever collector this run actually used."""
    from engine.monitor.gvisor_strace import GvisorStraceParser
    from engine.monitor.strace_parser import StraceParser

    if result.gvisor_trace_log:
        return GvisorStraceParser().parse_file(result.gvisor_trace_log)
    if result.strace_log:
        return StraceParser().parse_file(Path(result.strace_log))
    return None


def test_container_completes_without_a_sandbox_error(detonation):
    result, _ = detonation
    assert result.status == "completed", result.error
    assert result.error is None


def test_exit_code_is_the_samples_own_exit_code(detonation):
    """The entrypoint used to report 0 for everything because of a
    `timeout ... || true; EXIT_CODE=$?` sequence."""
    result, _ = detonation
    assert result.exit_code == 0


def test_a_syscall_trace_was_recovered_and_is_not_empty(detonation):
    result, _ = detonation
    parsed = _parsed_syscalls(result)
    assert parsed is not None
    assert parsed.parsed_events > 0
    if _tier(result) == IsolationTier.SANDBOXED_KERNEL:
        assert result.gvisor_trace_log is not None
        assert result.gvisor_trace_log.stat().st_size > 0
    else:
        assert result.artifacts is not None
        assert result.artifacts.strace_log is not None
        assert result.artifacts.strace_log.stat().st_size > 0


def test_syscall_trace_contains_real_activity(detonation):
    result, _ = detonation
    parsed = _parsed_syscalls(result)
    assert any(e.syscall == "execve" for e in parsed.events)
    assert any(
        any("/etc/passwd" in p for p in getattr(e, "paths", []) or [])
        or "/etc/passwd" in e.args
        for e in parsed.events
    )


def test_filesystem_events_were_recorded(detonation):
    result, _ = detonation
    if _tier(result) == IsolationTier.SANDBOXED_KERNEL:
        pytest.skip("in-guest inotify log is not recoverable under gVisor")
    assert result.artifacts.inotify_log is not None
    text = result.artifacts.inotify_log.read_text(errors="replace")
    assert "hatchery-e2e-write.txt" in text


def test_dropped_files_are_the_samples_files_and_nothing_else(detonation):
    """The filesystem diff used to include HATCHERY's own output directory, so
    every artifact the sandbox wrote was reported as a file the sample dropped."""
    result, _ = detonation
    if _tier(result) == IsolationTier.SANDBOXED_KERNEL:
        pytest.skip("in-guest dropped-file recovery is not possible under gVisor")
    names = {p.name for p in result.artifacts.dropped_files}
    assert any("hatchery-e2e-write.txt" in n for n in names)
    assert not any("_hatchery_output" in n for n in names)


def test_isolation_tier_is_reported_on_the_result(detonation):
    result, _ = detonation
    assert result.isolation is not None
    assert "boundary" in result.isolation
    assert isinstance(result.isolation["is_security_boundary"], bool)


def test_bundle_is_written_and_describes_the_run(manager, sample, tmp_path):
    from engine.bundle import AnalysisBundle, normalize_events, write_bundle

    run_dir = tmp_path / "bundle-run"
    result = manager.execute(sample, run_dir / "sandbox")
    assert result.status == "completed", result.error

    parsed = _parsed_syscalls(result)
    assert parsed is not None
    if result.gvisor_trace_log:
        events = normalize_events(gvisor_result=parsed)
    else:
        events = normalize_events(strace_result=parsed)

    bundle = AnalysisBundle(
        task_id="e2e",
        sandbox=result.to_dict(),
        events=events,
        limitations=["placeholder"],
    )
    write_bundle(run_dir / "bundle", bundle)

    analysis = json.loads((run_dir / "bundle" / ANALYSIS_FILENAME).read_text())
    assert analysis["task_id"] == "e2e"
    assert analysis["summary"]["dynamic_analysis_performed"] is True
    assert analysis["summary"]["events_total"] > 0

    lines = (run_dir / "bundle" / EVENTS_FILENAME).read_text().strip().splitlines()
    assert len(lines) == analysis["summary"]["events_total"]
    assert all(json.loads(line)["source"] for line in lines)


def test_tier_one_run_is_labeled_as_having_no_boundary(detonation):
    """Whatever tier this host supports, the bundle must not imply a boundary
    that is not there."""
    result, _ = detonation
    tier = _tier(result)
    if tier in (IsolationTier.STATIC_ONLY, IsolationTier.SHARED_KERNEL):
        assert result.isolation["is_security_boundary"] is False
        assert "shares the host kernel" in result.isolation["boundary"]


def test_monitoring_collector_and_blind_spots_are_reported(detonation):
    """Every run must name how behaviour was observed and what it could not see."""
    result, _ = detonation
    assert result.monitoring is not None
    assert result.monitoring["collector"]
    assert result.monitoring["location"] in ("guest", "host", "none")
    assert result.monitoring["blind_spots"]


RECON_SCRIPT = """#!/bin/sh
# Event-thin recon-then-quiet probe. Builtins only, no external processes.
read x < /proc/cpuinfo
read x < /proc/uptime
read x < /proc/self/status
[ -r /sys/class/dmi/id/product_name ]
[ -r /sys/hypervisor/type ]
[ -x /usr/bin/strace ]
[ -x /usr/bin/gdb ]
[ -x /usr/bin/ltrace ]
exit 0
"""


def test_recon_then_quiet_detonation_is_evasive_and_inconclusive(manager, tmp_path):
    """The whole pipeline: a sample that reconnoiters and exits quietly is
    reported evasive/inconclusive from whichever collector this tier uses."""
    from engine.monitor.evasion import analyze_evasion

    sample = tmp_path / "recon.sh"
    sample.write_text(RECON_SCRIPT)
    sample.chmod(0o755)
    result = manager.execute(sample, tmp_path / "run")
    assert result.status == "completed", result.error

    parsed = _parsed_syscalls(result)
    assert parsed is not None
    report = analyze_evasion(parsed)
    assert report.verdict == "evasive", report.to_dict()
    assert report.inconclusive is True


def test_tier_two_uses_the_gvisor_sentry_trace(manager, tmp_path):
    """Opt-in tier-2 proof: when runsc is the runtime, the gVisor Sentry trace
    is the collector and evasion is scored from its events. Skipped on a
    tier-1 host (including CI, which has no runsc)."""
    from engine.monitor.evasion import analyze_evasion
    from engine.monitor.gvisor_strace import GvisorStraceParser

    if manager.isolation.tier != IsolationTier.SANDBOXED_KERNEL:
        pytest.skip("host is not running a tier-2 (gVisor) runtime")

    sample = tmp_path / "recon-min.sh"
    sample.write_text(RECON_SCRIPT)
    sample.chmod(0o755)
    result = manager.execute(sample, tmp_path / "tier2-run")
    assert result.status == "completed", result.error
    assert result.monitoring is not None
    assert result.monitoring["collector"] == "gvisor-sentry-strace"
    assert result.gvisor_trace_log is not None
    assert result.gvisor_trace_log.stat().st_size > 0

    parsed = GvisorStraceParser().parse_file(result.gvisor_trace_log)
    assert parsed.parsed_events > 0
    report = analyze_evasion(parsed)
    assert report.verdict == "evasive", report.to_dict()
    assert report.inconclusive is True
