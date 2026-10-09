"""Sample-subtree trace attribution tests — D17.

The gVisor Sentry trace is container-wide: the entrypoint, ``strace``,
``inotifywait``, ``tcpdump`` and ``find`` all appear. These tests pin that the
sample's events are kept and the instrumentation's are excluded, using a real
tier-2 capture trimmed from a live run (``gvisor-strace-sample-real.log``).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from engine.monitor.attribution import (
    attribute_to_sample,
    build_subtree,
    find_sample_root,
)
from engine.monitor.gvisor_strace import GvisorStraceParser

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_FIXTURE = FIXTURES / "gvisor-strace-sample-real.log"
CONTAINER_WIDE_FIXTURE = FIXTURES / "gvisor-strace-real.log"


def event(syscall, args="", pid=1, ret="0", comm=""):
    return SimpleNamespace(
        timestamp="12:00:00.000001",
        pid=pid,
        syscall=syscall,
        args=args,
        return_value=ret,
        comm=comm,
        paths=[],
    )


def parsed_sample():
    return GvisorStraceParser().parse_file(SAMPLE_FIXTURE)


# ---------------------------------------------------------------------------
# Real capture
# ---------------------------------------------------------------------------


def test_real_fixture_attributes_to_the_sample_subtree():
    parsed = parsed_sample()
    included, attribution = attribute_to_sample(parsed.events, sample_name="recon.sh")

    assert attribution.attributed is True
    assert attribution.sample_root_pid == 43
    assert attribution.root_target == "/hatchery/sample/recon.sh"
    assert attribution.included > 0
    assert attribution.excluded > 0
    assert attribution.included == len(included)
    assert 0 < attribution.included < len(parsed.events)


def test_monitor_events_are_excluded_and_sample_events_kept():
    parsed = parsed_sample()
    included, _ = attribute_to_sample(parsed.events, sample_name="recon.sh")

    comms = {getattr(e, "comm", "") for e in included}
    assert "recon.sh" in comms
    # The entrypoint and the filesystem-snapshot noise must not survive.
    assert "entrypoint.sh" not in comms
    assert "find" not in comms
    assert all(e.pid == 43 for e in included)


def test_monitor_execve_argv_is_not_mistaken_for_the_root():
    """PIDs 39/40 exec timeout/strace with the sample path in their *argv*.
    Only the exec whose target is the sample (PID 43) is the root."""
    parsed = parsed_sample()
    root, target = find_sample_root(parsed.events, sample_name="recon.sh")
    assert root == 43
    assert target == "/hatchery/sample/recon.sh"


def test_attribution_record_is_json_shaped():
    parsed = parsed_sample()
    _, attribution = attribute_to_sample(parsed.events, sample_name="recon.sh")
    data = attribution.to_dict()
    assert set(data) == {
        "sample_root_pid",
        "root_target",
        "included",
        "excluded",
        "attributed",
        "included_pids",
        "reason",
    }
    assert data["included_pids"] == [43]
    assert "excluded" in data["reason"]


def test_container_wide_trace_without_sample_root_keeps_everything():
    """When the root cannot be found, nothing is silently dropped and the
    reason says so."""
    parsed = GvisorStraceParser().parse_file(CONTAINER_WIDE_FIXTURE)
    included, attribution = attribute_to_sample(parsed.events, sample_name="probe.sh")

    assert attribution.attributed is False
    assert attribution.sample_root_pid is None
    assert attribution.excluded == 0
    assert attribution.included == len(parsed.events)
    assert included == parsed.events
    assert "no events were excluded" in attribution.reason


# ---------------------------------------------------------------------------
# Synthetic process tree
# ---------------------------------------------------------------------------


def test_clone_children_are_followed_to_a_fixpoint():
    events = [
        event("execve", '"/hatchery/sample/evil", ["evil"], 0x0', pid=10),
        event("clone", "CLONE_CHILD_CLEARTID|0x11", pid=10, ret="11 (0xb)"),
        event("clone", "CLONE_CHILD_CLEARTID|0x11", pid=11, ret="12 (0xc)"),
        # an unrelated monitor process
        event("openat", 'AT_FDCWD, "/etc/profile", O_RDONLY', pid=1),
    ]
    assert build_subtree(events, 10) == {10, 11, 12}

    included, attribution = attribute_to_sample(events, sample_name="evil")
    assert attribution.included_pids == [10, 11, 12]
    assert attribution.included == 3
    assert attribution.excluded == 1
    # PID 12 has no events of its own in this synthetic trace, but it is in the
    # subtree; the three included events belong to PIDs 10 and 11.
    assert {e.pid for e in included} == {10, 11}


def test_no_execve_root_means_full_trace_is_returned():
    events = [event("openat", 'AT_FDCWD, "/proc/cpuinfo", O_RDONLY', pid=7)]
    included, attribution = attribute_to_sample(events)
    assert included == events
    assert attribution.attributed is False
    assert attribution.included == 1
    assert attribution.excluded == 0
