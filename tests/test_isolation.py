"""Tests for the isolation tier model."""

from __future__ import annotations

from typing import Any

from engine.sandbox.isolation import (
    STRACE_COLLECTOR,
    TIER_GUEST_TELLS,
    TIER_PROFILES,
    TIER_RECOMMENDED_COLLECTOR,
    IsolationTier,
    describe_tiers,
    probe_isolation,
    recommended_collector,
    resolve_collector,
)


class FakeClient:
    """Minimal stand-in for docker.DockerClient."""

    def __init__(self, runtimes: dict[str, Any] | None = None) -> None:
        self._runtimes = runtimes if runtimes is not None else {"runc": {}}

    def info(self) -> dict:
        return {"Runtimes": self._runtimes}


def test_every_tier_has_a_profile():
    for tier in IsolationTier:
        assert tier in TIER_PROFILES


def test_only_sandboxed_kernel_and_hardware_vm_are_boundaries():
    assert not TIER_PROFILES[IsolationTier.STATIC_ONLY].is_security_boundary
    assert not TIER_PROFILES[IsolationTier.SHARED_KERNEL].is_security_boundary
    assert TIER_PROFILES[IsolationTier.SANDBOXED_KERNEL].is_security_boundary
    assert TIER_PROFILES[IsolationTier.HARDWARE_VM].is_security_boundary


def test_probe_prefers_strongest_available_tier():
    probe = probe_isolation(FakeClient({"runc": {}, "runsc": {}}))
    assert probe.tier == IsolationTier.SANDBOXED_KERNEL
    assert probe.runtime == "runsc"
    assert probe.is_security_boundary


def test_probe_prefers_microvm_over_gvisor():
    probe = probe_isolation(FakeClient({"runc": {}, "runsc": {}, "kata-fc": {}}))
    assert probe.tier == IsolationTier.HARDWARE_VM
    assert probe.runtime == "kata-fc"


def test_probe_reports_shared_kernel_as_not_a_boundary():
    probe = probe_isolation(FakeClient({"runc": {}}))
    assert probe.tier == IsolationTier.SHARED_KERNEL
    assert probe.is_security_boundary is False
    # The operator must be able to read why, from the probe alone.
    assert "shares the host kernel" in probe.selected.boundary


def test_probe_honors_explicit_runtime_request():
    probe = probe_isolation(FakeClient({"runc": {}, "runsc": {}}), preferred_runtime="runc")
    assert probe.runtime == "runc"
    assert probe.tier == IsolationTier.SHARED_KERNEL


def test_probe_records_error_when_requested_runtime_is_missing():
    probe = probe_isolation(FakeClient({"runc": {}}), preferred_runtime="runsc")
    assert any("runsc" in e for e in probe.errors)
    # Still reports something usable rather than leaving the caller with nothing.
    assert probe.runtime == "runc"


def test_probe_ignores_unknown_runtimes():
    probe = probe_isolation(FakeClient({"runc": {}, "some-custom-runtime": {}}))
    assert "some-custom-runtime" not in probe.runtimes
    assert probe.runtime == "runc"


def test_probe_without_any_known_runtime_reports_static_only():
    probe = probe_isolation(FakeClient({}))
    assert probe.tier == IsolationTier.STATIC_ONLY
    assert probe.errors


def test_probe_with_broken_client_never_raises():
    class Broken:
        def info(self) -> dict:
            raise RuntimeError("daemon exploded")

    probe = probe_isolation(Broken())
    assert probe.tier == IsolationTier.STATIC_ONLY
    assert any("daemon exploded" in e for e in probe.errors)


def test_probe_serializes_the_honest_claim():
    probe = probe_isolation(FakeClient({"runc": {}}))
    data = probe.to_dict()
    assert data["is_security_boundary"] is False
    assert data["tier"] == 1
    assert data["boundary"]


def test_describe_tiers_mentions_every_tier():
    text = describe_tiers()
    for tier in IsolationTier:
        assert TIER_PROFILES[tier].name in text


# ---------------------------------------------------------------------------
# Monitoring strategy
# ---------------------------------------------------------------------------


def test_every_tier_has_a_recommended_collector_and_guest_tells():
    for tier in IsolationTier:
        assert tier in TIER_RECOMMENDED_COLLECTOR
        assert tier in TIER_GUEST_TELLS
        assert TIER_GUEST_TELLS[tier]


def test_tier_one_uses_strace_with_no_downgrade():
    collector, downgrade = resolve_collector(IsolationTier.SHARED_KERNEL)
    assert collector.collector == "strace-ptrace"
    assert downgrade == ""


def test_tier_two_uses_the_wired_gvisor_sentry_trace():
    """Tier 2's Sentry trace is wired, so the run must name it with no
    downgrade — the collector is no longer the detectable ptrace tracer."""
    collector, downgrade = resolve_collector(IsolationTier.SANDBOXED_KERNEL)
    assert collector.collector == "gvisor-sentry-strace"
    assert collector.location == "host"
    assert downgrade == ""


def test_tier_three_still_declares_its_collector_downgrade():
    """Host-side eBPF is not wired yet, so a hardware-VM run must say it fell
    back to a detectable tracer rather than implying otherwise."""
    collector, downgrade = resolve_collector(IsolationTier.HARDWARE_VM)
    assert collector.collector == "strace-ptrace"
    assert recommended_collector(IsolationTier.HARDWARE_VM).collector == "ebpf-host"
    assert "fell back" in downgrade


def test_gvisor_collector_declares_what_it_cannot_see():
    blind = " ".join(recommended_collector(IsolationTier.SANDBOXED_KERNEL).blind_spots)
    assert "RDTSC" in blind and "CPUID" in blind
    assert "get_archive" in blind


def test_strace_collector_declares_the_cpuid_and_vdso_blind_spots():
    blind = " ".join(STRACE_COLLECTOR.blind_spots)
    assert "RDTSC" in blind
    assert "CPUID" in blind
    assert "vDSO" in blind or "vDSO" in blind
    assert "TracerPid" in blind


def test_guest_tells_are_per_tier_and_honest_at_tier_one():
    assert "cannot be faked" in TIER_GUEST_TELLS[IsolationTier.SHARED_KERNEL]
    assert "hypervisor" in TIER_GUEST_TELLS[IsolationTier.HARDWARE_VM].lower()


def test_sandboxed_kernel_recommends_gvisor_not_ptrace():
    assert recommended_collector(IsolationTier.SANDBOXED_KERNEL).collector == (
        "gvisor-sentry-strace"
    )
    assert recommended_collector(IsolationTier.HARDWARE_VM).collector == "ebpf-host"
