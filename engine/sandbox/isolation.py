"""Isolation tier model — the honest boundary contract.

HATCHERY does not *have* an isolation level; the host does. This module
probes the host for the strongest isolation it can actually provide and
reports, per analysis, what boundary was in force and what it does **not**
protect against.

Tier model (strongest last):

  0 STATIC_ONLY       no execution at all
  1 SHARED_KERNEL     plain container (runc/crun) — NOT a security boundary
  2 SANDBOXED_KERNEL  gVisor (runsc) — user-space kernel, real boundary
  3 HARDWARE_VM       Firecracker / Cloud Hypervisor via Kata — CPU-enforced

Why this exists: a sandbox that silently runs malware in a shared-kernel
container while its README says "sandbox" is lying to its operator. A
sandbox that probes and reports "this run had no hardware boundary between
the sample and your workstation" is doing its job.

Empirical basis for the tier ordering (2026): a kernel 0-day run against a
container configured with seccomp on, unprivileged uid and a patched kernel
went from unprivileged user to root in under two seconds; the same exploit
run against a microVM configured *worse* (unpatched guest kernel, no seccomp,
running as root, full capabilities) succeeded inside the guest but never
reached the host. Whether the kernel is shared is the property that matters,
not which permissions the runtime withholds.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class IsolationTier(IntEnum):
    """Strength of the sample/host boundary, strongest last."""

    STATIC_ONLY = 0
    SHARED_KERNEL = 1
    SANDBOXED_KERNEL = 2
    HARDWARE_VM = 3


@dataclass(frozen=True)
class TierProfile:
    """What a given isolation tier actually guarantees."""

    tier: IsolationTier
    name: str
    boundary: str
    """One-line honest statement of the boundary in force."""
    is_security_boundary: bool
    """True only when a kernel exploit in the sample does not reach the host."""
    escape_barrier: str
    """What an attacker must defeat, in plain language."""
    host_requirements: str
    monitoring: str
    """How behavior is observed at this tier."""


TIER_PROFILES: dict[IsolationTier, TierProfile] = {
    IsolationTier.STATIC_ONLY: TierProfile(
        tier=IsolationTier.STATIC_ONLY,
        name="static-only",
        boundary="No execution. The sample is never run.",
        is_security_boundary=False,
        escape_barrier="n/a — nothing executes",
        host_requirements="none",
        monitoring="none (static analysis only)",
    ),
    IsolationTier.SHARED_KERNEL: TierProfile(
        tier=IsolationTier.SHARED_KERNEL,
        name="shared-kernel",
        boundary=(
            "The sample shares the host kernel. Namespaces, cgroups and seccomp "
            "narrow what it may ask for; they do not stop a kernel exploit."
        ),
        is_security_boundary=False,
        escape_barrier="a single kernel vulnerability reachable through an allowed syscall",
        host_requirements="any Docker-capable host",
        monitoring="strace (ptrace) — requires the seccomp profile to permit ptrace",
    ),
    IsolationTier.SANDBOXED_KERNEL: TierProfile(
        tier=IsolationTier.SANDBOXED_KERNEL,
        name="sandboxed-kernel",
        boundary=(
            "A user-space kernel answers the sample's syscalls, so sample code never "
            "reaches the host kernel directly."
        ),
        is_security_boundary=True,
        escape_barrier="a bug in the user-space kernel plus a usable host syscall",
        host_requirements="Linux host without KVM; runsc installed as a Docker runtime",
        monitoring="eBPF on the host, or the sandbox's own syscall log",
    ),
    IsolationTier.HARDWARE_VM: TierProfile(
        tier=IsolationTier.HARDWARE_VM,
        name="hardware-vm",
        boundary=(
            "The sample runs in its own virtual machine with its own guest kernel, "
            "enforced by CPU virtualisation."
        ),
        is_security_boundary=True,
        escape_barrier="escape the guest kernel, then KVM, then the device model",
        host_requirements="Linux host with /dev/kvm; Kata or Firecracker installed",
        monitoring="eBPF on the host, or the VMM's own observability surface",
    ),
}

# Docker runtime name -> isolation tier it provides.
RUNTIME_TIERS: dict[str, IsolationTier] = {
    "runc": IsolationTier.SHARED_KERNEL,
    "crun": IsolationTier.SHARED_KERNEL,
    "runsc": IsolationTier.SANDBOXED_KERNEL,
    "runsc-hatchery": IsolationTier.SANDBOXED_KERNEL,
    "gvisor": IsolationTier.SANDBOXED_KERNEL,
    "kata-runtime": IsolationTier.HARDWARE_VM,
    "kata-qemu": IsolationTier.HARDWARE_VM,
    "kata-clh": IsolationTier.HARDWARE_VM,
    "kata-fc": IsolationTier.HARDWARE_VM,
    "firecracker": IsolationTier.HARDWARE_VM,
}

# Preference order when several tiers are available: strongest wins, unless
# the caller asks explicitly.
TIER_PREFERENCE: list[str] = [
    "kata-fc", "kata-clh", "kata-qemu", "runsc-hatchery", "runsc", "crun", "runc",
]


# ---------------------------------------------------------------------------
# Per-tier monitoring strategy
# ---------------------------------------------------------------------------
#
# Isolation tells you what an attacker must defeat. It does *not* tell you how
# behaviour was observed, and the two are not the same question: ptrace-based
# tracing is visible to the sample and can be killed, whereas gVisor's own
# Sentry trace and host-side eBPF are not attached to the sample at all. A run
# must therefore name the collector that was actually used and what that
# collector cannot see.
#
# The empirical fact this is built on: `strace` cannot observe `RDTSC`, `CPUID`
# or a vDSO-served `clock_gettime`. The captured fixture
# `tests/fixtures/strace-evasive-real.log` ran `date +%s` in a loop and the log
# contains no clock syscall, because glibc resolved it in the vDSO. Timing and
# VM checks are therefore largely invisible to tier-1 collection.


@dataclass(frozen=True)
class MonitoringStrategy:
    """How behaviour is observed, and what that observation misses."""

    collector: str
    location: str
    """``guest`` (attached to the sample) or ``host`` (outside it)."""
    how: str
    blind_spots: tuple[str, ...]
    requires: str

    def to_dict(self) -> dict:
        return {
            "collector": self.collector,
            "location": self.location,
            "how": self.how,
            "blind_spots": list(self.blind_spots),
            "requires": self.requires,
        }


NO_COLLECTOR = MonitoringStrategy(
    collector="none",
    location="none",
    how="Nothing executes; there is no behaviour to observe.",
    blind_spots=("Everything: static analysis cannot observe behaviour.",),
    requires="none",
)

STRACE_COLLECTOR = MonitoringStrategy(
    collector="strace-ptrace",
    location="guest",
    how=(
        "strace -f -tt attached to the sample with ptrace; the seccomp profile "
        "must permit ptrace or the tracer cannot attach."
    ),
    blind_spots=(
        "RDTSC/RDTSCP and CPUID are CPU instructions, not syscalls, and never "
        "appear.",
        "clock_gettime/gettimeofday served by the vDSO are userspace calls and "
        "never appear; timing checks are therefore largely invisible.",
        "The tracer is detectable: /proc/self/status exposes TracerPid, and "
        "ptrace stops the process at every syscall.",
        "A sample can kill the tracer; 2026 eBPF rootkits SIGKILL processes that "
        "ptrace a protected PID.",
        "Anything the sample does before the tracer attaches is not observed.",
    ),
    requires="a seccomp profile that permits ptrace",
)

GVISOR_COLLECTOR = MonitoringStrategy(
    collector="gvisor-sentry-strace",
    location="host",
    how=(
        "gVisor's Sentry-level syscall trace, enabled per container with the "
        "dev.gvisor.flag.debug/strace/strace-log-size/debug-to-user-log OCI "
        "annotations. runsc writes one .boot.txt per sandbox to its host "
        "debug-log directory; the engine reads that file back and parses it "
        "(source='gvisor-sentry'). No global --strace and no ptrace attach."
    ),
    blind_spots=(
        "Syscalls gVisor does not implement are absent by construction.",
        "RDTSC/RDTSCP and CPUID are CPU instructions, not syscalls, and "
        "--strace does not emit them; the Sentry services them internally.",
        "The trace destination (--debug-log) is a host-side runtimeArg and is "
        "not annotation-overridable; the annotations only toggle the flags.",
        "The trace is container-wide: the entrypoint and monitors are in it. "
        "HATCHERY attributes events to the sample's process subtree before "
        "scoring and records how many were excluded.",
        "Docker's get_archive cannot see files written inside a gVisor "
        "container (the rootfs overlay is in-memory); in-guest artifacts are "
        "recovered copy-based through a named output volume instead.",
    ),
    requires="runsc registered as a Docker runtime with --debug-log; a readable debug-log directory",
)

EBPF_COLLECTOR = MonitoringStrategy(
    collector="ebpf-host",
    location="host",
    how=(
        "eBPF syscall collection on the host (Tetragon/Tracee/Falco or a "
        "bpftrace set) observing past the guest; guest strace only as a "
        "declared fallback."
    ),
    blind_spots=(
        "Requires a Linux host with BPF and BTF; unavailable on macOS and on "
        "this project's CI.",
        "Guest behaviour not surfaced through the host boundary may be "
        "invisible, depending on the collector's hooks.",
    ),
    requires="a Linux host with BPF/BTF and a collector installed",
)

# The collector each tier should use. The gap between this and what is wired
# is reported per run rather than hidden.
TIER_RECOMMENDED_COLLECTOR: dict[IsolationTier, MonitoringStrategy] = {
    IsolationTier.STATIC_ONLY: NO_COLLECTOR,
    IsolationTier.SHARED_KERNEL: STRACE_COLLECTOR,
    IsolationTier.SANDBOXED_KERNEL: GVISOR_COLLECTOR,
    IsolationTier.HARDWARE_VM: EBPF_COLLECTOR,
}


def recommended_collector(tier: IsolationTier) -> MonitoringStrategy:
    """Return the collector that *should* be used at this tier."""
    return TIER_RECOMMENDED_COLLECTOR[tier]


# Which guest-profile tells are structurally impossible to fix at each tier.
# The point is not to "look more real"; it is to say plainly which checks a
# sample can use to fingerprint the environment, so a sample that abandons
# execution is read as evasion rather than as a clean run.
TIER_GUEST_TELLS: dict[IsolationTier, str] = {
    IsolationTier.STATIC_ONLY: "n/a — nothing executes.",
    IsolationTier.SHARED_KERNEL: (
        "The host kernel version, CPU count, RAM, disk size and uptime are "
        "readable through /proc and cannot be faked, and CPUID reports the "
        "host. Modern loaders chain a dozen such checks and abandon execution "
        "at the first failure."
    ),
    IsolationTier.SANDBOXED_KERNEL: (
        "gVisor presents its own kernel and /proc rather than the host's, so "
        "host uptime and kernel version are no longer direct reads, but the "
        "sandbox is still identifiable (its kernel string is distinctive) and "
        "CPUID behaviour depends on the platform in use."
    ),
    IsolationTier.HARDWARE_VM: (
        "A real guest kernel is presented, but hypervisor presence remains "
        "visible through the CPUID hypervisor bit and vendor leaf, and through "
        "paravirtualised device names."
    ),
}


def resolve_collector(tier: IsolationTier) -> tuple[MonitoringStrategy, str]:
    """Return the collector actually usable today, plus a downgrade reason.

    ``strace-ptrace`` (tier 1) and the gVisor Sentry trace (tier 2) are both
    wired. Tier 3's recommended host-side eBPF is still not implemented, so a
    hardware-VM run falls back to ptrace and says so. The alternative —
    silently using the fallback while the report implies a stronger collector —
    is the exact dishonesty this project exists to avoid.
    """
    recommended = recommended_collector(tier)
    if recommended.collector in (
        NO_COLLECTOR.collector,
        STRACE_COLLECTOR.collector,
        GVISOR_COLLECTOR.collector,
    ):
        return recommended, ""
    return (
        STRACE_COLLECTOR,
        (
            f"tier {int(tier)} recommends {recommended.collector!r}, which is not "
            f"wired yet; this run fell back to {STRACE_COLLECTOR.collector!r}, "
            "which the sample can detect and can kill."
        ),
    )


@dataclass
class IsolationProbe:
    """Result of asking the host what isolation it can actually provide."""

    runtimes: dict[str, IsolationTier] = field(default_factory=dict)
    available: list[TierProfile] = field(default_factory=list)
    selected: Optional[TierProfile] = None
    runtime: Optional[str] = None
    errors: list[str] = field(default_factory=list)
    probed: bool = False

    @property
    def tier(self) -> IsolationTier:
        return self.selected.tier if self.selected else IsolationTier.STATIC_ONLY

    @property
    def is_security_boundary(self) -> bool:
        return bool(self.selected and self.selected.is_security_boundary)

    def to_dict(self) -> dict:
        return {
            "tier": int(self.tier),
            "tier_name": self.selected.name if self.selected else "static-only",
            "boundary": self.selected.boundary if self.selected else "No execution.",
            "is_security_boundary": self.is_security_boundary,
            "escape_barrier": self.selected.escape_barrier if self.selected else "",
            "runtime": self.runtime,
            "runtimes_seen": {k: int(v) for k, v in self.runtimes.items()},
            "errors": self.errors,
        }


def probe_isolation(
    client: Any = None,
    preferred_runtime: str | None = None,
) -> IsolationProbe:
    """Ask the host which isolation tiers it can provide.

    Args:
        client: A ``docker.DockerClient``. If None, one is created lazily.
        preferred_runtime: Force a specific Docker runtime name.

    Returns:
        An :class:`IsolationProbe` describing what is actually available.
        Never raises — absence of Docker is a legitimate, reportable answer.
    """
    probe = IsolationProbe(probed=True)

    if client is None:
        try:
            import docker as docker_sdk

            client = docker_sdk.from_env()
        except Exception as e:  # noqa: BLE001 - any failure means "no Docker"
            probe.errors.append(f"Docker unavailable: {e}")
            return probe

    try:
        info = client.info()
        runtimes = info.get("Runtimes") or {}
    except Exception as e:  # noqa: BLE001
        probe.errors.append(f"Could not read Docker runtimes: {e}")
        runtimes = {}

    for name in runtimes:
        tier = RUNTIME_TIERS.get(name)
        if tier is None:
            logger.debug("Unknown Docker runtime %r — ignoring for tier model", name)
            continue
        probe.runtimes[name] = tier

    if not probe.runtimes:
        probe.errors.append(
            "No known container runtime reported by the Docker daemon "
            "(expected at least 'runc')."
        )
        return probe

    # Resolve which runtime/tier to use.
    if preferred_runtime:
        if preferred_runtime not in probe.runtimes:
            probe.errors.append(
                f"Requested runtime {preferred_runtime!r} is not available on this host."
            )
        else:
            probe.runtime = preferred_runtime
    else:
        # Strongest available wins.
        best = max(probe.runtimes.values())
        for candidate in TIER_PREFERENCE:
            if probe.runtimes.get(candidate) == best:
                probe.runtime = candidate
                break

    if probe.runtime is None:
        # Fall back to the weakest-known runtime so a run can still happen.
        probe.runtime = "runc" if "runc" in probe.runtimes else next(iter(probe.runtimes))

    tier = probe.runtimes[probe.runtime]
    probe.selected = TIER_PROFILES[tier]

    # Make the weakest case impossible to miss in logs.
    if not probe.selected.is_security_boundary:
        logger.warning(
            "Isolation tier %d (%s): %s",
            int(tier),
            probe.selected.name,
            probe.selected.boundary,
        )

    return probe


def describe_tiers() -> str:
    """Render the tier table for CLI/README use."""
    lines = ["Isolation tiers HATCHERY will report:", ""]
    for tier in IsolationTier:
        profile = TIER_PROFILES[tier]
        mark = "BOUNDARY" if profile.is_security_boundary else "not a boundary"
        lines.append(f"  [{int(tier)}] {profile.name:<18} ({mark})")
        lines.append(f"      {profile.boundary}")
        lines.append(f"      host: {profile.host_requirements}")
    return "\n".join(lines)
