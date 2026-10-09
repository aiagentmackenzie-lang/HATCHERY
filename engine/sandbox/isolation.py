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
    "gvisor": IsolationTier.SANDBOXED_KERNEL,
    "kata-runtime": IsolationTier.HARDWARE_VM,
    "kata-qemu": IsolationTier.HARDWARE_VM,
    "kata-clh": IsolationTier.HARDWARE_VM,
    "kata-fc": IsolationTier.HARDWARE_VM,
    "firecracker": IsolationTier.HARDWARE_VM,
}

# Preference order when several tiers are available: strongest wins, unless
# the caller asks explicitly.
TIER_PREFERENCE: list[str] = ["kata-fc", "kata-clh", "kata-qemu", "runsc", "crun", "runc"]


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
