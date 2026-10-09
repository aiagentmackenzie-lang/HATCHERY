"""Emulation stage — Windows PE config extraction and dynamic capa.

This package drives **Mandiant Speakeasy** (pinned separately as the optional
``[emulation]`` extra) inside a container at the probed isolation tier. It is a
declared, containerized, fail-closed analysis stage — *not* an isolation
boundary (see ``docs/DECISIONS.md`` D21).

Hard rule for this package: **nothing here imports ``speakeasy`` at module
import time.** Parsing a captured report, building a config, selecting memory
snapshots and normalising events are all pure-Python and must stay runnable in
the pinned python-gate matrix, which never installs the beta emulator. Only the
container image and the optional host escape hatch touch ``speakeasy``, and only
inside a subprocess.
"""

from __future__ import annotations

__all__ = ["report", "config", "memory", "normalize", "runner"]
