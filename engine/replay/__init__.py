"""Deterministic replay — re-analyse a run and defend (or fail) the result (D26).

A sandbox result is only worth something if someone can re-run it. ``hatchery
replay <run_dir>`` re-analyses the same sample under the settings the original
bundle recorded, then compares the two runs:

* **Deterministic** signals — hashes, file type, delivery format and extracted
  child hashes, the YARA rule-name set, the capa capability set, the ATT&CK
  technique-id set and the static IOC set — must be identical or the replay is a
  loud ``static-mismatch``.
* **Volatile** signals — dynamic event counts, durations, collected-IOC order,
  evasion score, emulation counters — are reported as drift, never as failure.
  Sandboxes and emulators are not bit-for-bit reproducible, and a replay tool
  that pretends otherwise is lying.
* **Unknown** signals — anything the replay could not re-establish (a bundle
  older than the stage that produced a signal) — force an ``inconclusive``
  verdict rather than a silent pass.

The replay re-uses the existing ``hatchery submit`` pipeline (one producer, D4):
it locates the sample, shells out to submit with the reproduced settings, and
compares the resulting bundle. It never re-implements analysis.
"""

from __future__ import annotations

from engine.replay.compare import (
    Comparison,
    ReplaySettings,
    SettingsComparison,
    compare_settings,
    compare_signals,
    settings_from_bundle,
)
from engine.replay.replay import (
    ReplayError,
    ReplayResult,
    attach_replay,
    build_submit_command,
    default_output_dir,
    locate_sample,
    resolve_run_dir,
    run_replay,
    write_replay,
)
from engine.replay.signals import (
    DETERMINISTIC_KINDS,
    VOLATILE_KINDS,
    Signals,
    extract_signals,
)

__all__ = [
    "DETERMINISTIC_KINDS",
    "VOLATILE_KINDS",
    "Comparison",
    "ReplayError",
    "ReplayResult",
    "ReplaySettings",
    "SettingsComparison",
    "Signals",
    "attach_replay",
    "compare_settings",
    "compare_signals",
    "build_submit_command",
    "default_output_dir",
    "extract_signals",
    "locate_sample",
    "resolve_run_dir",
    "run_replay",
    "settings_from_bundle",
    "write_replay",
]
