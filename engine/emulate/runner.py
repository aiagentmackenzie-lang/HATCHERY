"""Build the Speakeasy invocation and assemble the emulation bundle section.

This module is pure orchestration: it builds the emulator configuration and
command line, then turns a parsed report into HATCHERY's ``emulation`` section
plus its separate event stream. It never imports ``speakeasy`` — only the
container entrypoint and the optional host escape hatch do, and only in a
subprocess.

The caps that matter are set here as *data* so they can be asserted by a test
rather than living only as flags in an image:

* ``timeout`` — Speakeasy's own emulated-run timeout (seconds).
* ``max_api_count`` — stop after this many emulated API calls (API-hammering and
  runaway loops).
* ``max_instructions`` — stop after this many emulated instructions.
* the container wall-clock — the outer deadline, enforced by the manager.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from engine.emulate import config as config_extract
from engine.emulate import memory as memory_analysis
from engine.emulate.normalize import normalize_emulation_events
from engine.emulate.report import (
    EMULATOR_NAME,
    EMULATOR_VERSION,
    parse_report,
)

logger = logging.getLogger(__name__)

# Container paths, fixed and mirrored by engine/emulate/docker/entrypoint.sh.
SAMPLE_CONTAINER_DIR = "/hatchery/sample"
CONFIG_CONTAINER_PATH = "/hatchery/emu-config.json"
OUTPUT_CONTAINER_DIR = "/hatchery/output"
REPORT_CONTAINER_PATH = f"{OUTPUT_CONTAINER_DIR}/report.json"

EMULATION_IMAGE = "hatchery-emulation:latest"
EMULATION_EVENTS_FILENAME = "emulation-events.jsonl"

DEFAULT_EMULATE_TIMEOUT = 60
DEFAULT_MAX_API_COUNT = 10000
DEFAULT_MAX_INSTRUCTIONS = -1


def speakeasy_config(
    timeout: int = DEFAULT_EMULATE_TIMEOUT,
    max_api_count: int = DEFAULT_MAX_API_COUNT,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    snapshot_memory_regions: bool = True,
) -> dict:
    """Build the (partial) Speakeasy config merged over its defaults.

    Speakeasy deep-merges this over its built-in default profile, so only the
    fields HATCHERY controls are set. ``max_api_count`` is the emulated-step
    cap; ``max_instructions`` a hard instruction cap.
    """
    return {
        "timeout": float(timeout),
        "max_api_count": int(max_api_count),
        "max_instructions": int(max_instructions),
        "snapshot_memory_regions": bool(snapshot_memory_regions),
        "analysis": {"strings": True},
    }


def speakeasy_args(
    sample_container_path: str,
    report_container_path: str = REPORT_CONTAINER_PATH,
    config_container_path: str = CONFIG_CONTAINER_PATH,
    raw: bool = False,
    arch: Optional[str] = None,
    emulate_children: bool = False,
) -> list[str]:
    """Build the argument list for ``speakeasy`` inside the emulation image.

    Args are passed as an argv list (never interpolated into a shell string), so
    a hostile sample filename cannot become a command.
    """
    args = [
        "-t", sample_container_path,
        "-o", report_container_path,
        "-c", config_container_path,
        "--no-mp",
    ]
    if raw:
        args += ["--raw"]
        args += ["--arch", arch or "x86"]
    if emulate_children:
        args += ["--emulate-children"]
    return args


def analyze(
    raw_report: Any,
    run_capa: bool = True,
    yara_scanner: Optional[object] = None,
    capa_scanner: Optional[object] = None,
) -> tuple[dict, list[dict]]:
    """Turn a raw report into ``(emulation_section, emulation_events)``.

    The section is JSON-serialisable and lands in the bundle as a top-level
    ``emulation`` key. The events are a separate stream — never merged into the
    native ``events.jsonl`` (D4).
    """
    report = parse_report(raw_report)
    config = config_extract.extract_config(report)
    snapshots = memory_analysis.analyze_snapshots(
        report, capa_scanner=capa_scanner, yara_scanner=yara_scanner, run_capa=run_capa
    )
    events = normalize_emulation_events(report)
    iocs = config_extract.extract_iocs(config)

    section = report.to_dict()
    flags = ["emulation"]
    if (
        config.get("network_endpoints")
        or config.get("registry")
        or config.get("mutexes")
        or config.get("user_agents")
        or config.get("dropped_files")
    ):
        flags.append("emulation-config")
    if config.get("network_endpoints"):
        flags.append("emulation-network")
    if config.get("dropped_files"):
        flags.append("emulation-dropped-file")
    if report.unsupported_apis:
        flags.append("emulation-api-missing")
    if not report.has_events:
        flags.append("emulation-empty")
    section.update(
        {
            "available": True,
            "status": "completed",
            "flags": flags,
            "config": config,
            "snapshots": snapshots,
            "capa_dynamic": snapshots.get("capa_dynamic"),
            "yara_dynamic": snapshots.get("yara_dynamic"),
            "iocs": iocs,
            "events_written": len(events),
        }
    )
    # The section carries the emulator identity at the top for the summary and
    # report; report.to_dict already adds it, so keep both consistent.
    section["emulator"] = EMULATOR_NAME
    section["emulator_version"] = EMULATOR_VERSION
    return section, events


def unavailable_section(reason: str) -> dict:
    """A declared 'emulation was not run' section.

    Used at tier 0, when the image is missing, or when the operator has not
    opted in. Never rendered as an empty-but-clean result.
    """
    return {
        "available": False,
        "status": "unavailable",
        "reason": reason,
        "flags": ["emulation-unavailable"],
        "emulator": EMULATOR_NAME,
        "emulator_version": EMULATOR_VERSION,
        "config": {},
        "snapshots": {"regions_total": 0, "regions_selected": 0, "regions_decoded": 0},
        "capa_dynamic": {"is_available": False, "capabilities": []},
        "yara_dynamic": {"matches": []},
        "iocs": [],
        "events_written": 0,
    }
