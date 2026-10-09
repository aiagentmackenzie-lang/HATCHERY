"""Parse a Speakeasy JSON report into a stable, inspectable shape.

Everything downstream — configuration extraction, event normalisation and
capa-on-snapshots — reads this module's :class:`EmulationReport`. There is
exactly one parser, so a beta bump to Speakeasy is visible in one place.

This module deliberately does **not** import ``speakeasy``: a captured report is
just JSON, and the pinned python-gate matrix must be able to parse one without
the beta extra installed (the ``emulation`` extra is opt-in; see D21).

Speakeasy's report format is versioned (``report_version``), but its beta series
has already changed shape once. Rather than trusting a version string, the
parser is tolerant by field and records a **schema hash** — a hash over the
report version, the top-level keys and the set of event discriminators — so a
change in the emulator's output is visible per run instead of silent.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import zlib
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# The pinned emulator. Kept here (not imported) so the report records the exact
# version the engine expects; a test asserts it matches pyproject's pin.
EMULATOR_NAME = "speakeasy-emulator"
EMULATOR_VERSION = "2.0.0b6"

# Event discriminators that carry an endpoint/registry/file fact we extract.
NETWORK_EVENTS = ("net_dns", "net_http", "net_traffic")
REGISTRY_EVENTS = (
    "reg_open_key",
    "reg_create_key",
    "reg_read_value",
    "reg_write_value",
    "reg_list_subkeys",
)
FILE_EVENTS = ("file_create", "file_open", "file_read", "file_write")
PROCESS_EVENTS = ("process_create", "thread_create", "thread_inject", "module_load")
MEMORY_EVENTS = ("mem_alloc", "mem_write", "mem_read", "mem_protect", "mem_free")


def _to_int(value: Any) -> Optional[int]:
    """Parse an int that Speakeasy may serialise as ``0x``-prefixed hex."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        return int(text, 0)
    except (TypeError, ValueError):
        return None


@dataclass
class MemoryRegion:
    """One captured memory region in the run-end layout."""

    tag: str
    address: int
    size: int
    prot: str
    data_ref: str = ""
    is_free: bool = False
    accesses: Optional[dict] = None

    @property
    def is_executable(self) -> bool:
        return "x" in (self.prot or "")

    @property
    def is_dynamic(self) -> bool:
        return "dynamic" in self.tag

    @property
    def looks_like_pe(self) -> bool:
        return False  # decided from decoded bytes, not metadata

    def to_dict(self) -> dict:
        return {
            "tag": self.tag,
            "address": hex(self.address),
            "size": self.size,
            "prot": self.prot,
            "data_ref": self.data_ref,
            "is_free": self.is_free,
            "accesses": self.accesses,
        }


@dataclass
class EmulationReport:
    """A parsed Speakeasy report, with the facts the rest of HATCHERY needs."""

    report_version: str = ""
    schema_hash: str = ""
    arch: str = ""
    filetype: str = ""
    sha256: str = ""
    size: int = 0
    image_base: Optional[int] = None
    runtime_seconds: float = 0.0
    timestamp: int = 0
    entry_point_count: int = 0
    events: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    memory_regions: list[MemoryRegion] = field(default_factory=list)
    dynamic_segments: list[dict] = field(default_factory=list)
    dropped_files: list[dict] = field(default_factory=list)
    data_store: dict[str, dict] = field(default_factory=dict)
    strings: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ facts

    @property
    def api_names(self) -> list[str]:
        return [
            str(ev.get("api_name"))
            for ev in self.events
            if ev.get("event") == "api" and ev.get("api_name")
        ]

    @property
    def api_call_count(self) -> int:
        return sum(1 for ev in self.events if ev.get("event") == "api")

    @property
    def unsupported_apis(self) -> list[str]:
        """APIs the emulator has no handler for (the real negative signal)."""
        names: list[str] = []
        for error in self.errors:
            if str(error.get("type", "")).startswith("unsupported"):
                if error.get("api_name"):
                    names.append(str(error["api_name"]))
        for entry in self.raw.get("entry_points") or []:
            error = entry.get("error") or {}
            if str(error.get("type", "")).startswith("unsupported") and error.get("api_name"):
                names.append(str(error["api_name"]))
        return sorted(set(names))

    @property
    def error_types(self) -> list[str]:
        types = [str(e.get("type", "")) for e in self.errors]
        for entry in self.raw.get("entry_points") or []:
            error = entry.get("error") or {}
            if error.get("type"):
                types.append(str(error["type"]))
        return sorted(set(t for t in types if t))

    @property
    def has_events(self) -> bool:
        return bool(self.events)

    @property
    def is_conclusive(self) -> bool:
        """False when the emulator could not finish on its own terms.

        An unimplemented API aborts the run cleanly *from the emulator's point
        of view* and a packer can exploit that, so it is INCONCLUSIVE, never
        clean. This is the D3 rule applied to the emulation collector.
        """
        return not self.unsupported_apis

    def to_dict(self) -> dict:
        return {
            "report_version": self.report_version,
            "schema_hash": self.schema_hash,
            "arch": self.arch,
            "filetype": self.filetype,
            "sha256": self.sha256,
            "size": self.size,
            "image_base": hex(self.image_base) if self.image_base is not None else None,
            "runtime_seconds": round(self.runtime_seconds, 3),
            "entry_points": self.entry_point_count,
            "api_calls": self.api_call_count,
            "events": len(self.events),
            "memory_regions": len(self.memory_regions),
            "dynamic_segments": len(self.dynamic_segments),
            "dropped_files": len(self.dropped_files),
            "errors": self.errors,
            "unsupported_apis": self.unsupported_apis,
            "conclusive": self.is_conclusive,
            "emulator": EMULATOR_NAME,
            "emulator_version": EMULATOR_VERSION,
        }


def report_schema_hash(raw: dict) -> str:
    """Hash the *shape* of a report, not its content.

    A beta emulator can rename a field or drop an event type between releases.
    Hashing the version, top-level keys and event discriminators makes that
    visible in the bundle for every run rather than only when a parser breaks.
    """
    event_types: set[str] = set()
    for entry in raw.get("entry_points") or []:
        for event in entry.get("events") or []:
            if isinstance(event, dict) and event.get("event"):
                event_types.add(str(event["event"]))
    shape = {
        "report_version": str(raw.get("report_version", "")),
        "top_level": sorted(str(k) for k in raw.keys()),
        "event_types": sorted(event_types),
    }
    canonical = json.dumps(shape, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_region(entry: dict) -> Optional[MemoryRegion]:
    address = _to_int(entry.get("address"))
    size = _to_int(entry.get("size"))
    if address is None or size is None:
        return None
    return MemoryRegion(
        tag=str(entry.get("tag", "")),
        address=address,
        size=size,
        prot=str(entry.get("prot", "")),
        data_ref=str(entry.get("data_ref") or ""),
        is_free=bool(entry.get("is_free", False)),
        accesses=entry.get("accesses"),
    )


def parse_report(source: Any) -> EmulationReport:
    """Parse a report from a dict, JSON string, or JSON bytes.

    Raises:
        ValueError: when the input is not a JSON object. A report that is not an
            object is not a Speakeasy report, and silently returning an empty
            one would let a crash read as a clean run.
    """
    if isinstance(source, (bytes, bytearray)):
        source = source.decode("utf-8", errors="replace")
    if isinstance(source, str):
        source = json.loads(source)
    if not isinstance(source, dict):
        raise ValueError(
            f"Emulation report must be a JSON object, got {type(source).__name__}"
        )

    report = EmulationReport(raw=source)
    report.report_version = str(source.get("report_version", ""))
    report.schema_hash = report_schema_hash(source)
    report.arch = str(source.get("arch") or "")
    report.filetype = str(source.get("filetype") or "")
    report.sha256 = str(source.get("sha256") or "")
    report.size = int(source.get("size") or 0)
    report.image_base = _to_int(source.get("image_base"))
    report.runtime_seconds = float(source.get("emulation_total_runtime") or 0.0)
    report.timestamp = int(source.get("timestamp") or 0)
    report.data_store = source.get("data") or {}
    report.strings = source.get("strings") or {}
    report.errors = list(source.get("errors") or [])

    entry_points = source.get("entry_points") or []
    report.entry_point_count = len(entry_points)

    for entry in entry_points:
        if not isinstance(entry, dict):
            continue
        for event in entry.get("events") or []:
            if isinstance(event, dict):
                report.events.append(event)
        for segment in entry.get("dynamic_code_segments") or []:
            if isinstance(segment, dict):
                report.dynamic_segments.append(segment)
        for dropped in entry.get("dropped_files") or []:
            if isinstance(dropped, dict):
                report.dropped_files.append(dropped)
        layout = (entry.get("memory") or {}).get("layout") or []
        for raw_region in layout:
            if not isinstance(raw_region, dict):
                continue
            region = _parse_region(raw_region)
            if region is not None:
                report.memory_regions.append(region)

    logger.info(
        "Parsed Speakeasy report v%s: %d entry point(s), %d event(s), "
        "%d memory region(s), schema %s",
        report.report_version,
        report.entry_point_count,
        len(report.events),
        len(report.memory_regions),
        report.schema_hash[:12],
    )
    return report


def decode_data_ref(data_store: dict, data_ref: str) -> Optional[bytes]:
    """Decode one deduplicated data-store entry to raw bytes.

    Speakeasy stores payloads as ``base64(zlib(bytes))`` keyed by SHA-256 (see
    ``mandiant/speakeasy``'s artifact store). A missing or malformed reference
    returns ``None`` rather than raising: a snapshot the emulator did not keep is
    a fact to report, not a crash.
    """
    if not data_ref:
        return None
    entry = (data_store or {}).get(data_ref)
    if not isinstance(entry, dict):
        return None
    try:
        payload = base64.b64decode(entry.get("data") or "", validate=False)
        compression = str(entry.get("compression") or "zlib").lower()
        if compression == "zlib":
            payload = zlib.decompress(payload)
        elif compression in ("none", ""):
            pass
        else:
            logger.warning("Unknown snapshot compression %r for %s", compression, data_ref[:12])
            return None
        declared = entry.get("size")
        if isinstance(declared, int) and declared >= 0 and len(payload) != declared:
            logger.warning(
                "Snapshot %s decoded to %d bytes, header declared %d",
                data_ref[:12], len(payload), declared,
            )
        return payload
    except (ValueError, zlib.error) as exc:
        logger.warning("Could not decode snapshot %s: %s", data_ref[:12], exc)
        return None
