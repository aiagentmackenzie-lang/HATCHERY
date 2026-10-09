"""capa and YARA over Speakeasy memory snapshots — "dynamic" capa, honestly.

capa has no Speakeasy backend. Its dynamic formats are sandbox traces
(``cape``, ``drakvuf``, ``vmray``); Speakeasy is not one of them. So HATCHERY
does not synthesise a CAPE report (that would be fake integration). Instead it
runs **static capa and YARA over the memory regions Speakeasy captured** —
unpacked module sections and dynamically generated code — and labels the result
``capa_dynamic``, kept separate from the static ``capa`` results.

The regions come from the report's deduplicated data store
(``base64(zlib(bytes))`` keyed by SHA-256). Selection is bounded: a region cap, a
per-region byte cap and a total byte cap, with any truncation recorded rather
than hidden. Emulator-internal structures (``emu.struct.*``) and argument slots
are excluded; a region is only considered when it is executable and looks like
module code or dynamically generated code.
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Any, Optional

from engine.emulate.report import EmulationReport, MemoryRegion, decode_data_ref

logger = logging.getLogger(__name__)

# Bounds. A 200-region snapshot store is normal; running capa on all of it is
# slow and mostly noise. These caps keep the stage predictable.
MAX_REGIONS = 24
MAX_REGION_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
# capa is a subprocess per region; cap the number we actually invoke it on.
MAX_CAPA_REGIONS = 12

_EXCLUDED_TAG_PARTS = (
    "emu.struct",
    "emu.module_arg",
    ".rdata",
    ".reloc",
    ".headers",
    ".edata",
    ".rsrc",
    ".idata",
)


def is_interesting(region: MemoryRegion) -> bool:
    """True for executable module code or dynamically generated code."""
    if not region.is_executable or region.is_free or not region.data_ref:
        return False
    tag = region.tag.lower()
    if any(part in tag for part in _EXCLUDED_TAG_PARTS):
        return False
    return "dynamic" in tag or ".text" in tag


def select_regions(report: EmulationReport) -> tuple[list[MemoryRegion], bool]:
    """Return the regions worth scanning, plus whether the list was truncated."""
    selected = [r for r in report.memory_regions if is_interesting(r)]
    # Dynamic code first: that is the unpacked/decrypted material.
    selected.sort(key=lambda r: (0 if r.is_dynamic else 1, -r.size))
    truncated = len(selected) > MAX_REGIONS
    return selected[:MAX_REGIONS], truncated


def _format_for(data: bytes, arch: str) -> str:
    if data[:2] == b"MZ":
        return "pe"
    if arch.lower() in ("x64", "amd64"):
        return "sc64"
    return "sc32"


def analyze_snapshots(
    report: EmulationReport,
    capa_scanner: Optional[Any] = None,
    yara_scanner: Optional[Any] = None,
    run_capa: bool = True,
) -> dict:
    """Run capa and YARA over the captured executable regions.

    ``capa_scanner``/``yara_scanner`` are injectable so tests can run without
    the real tools. Returns a JSON-serialisable summary; every skipped or
    truncated step is recorded.
    """
    from engine.static.capa_scanner import CapaScanner
    from engine.static.yara_scanner import YARAScanner

    regions, truncated = select_regions(report)
    candidates = sum(1 for r in report.memory_regions if is_interesting(r))
    result: dict = {
        "regions_total": len(report.memory_regions),
        "regions_available": candidates,
        "regions_selected": len(regions),
        "regions_decoded": 0,
        "bytes_analyzed": 0,
        "capa_regions": 0,
        "truncated": truncated,
        "capa_dynamic": {
            "is_available": False,
            "capabilities": [],
            "attack_techniques": [],
            "mbc_behaviors": [],
            "error": None,
        },
        "yara_dynamic": {"rules_loaded": 0, "matches": [], "error": None},
        "regions": [],
        "errors": [],
    }
    if truncated:
        result["errors"].append(
            f"more than {MAX_REGIONS} executable snapshot regions matched; only "
            f"{MAX_REGIONS} were selected"
        )
    if not regions:
        return result

    capa: Any = capa_scanner if capa_scanner is not None else (CapaScanner() if run_capa else None)
    yara: Any = yara_scanner if yara_scanner is not None else YARAScanner()

    capa_by_name: dict[str, dict] = {}
    attack: list[dict] = []
    mbc: list[dict] = []
    yara_by_rule: dict[str, dict] = {}
    total_bytes = 0

    for region in regions:
        if total_bytes >= MAX_TOTAL_BYTES:
            result["truncated"] = True
            result["errors"].append(
                "snapshot analysis stopped at the total-byte cap; later regions "
                "were not scanned"
            )
            break
        data = decode_data_ref(report.data_store, region.data_ref)
        if data is None:
            result["errors"].append(
                f"snapshot {region.tag} ({region.data_ref[:12]}) could not be decoded"
            )
            continue
        if len(data) > MAX_REGION_BYTES:
            data = data[:MAX_REGION_BYTES]
            result["truncated"] = True
        total_bytes += len(data)
        result["regions_decoded"] += 1
        fmt = _format_for(data, report.arch)
        digest = hashlib.sha256(data).hexdigest()
        region_row = {
            "tag": region.tag,
            "address": hex(region.address),
            "size": region.size,
            "prot": region.prot,
            "format": fmt,
            "sha256": digest,
            "capa_capabilities": 0,
            "yara_matches": 0,
        }

        if yara is not None:
            try:
                yara_result = yara.scan_bytes(data)
                for match in getattr(yara_result, "matches", []) or []:
                    row = match.to_dict() if hasattr(match, "to_dict") else dict(match)
                    yara_by_rule.setdefault(str(row.get("rule", "")), row)
                region_row["yara_matches"] = len(getattr(yara_result, "matches", []) or [])
                if getattr(yara_result, "error", None):
                    result["errors"].append(f"YARA on {region.tag}: {yara_result.error}")
            except Exception as exc:  # noqa: BLE001 - a region must not abort the run
                result["errors"].append(f"YARA on {region.tag} failed: {exc}")

        if capa is not None and result["capa_regions"] < MAX_CAPA_REGIONS:
            region_row["capa_capabilities"] = _run_capa_region(
                capa, data, fmt, region.tag, result, capa_by_name, attack, mbc
            )

        result["regions"].append(region_row)

    if capa is not None and result["regions_decoded"] > result["capa_regions"]:
        # capa is a subprocess per region, so it is capped; YARA still ran on
        # every decoded region. Say so rather than reporting a clean capa pass.
        result["truncated"] = True
        result["errors"].append(
            f"capa ran on {result['capa_regions']} of "
            f"{result['regions_decoded']} decoded region(s); the rest were "
            "scanned by YARA only"
        )

    result["bytes_analyzed"] = total_bytes
    result["capa_dynamic"] = {
        "is_available": bool(capa is not None),
        "capabilities": list(capa_by_name.values()),
        "attack_techniques": attack,
        "mbc_behaviors": mbc,
        "error": None,
    }
    result["yara_dynamic"] = {
        "rules_loaded": int(getattr(yara, "_rules_loaded", 0) or 0) if yara is not None else 0,
        "matches": list(yara_by_rule.values()),
        "error": None,
    }
    logger.info(
        "Snapshot analysis: %d/%d regions decoded, %d bytes, capa on %d region(s), "
        "%d capability(ies), %d YARA match(es)",
        result["regions_decoded"], result["regions_selected"], total_bytes,
        result["capa_regions"], len(capa_by_name), len(yara_by_rule),
    )
    return result


def _run_capa_region(
    capa: Any,
    data: bytes,
    fmt: str,
    tag: str,
    result: dict,
    capa_by_name: dict[str, dict],
    attack: list[dict],
    mbc: list[dict],
) -> int:
    """Run capa on one region, merging capabilities into the accumulators."""
    with tempfile.NamedTemporaryFile(prefix="hatchery-snap-", suffix=".bin", delete=False) as handle:
        handle.write(data)
        temp_path = Path(handle.name)
    try:
        scan = getattr(capa, "scan")
        capa_result = scan(temp_path, format=fmt)
        if getattr(capa_result, "error", None):
            result["errors"].append(f"capa on {tag}: {capa_result.error}")
        capabilities = getattr(capa_result, "capabilities", []) or []
        for capability in capabilities:
            row = capability.to_dict() if hasattr(capability, "to_dict") else dict(capability)
            capa_by_name.setdefault(str(row.get("name", "")), row)
        for tech in getattr(capa_result, "attack_techniques", []) or []:
            if tech not in attack:
                attack.append(tech)
        for behavior in getattr(capa_result, "mbc_behaviors", []) or []:
            if behavior not in mbc:
                mbc.append(behavior)
        result["capa_regions"] += 1
        return len(capabilities)
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"capa on {tag} failed: {exc}")
        return 0
    finally:
        temp_path.unlink(missing_ok=True)
