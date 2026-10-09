"""capa-on-snapshots and YARA-over-snapshots, with injected fake tools."""

from __future__ import annotations

import base64
import zlib
from typing import Any

from engine.emulate import memory as memory_mod
from engine.emulate.report import parse_report


def _blob(data: bytes) -> dict:
    return {
        "compression": "zlib",
        "encoding": "base64",
        "size": len(data),
        "data": base64.b64encode(zlib.compress(data)).decode(),
    }


def _make_report(regions: list[dict]) -> Any:
    store: dict[str, Any] = {}
    layout = []
    for region in regions:
        ref = region.pop("ref")
        store[ref] = _blob(region.pop("bytes"))
        layout.append(
            {
                "tag": region["tag"],
                "address": hex(region.get("address", 0x1000)),
                "size": len(store[ref]["data"]),
                "prot": region.get("prot", "r-x"),
                "data_ref": ref,
            }
        )
    return parse_report(
        {
            "report_version": "4.0.0",
            "arch": "x86",
            "data": store,
            "entry_points": [{"ep_type": "module_entry", "events": [], "memory": {"layout": layout}}],
        }
    )


class _Cap:
    def __init__(self, name: str, namespace: str = "execution") -> None:
        self.name = name
        self.namespace = namespace

    def to_dict(self) -> dict:
        return {"name": self.name, "namespace": self.namespace}


class _CapaResult:
    def __init__(self, capabilities: list[_Cap]) -> None:
        self.capabilities = capabilities
        self.attack_techniques: list[dict] = []
        self.mbc_behaviors: list[dict] = []
        self.error = None


class FakeCapa:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def scan(self, path: Any, format: str | None = None) -> _CapaResult:
        self.calls.append((str(path), format))
        return _CapaResult([_Cap("write file"), _Cap("connect to server", "communication")])


class _YaraMatch:
    def __init__(self, rule: str) -> None:
        self.rule = rule

    def to_dict(self) -> dict:
        return {"rule": self.rule, "meta": {"severity": "medium"}}


class _YaraResult:
    def __init__(self) -> None:
        self.matches = [_YaraMatch("HATCHERY_Emulated_Code")]
        self.rules_loaded = 1
        self.error = None


class FakeYara:
    def scan_bytes(self, data: bytes) -> _YaraResult:
        return _YaraResult()


def test_is_interesting_selects_executable_code_only() -> None:
    report = _make_report([
        {"ref": "a" * 64, "bytes": b"\x90" * 16, "tag": "emu.module.x..text.0x1000", "prot": "r-x"},
        {"ref": "b" * 64, "bytes": b"\x90" * 16, "tag": "emu.module.x..rdata.0x2000", "prot": "r--"},
        {"ref": "c" * 64, "bytes": b"\x90" * 16, "tag": "emu.struct.EPROCESS.0x3000", "prot": "rwx"},
        {"ref": "d" * 64, "bytes": b"\x90" * 16, "tag": "emu.dynamic.0x4000", "prot": "rwx"},
    ])
    interesting = [r.tag for r in report.memory_regions if memory_mod.is_interesting(r)]
    assert interesting == ["emu.module.x..text.0x1000", "emu.dynamic.0x4000"]


def test_dynamic_regions_are_selected_first() -> None:
    report = _make_report([
        {"ref": "a" * 64, "bytes": b"\x90" * 16, "tag": "emu.module.x..text.0x1000", "prot": "r-x"},
        {"ref": "b" * 64, "bytes": b"\x90" * 16, "tag": "emu.dynamic.0x4000", "prot": "rwx"},
    ])
    selected, truncated = memory_mod.select_regions(report)
    assert not truncated
    assert selected[0].tag == "emu.dynamic.0x4000"


def test_capa_runs_with_sc32_format_and_merges() -> None:
    report = _make_report([
        {"ref": "a" * 64, "bytes": b"\x90" * 16, "tag": "emu.module.x..text.0x1000", "prot": "r-x"},
    ])
    capa = FakeCapa()
    summary = memory_mod.analyze_snapshots(report, capa_scanner=capa, yara_scanner=FakeYara())
    assert summary["regions_decoded"] == 1
    assert summary["capa_regions"] == 1
    assert capa.calls[0][1] == "sc32"
    names = {c["name"] for c in summary["capa_dynamic"]["capabilities"]}
    assert names == {"write file", "connect to server"}
    assert summary["yara_dynamic"]["matches"][0]["rule"] == "HATCHERY_Emulated_Code"


def test_pe_region_uses_pe_format() -> None:
    report = _make_report([
        {"ref": "a" * 64, "bytes": b"MZ" + b"\x00" * 30, "tag": "emu.module.x..text.0x1000", "prot": "r-x"},
    ])
    capa = FakeCapa()
    memory_mod.analyze_snapshots(report, capa_scanner=capa, yara_scanner=FakeYara())
    assert capa.calls[0][1] == "pe"


def test_undecodable_region_is_recorded_not_fatal() -> None:
    report = parse_report(
        {
            "report_version": "4.0.0",
            "arch": "x86",
            "data": {},
            "entry_points": [
                {
                    "ep_type": "module_entry",
                    "events": [],
                    "memory": {
                        "layout": [
                            {"tag": "emu.module.x..text.0x1000", "address": "0x1000", "size": "0x10", "prot": "r-x", "data_ref": "x" * 64}
                        ]
                    },
                }
            ],
        }
    )
    summary = memory_mod.analyze_snapshots(report, capa_scanner=FakeCapa(), yara_scanner=FakeYara())
    assert summary["regions_decoded"] == 0
    assert any("could not be decoded" in err for err in summary["errors"])


def test_region_cap_marks_truncation() -> None:
    regions = [
        {"ref": f"{i:064x}", "bytes": b"\x90" * 16, "tag": f"emu.dynamic.{i}", "prot": "rwx"}
        for i in range(memory_mod.MAX_REGIONS + 5)
    ]
    report = _make_report(regions)
    selected, truncated = memory_mod.select_regions(report)
    assert truncated
    assert len(selected) == memory_mod.MAX_REGIONS


def test_no_regions_returns_empty_summary() -> None:
    report = parse_report({"report_version": "4.0.0", "entry_points": []})
    summary = memory_mod.analyze_snapshots(report, capa_scanner=FakeCapa(), yara_scanner=FakeYara())
    assert summary["regions_selected"] == 0
    assert summary["capa_dynamic"]["capabilities"] == []
