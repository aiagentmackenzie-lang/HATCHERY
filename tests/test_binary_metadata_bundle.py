"""Binary metadata reaches the bundle and its readers (D38).

The PE and ELF analyzers ran for the console and their results were thrown away,
so ``static.pe`` and ``static.elf`` never existed — even though the API's
``pe_json``/``elf_json`` columns, ``server/src/routes/report.ts``, the dashboard's
``YARAResults`` and ``engine/cluster/fingerprint.py`` all already read those
sections. These tests use real ``hatchery submit`` runs and the real report the
submit writes beside the bundle.
"""

from __future__ import annotations

import json
from pathlib import Path

from _results_builder import submit

REPO_ROOT = Path(__file__).resolve().parent.parent
PE = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "benign" / "benign_pe.exe"
ELF = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "benign" / "hello.elf"
TEXT = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "benign" / "negative.txt"
SCHEMA_VERSION = "1.1"


def _analysis(run_dir: Path) -> dict:
    return json.loads((run_dir / "bundle" / "analysis.json").read_text(encoding="utf-8"))


def test_a_pe_run_carries_its_structure(tmp_path: Path) -> None:
    run = submit(tmp_path, "pe", sample=PE)
    analysis = _analysis(run)

    pe = analysis["static"]["pe"]
    assert pe["is_valid_pe"] is True
    assert pe["machine_type"] == "x64 (AMD64)"
    assert pe["subsystem"].startswith("Windows CUI")
    assert pe["is_64bit"] is True
    assert [section["name"] for section in pe["sections"]] == [".text"]
    assert analysis["static"]["elf"] is None, "a PE run must not claim ELF metadata"
    assert analysis["errors"] == []
    assert analysis["schema_version"] == SCHEMA_VERSION


def test_an_elf_run_carries_its_structure(tmp_path: Path) -> None:
    run = submit(tmp_path, "elf", sample=ELF)
    analysis = _analysis(run)

    elf = analysis["static"]["elf"]
    assert elf["is_valid_elf"] is True
    assert (elf["arch"], elf["bits"], elf["elf_type"]) == (
        "x86-64", 64, "EXEC (executable)"
    )
    assert elf["entry_point"] == 0x401000
    assert [section["name"] for section in elf["sections"]] == ["", ".text", ".shstrtab"]
    assert elf["security"]["is_pie"] is False
    assert elf["security"]["is_stripped"] is True
    assert analysis["static"]["pe"] is None, "an ELF run must not claim PE metadata"
    assert analysis["errors"] == []


def test_a_non_binary_run_says_not_applicable_not_absent(tmp_path: Path) -> None:
    run = submit(tmp_path, "text", sample=TEXT)
    static = _analysis(run)["static"]

    # The keys are present with a null value, so a reader can tell "this is not
    # a PE/ELF" from "this revision dropped the section".
    assert "pe" in static and static["pe"] is None
    assert "elf" in static and static["elf"] is None


def test_the_report_renders_the_structure_the_bundle_carries(tmp_path: Path) -> None:
    pe_run = submit(tmp_path, "pe-report", sample=PE)
    pe_report = (pe_run / "report.md").read_text(encoding="utf-8")
    assert "### PE Structure" in pe_report
    assert "**Machine:** x64 (AMD64), 64-bit" in pe_report
    assert "`.text`" in pe_report

    elf_run = submit(tmp_path, "elf-report", sample=ELF)
    elf_report = (elf_run / "report.md").read_text(encoding="utf-8")
    assert "### ELF Structure" in elf_report
    assert "**Architecture:** x86-64, 64-bit, Little-endian" in elf_report
    assert "**Hardening:** NX off, PIE off" in elf_report
