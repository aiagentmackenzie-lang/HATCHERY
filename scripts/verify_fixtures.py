#!/usr/bin/env python3
"""Verify the acceptance fixtures against the code that ships today.

This is the analyst-facing half of slice 0.2. It answers, for every fixture,
one of four things:

    PASS          behaviour matches the recorded expectation
    FAIL          behaviour diverged unexpectedly
    KNOWN-DEFECT  the recorded expectation is a defect owned by a later slice
    UNVERIFIED    a required backend is not installed on this machine

Exit status is 0 unless a check FAILs. Known defects are reported (and counted)
but do not break the baseline: the whole point of recording them is to carry
them into the slice that fixes them. Run with --strict to treat them as
failures when gating a release.

    python scripts/verify_fixtures.py
    python scripts/verify_fixtures.py --strict

The script never writes outside a temporary directory and never touches
`results/`, `uploads/`, `data/` or the checked-in samples.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "manifest.json"


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, check: str, status: str, detail: str) -> None:
        self.rows.append((check, status, detail))

    def count(self, status: str) -> int:
        return sum(1 for _, s, _ in self.rows if s == status)

    def print(self) -> None:
        width = max(len(name) for name, _, _ in self.rows) + 2
        for name, status, detail in self.rows:
            print(f"{name:<{width}} {status:<13} {detail}")
        print()
        print(
            f"{self.count('PASS')} passed, {self.count('FAIL')} failed, "
            f"{self.count('KNOWN-DEFECT')} known defects, "
            f"{self.count('UNVERIFIED')} unverified, "
            f"{self.count('CHANGED')} changed"
        )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_manifest(report: Report, manifest: dict) -> bool:
    failures = []
    for entry in manifest["fixtures"]:
        path = REPO_ROOT / entry["path"]
        if not path.exists():
            failures.append(f"{entry['path']} missing")
            continue
        digest = sha256(path)
        if digest != entry["sha256"]:
            failures.append(f"{entry['path']} sha256 {digest[:16]}… != {entry['sha256'][:16]}…")
        elif path.stat().st_size != entry["size"]:
            failures.append(f"{entry['path']} size mismatch")
    if failures:
        report.add("fixture/hashes", "FAIL", "; ".join(failures))
        return False
    report.add("fixture/hashes", "PASS",
               f"{len(manifest['fixtures'])} files match the manifest")
    return True


def check_static(report: Report, manifest: dict) -> None:
    from engine.intake.elf_analyzer import ELFAnalyzer
    from engine.intake.pe_analyzer import PEAnalyzer
    from engine.intake.uploader import SampleUploader
    from engine.static.capa_scanner import HAS_CAPA, HAS_CAPA_PYTHON, CapaScanner
    from engine.static.packer_detect import PackerDetector
    from engine.static.yara_scanner import YARAScanner

    by_id = {e["id"]: e for e in manifest["fixtures"]}
    sample_store = Path(tempfile.mkdtemp(prefix="hatchery-fixtures-"))
    uploader = SampleUploader(samples_dir=sample_store)

    scanner = YARAScanner()
    scanner.compile_rules()

    def yara(path: Path):
        return scanner.scan(path)

    # EICAR: positive control.
    eicar = REPO_ROOT / by_id["eicar"]["path"]
    result = yara(eicar)
    expected = by_id["eicar"]["expected"]
    matched = sorted(m.rule for m in result.matches)
    if result.error:
        report.add("static/eicar", "FAIL", f"YARA error: {result.error}")
    elif result.rules_loaded == 0:
        report.add("static/eicar", "FAIL", "no YARA rules loaded; scanning did not run")
    elif matched != expected["yara"]["rules"]:
        report.add("static/eicar", "FAIL",
                   f"expected {expected['yara']['rules']}, got {matched}")
    else:
        report.add("static/eicar", "PASS",
                   f"{', '.join(matched)}; {result.rules_loaded} rule files loaded")

    # Negative control: scanning ran and found nothing.
    negative = REPO_ROOT / by_id["negative_text"]["path"]
    result = yara(negative)
    if result.error:
        report.add("static/negative-control", "FAIL", f"YARA error: {result.error}")
    elif result.rules_loaded == 0:
        report.add("static/negative-control", "FAIL",
                   "no YARA rules loaded; zero matches is not evidence of a clean scan")
    elif result.matches:
        report.add("static/negative-control", "FAIL",
                   f"unexpected matches: {[m.rule for m in result.matches]}")
    else:
        report.add("static/negative-control", "PASS",
                   f"0 matches with {result.rules_loaded} rule files loaded")

    # PE: fixture structure and the current rule-set outcome.
    pe_path = REPO_ROOT / by_id["benign_pe"]["path"]
    meta = uploader.upload(pe_path)
    pe = PEAnalyzer().analyze(pe_path)
    if meta.file_type != "PE" or not pe.is_valid_pe:
        report.add("static/benign-pe-structure", "FAIL",
                   f"uploader={meta.file_type} valid={pe.is_valid_pe} error={pe.error}")
    else:
        report.add("static/benign-pe-structure", "PASS",
                   f"PE32+ {pe.machine_type}; {pe.subsystem}")

    pe_yara = yara(pe_path)
    expected_rules = sorted(by_id["benign_pe"]["expected"]["yara"]["rules"])
    actual_rules = sorted(m.rule for m in pe_yara.matches)
    if actual_rules == expected_rules:
        report.add("static/benign-pe-yara", "KNOWN-DEFECT",
                   f"{', '.join(actual_rules)} on a benign PE (rule calibration)")
    elif actual_rules == []:
        report.add("static/benign-pe-yara", "CHANGED",
                   "rules no longer flag the benign PE; update fixtures/manifest.json and the master plan")
    else:
        report.add("static/benign-pe-yara", "FAIL",
                   f"expected {expected_rules}, got {actual_rules}")

    # ELF: the fixture is valid even though HATCHERY's analyzer is not (1.5).
    elf_path = REPO_ROOT / by_id["benign_elf"]["path"]
    try:
        from elftools.elf.elffile import ELFFile
        with elf_path.open("rb") as handle:
            elf = ELFFile(handle)
            arch = elf.header.e_machine
            elf_type = elf.header.e_type
        if arch in (62, "EM_X86_64") and elf_type in (2, "ET_EXEC"):
            report.add("static/benign-elf-fixture", "PASS",
                       f"independently parsed: {arch} {elf_type}")
        else:
            report.add("static/benign-elf-fixture", "FAIL",
                       f"unexpected header {arch} {elf_type}")
    except Exception as exc:  # noqa: BLE001 - report, do not mask
        report.add("static/benign-elf-fixture", "FAIL", f"pyelftools cannot parse fixture: {exc}")

    elf_meta = uploader.upload(elf_path)
    elf_result = ELFAnalyzer().analyze(elf_path)
    expected_elf = by_id["benign_elf"]["expected"]["elf"]
    if elf_result.is_valid_elf:
        report.add("static/benign-elf-analyzer", "CHANGED",
                   "ELFAnalyzer now parses the fixture; update the manifest and master plan (ELF parser)")
    elif expected_elf["error_contains"] in (elf_result.error or "") and elf_meta.file_type == "ELF":
        report.add("static/benign-elf-analyzer", "KNOWN-DEFECT",
                   f"uploader=ELF, analyzer error: {elf_result.error} (ELF parser)")
    else:
        report.add("static/benign-elf-analyzer", "FAIL",
                   f"uploader={elf_meta.file_type} error={elf_result.error}")

    # Packer analysis is PE-only; say so rather than reporting a clean result.
    packer = PackerDetector()
    pe_packer = packer.detect(pe_path)
    elf_packer = packer.detect(elf_path)
    if not pe_packer.is_packed and pe_packer.error is None:
        report.add("static/packer-pe", "PASS", "no packer indicators, no error")
    else:
        report.add("static/packer-pe", "FAIL",
                   f"is_packed={pe_packer.is_packed} error={pe_packer.error}")
    if elf_packer.error and "not" in elf_packer.error.lower():
        report.add("static/packer-elf", "PASS",
                   f"inapplicable with an explicit error: {elf_packer.error}")
    else:
        report.add("static/packer-elf", "FAIL",
                   f"expected an explicit inapplicability error, got is_packed={elf_packer.is_packed} error={elf_packer.error}")

    # Detector availability must never masquerade as a clean zero.
    capa = CapaScanner()
    capa_result = capa.scan(pe_path)
    if capa_result.is_available and capa_result.error is None:
        report.add("detector/capa", "PASS",
                   f"ran; {len(capa_result.capabilities)} capabilities")
    elif not capa_result.is_available and capa_result.error:
        installed = "CLI" if HAS_CAPA else ("Python" if HAS_CAPA_PYTHON else "not installed")
        report.add("detector/capa", "PASS",
                   f"unavailable ({installed}) with preserved reason: {capa_result.error[:110]}")
    else:
        report.add("detector/capa", "FAIL",
                   f"ambiguous status: available={capa_result.is_available} error={capa_result.error}")


def check_replay(report: Report, manifest: dict) -> None:
    from engine.monitor.file_watcher import FileWatcher
    from engine.monitor.network_capture import NetworkCapture
    from engine.monitor.strace_parser import StraceParser

    by_id = {e["id"]: e for e in manifest["fixtures"]}
    parser = StraceParser()

    trace = parser.parse_file(REPO_ROOT / by_id["trace_timestamp"]["path"])
    expect = by_id["trace_timestamp"]["expected"]["parse"]
    tree = {str(pid): children for pid, children in trace.process_tree.items()}
    if (
        trace.parsed_events == expect["parsed_events"]
        and len(trace.network_connections) == expect["network_connections"]
        and tree == {k: v for k, v in expect["process_tree"].items()}
    ):
        report.add("replay/strace-timestamp", "PASS",
                   f"{trace.parsed_events} events, tree {tree}, "
                   f"{len(trace.network_connections)} connection")
    else:
        report.add("replay/strace-timestamp", "FAIL",
                   f"events={trace.parsed_events} tree={tree} "
                   f"connections={len(trace.network_connections)}")

    pid_first = parser.parse_file(REPO_ROOT / by_id["trace_pid_first"]["path"])
    expect_pid = by_id["trace_pid_first"]["expected"]["parse"]
    pid_tree = {str(pid): children for pid, children in pid_first.process_tree.items()}
    if (pid_first.parsed_events == expect_pid["parsed_events"]
            and pid_tree == expect_pid["process_tree"]
            and len(pid_first.network_connections) == expect_pid["network_connections"]):
        report.add("replay/strace-pid-first", "PASS",
                   f"{pid_first.parsed_events} events, tree {pid_tree}")
    else:
        report.add("replay/strace-pid-first", "FAIL",
                   f"events={pid_first.parsed_events} tree={pid_tree}")

    events = FileWatcher().parse_log(REPO_ROOT / by_id["file_events"]["path"])
    expect_events = by_id["file_events"]["expected"]["parse"]
    observed = {
        "total_events": events.total_events,
        "created_files": len(events.created_files),
        "modified_files": len(events.modified_files),
        "deleted_files": len(events.deleted_files),
    }
    if observed == expect_events:
        report.add("replay/file-events", "PASS", str(observed))
    else:
        report.add("replay/file-events", "FAIL", f"expected {expect_events}, got {observed}")

    if shutil.which("tshark") is None:
        report.add("replay/pcap", "UNVERIFIED",
                   "tshark not installed; PCAP expectations were not exercised")
        return

    capture = NetworkCapture()
    for fixture_id, label in (
        ("pcap_one_packet", "replay/pcap-one-packet"),
        ("pcap_empty", "replay/pcap-empty"),
        ("pcap_malformed", "replay/pcap-malformed"),
    ):
        entry = by_id[fixture_id]
        result = capture.analyze_pcap(REPO_ROOT / entry["path"])
        expect = entry["expected"]["parse"]
        packets_ok = result.total_packets == expect["total_packets"]
        conns_ok = len(result.connections) == expect.get("connections", len(result.connections))
        known = entry["expected"].get("known_defect")
        if fixture_id == "pcap_malformed":
            if packets_ok and not result.errors:
                report.add(label, "KNOWN-DEFECT",
                           "unreadable capture reported as an empty result (PCAP backend)")
            elif result.errors:
                report.add(label, "CHANGED",
                           f"unreadable capture now reports: {result.errors[0][:90]}")
            else:
                report.add(label, "FAIL",
                           f"expected {expect['total_packets']} packets, got {result.total_packets}")
        elif packets_ok and conns_ok:
            detail = f"{result.total_packets} packets, {len(result.connections)} connections"
            if known:
                report.add(label, "KNOWN-DEFECT", f"{detail} ({known})")
            else:
                report.add(label, "PASS", detail)
        else:
            report.add(label, "FAIL",
                       f"expected packets={expect['total_packets']} "
                       f"connections={expect.get('connections')}, got "
                       f"{result.total_packets}/{len(result.connections)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero when known defects or unverified checks remain")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    report = Report()

    from engine.static.capa_scanner import HAS_CAPA
    print("HATCHERY fixture verification")
    print(f"manifest: {MANIFEST.relative_to(REPO_ROOT)} ({len(manifest['fixtures'])} fixtures)")
    print(f"python:   {sys.version.split()[0]} ({sys.executable})")
    print(f"capa:     {'CLI on PATH' if HAS_CAPA else 'not on PATH'}")
    print(f"tshark:   {shutil.which('tshark') or 'not installed'}")
    print()

    if not check_manifest(report, manifest):
        report.print()
        return 1

    check_static(report, manifest)
    check_replay(report, manifest)
    report.print()

    if report.count("FAIL") or report.count("CHANGED"):
        return 1
    if args.strict and (report.count("KNOWN-DEFECT") or report.count("UNVERIFIED")):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
